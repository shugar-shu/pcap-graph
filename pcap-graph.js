// pcap-graph.js — parse pcap / pcapng captures and aggregate who-talks-to-whom.
// Zero dependencies. Works in browsers (ES module) and Bun.
//
// parseCapture(ArrayBuffer) -> { format, packets: Packet[], dropped, linkTypes }
// buildGraph(packets, opts)  -> { nodes, edges, stats }

// ---------- link types ----------
const LINKTYPE_NULL = 0;
const LINKTYPE_ETHERNET = 1;
const LINKTYPE_RAW_A = 12;
const LINKTYPE_RAW = 101;
const LINKTYPE_LINUX_SLL = 113;
const LINKTYPE_IPV4 = 228;
const LINKTYPE_IPV6 = 229;
const LINKTYPE_LINUX_SLL2 = 276;

const ETH_IPV4 = 0x0800;
const ETH_ARP = 0x0806;
const ETH_VLAN = 0x8100;
const ETH_QINQ = 0x88a8;
const ETH_IPV6 = 0x86dd;

const IPPROTO_NAMES = {
  1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH",
  58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP",
};

// Well-known ports -> service label. Used for edge labelling, not decoding.
export const PORT_SERVICES = {
  20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3",
  123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
  143: "IMAP", 161: "SNMP", 162: "SNMP-trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
  464: "Kpasswd", 465: "SMTPS", 514: "Syslog", 587: "SMTP-sub", 636: "LDAPS",
  993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1812: "RADIUS",
  1900: "SSDP", 2049: "NFS", 3268: "GC", 3269: "GC-SSL", 3306: "MySQL",
  3389: "RDP", 5353: "mDNS", 5355: "LLMNR", 5432: "PostgreSQL", 5900: "VNC",
  5985: "WinRM", 5986: "WinRM-S", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
  9200: "Elastic", 27017: "MongoDB",
};

// ---------- byte helpers ----------
function mac(u8, o) {
  let s = "";
  for (let i = 0; i < 6; i++) {
    if (i) s += ":";
    s += u8[o + i].toString(16).padStart(2, "0");
  }
  return s;
}

function ipv4(u8, o) {
  return `${u8[o]}.${u8[o + 1]}.${u8[o + 2]}.${u8[o + 3]}`;
}

function ipv6(u8, o) {
  const g = new Array(8);
  for (let i = 0; i < 8; i++) g[i] = (u8[o + i * 2] << 8) | u8[o + i * 2 + 1];
  // RFC 5952 compression: longest run of zero groups (len >= 2)
  let bestStart = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  if (bestLen < 2) return g.map((x) => x.toString(16)).join(":");
  const head = g.slice(0, bestStart).map((x) => x.toString(16)).join(":");
  const tail = g.slice(bestStart + bestLen).map((x) => x.toString(16)).join(":");
  return `${head}::${tail}`;
}

// ---------- container parsing ----------
export function parseCapture(buffer) {
  const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  if (u8.length < 4) throw new Error("File too small to be a capture");
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const magic = dv.getUint32(0, true);
  if (magic === 0x0a0d0d0a) return parsePcapng(u8, dv);
  if (
    magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1 ||
    magic === 0xa1b23c4d || magic === 0x4d3cb2a1
  ) return parsePcap(u8, dv, magic);
  throw new Error(
    "Not a pcap or pcapng file (magic 0x" + magic.toString(16).padStart(8, "0") + "). " +
    "Export from Wireshark with File → Save As → pcapng/pcap.",
  );
}

function parsePcap(u8, dv, magic) {
  const le = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
  const nanos = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
  const linkType = dv.getUint32(20, le) & 0x0fffffff; // upper bits are FCS/P flags
  const packets = [];
  let dropped = 0;
  let off = 24;
  while (off + 16 <= u8.length) {
    const tsSec = dv.getUint32(off, le);
    const tsFrac = dv.getUint32(off + 4, le);
    const capLen = dv.getUint32(off + 8, le);
    const origLen = dv.getUint32(off + 12, le);
    off += 16;
    if (off + capLen > u8.length) { dropped++; break; }
    const ts = tsSec + tsFrac / (nanos ? 1e9 : 1e6);
    const pkt = decodeFrame(u8, off, capLen, linkType, ts, origLen);
    if (pkt) packets.push(pkt); else dropped++;
    off += capLen;
  }
  return { format: nanos ? "pcap (ns)" : "pcap", packets, dropped, linkTypes: [linkType] };
}

function parsePcapng(u8, dv) {
  const packets = [];
  const linkTypes = [];
  let dropped = 0;
  let le = true;
  let interfaces = []; // per-section: [{linkType, tsResol}]
  let off = 0;
  while (off + 12 <= u8.length) {
    const type = dv.getUint32(off, le);
    if (type === 0x0a0d0d0a) {
      // Section Header Block: byte-order magic decides endianness for this section
      const bom = dv.getUint32(off + 8, true);
      le = bom === 0x1a2b3c4d;
      interfaces = [];
    }
    const len = dv.getUint32(off + 4, le);
    if (len < 12 || off + len > u8.length) { dropped++; break; }
    const body = off + 8;
    switch (type) {
      case 0x00000001: { // IDB
        const linkType = dv.getUint16(body, le);
        let tsResol = 1e-6;
        // options start at body+8
        let o = body + 8;
        const end = off + len - 4;
        while (o + 4 <= end) {
          const code = dv.getUint16(o, le);
          const olen = dv.getUint16(o + 2, le);
          if (code === 0) break;
          if (code === 9 && olen >= 1) { // if_tsresol
            const v = u8[o + 4];
            tsResol = v & 0x80 ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v);
          }
          o += 4 + ((olen + 3) & ~3);
        }
        interfaces.push({ linkType, tsResol });
        if (!linkTypes.includes(linkType)) linkTypes.push(linkType);
        break;
      }
      case 0x00000006: { // EPB
        const ifId = dv.getUint32(body, le);
        const tsHi = dv.getUint32(body + 4, le);
        const tsLo = dv.getUint32(body + 8, le);
        const capLen = dv.getUint32(body + 12, le);
        const origLen = dv.getUint32(body + 16, le);
        const iface = interfaces[ifId];
        if (!iface || body + 20 + capLen > off + len) { dropped++; break; }
        const ts = (tsHi * 4294967296 + tsLo) * iface.tsResol;
        const pkt = decodeFrame(u8, body + 20, capLen, iface.linkType, ts, origLen);
        if (pkt) packets.push(pkt); else dropped++;
        break;
      }
      case 0x00000003: { // Simple Packet Block — uses interface 0, no timestamp
        const origLen = dv.getUint32(body, le);
        const iface = interfaces[0];
        const capLen = Math.min(origLen, len - 16);
        if (!iface) { dropped++; break; }
        const pkt = decodeFrame(u8, body + 4, capLen, iface.linkType, 0, origLen);
        if (pkt) packets.push(pkt); else dropped++;
        break;
      }
      default:
        break; // SHB, NRB, ISB, custom — skip
    }
    off += len;
  }
  return { format: "pcapng", packets, dropped, linkTypes };
}

// ---------- frame decoding ----------
// Returns Packet | null (null = couldn't find an L3 address pair)
function decodeFrame(u8, off, len, linkType, ts, origLen) {
  const end = off + len;
  const pkt = {
    ts, len: origLen,
    srcMac: null, dstMac: null,
    src: null, dst: null, l3: null,
    proto: null, sport: null, dport: null,
    vlan: null,
  };
  let o = off;
  let ethType;

  switch (linkType) {
    case LINKTYPE_ETHERNET:
      if (o + 14 > end) return null;
      pkt.dstMac = mac(u8, o);
      pkt.srcMac = mac(u8, o + 6);
      ethType = (u8[o + 12] << 8) | u8[o + 13];
      o += 14;
      break;
    case LINKTYPE_LINUX_SLL:
      if (o + 16 > end) return null;
      ethType = (u8[o + 14] << 8) | u8[o + 15];
      o += 16;
      break;
    case LINKTYPE_LINUX_SLL2:
      if (o + 20 > end) return null;
      ethType = (u8[o] << 8) | u8[o + 1];
      o += 20;
      break;
    case LINKTYPE_NULL: {
      if (o + 4 > end) return null;
      const fam = u8[o] !== 0 ? u8[o] : u8[o + 3]; // AF in host byte order
      ethType = fam === 2 ? ETH_IPV4 : ETH_IPV6; // AF_INET=2, else assume INET6
      o += 4;
      break;
    }
    case LINKTYPE_RAW:
    case LINKTYPE_RAW_A:
      if (o >= end) return null;
      ethType = (u8[o] >> 4) === 6 ? ETH_IPV6 : ETH_IPV4;
      break;
    case LINKTYPE_IPV4: ethType = ETH_IPV4; break;
    case LINKTYPE_IPV6: ethType = ETH_IPV6; break;
    default:
      return null;
  }

  // strip VLAN tags
  while (ethType === ETH_VLAN || ethType === ETH_QINQ) {
    if (o + 4 > end) return null;
    const tci = (u8[o] << 8) | u8[o + 1];
    if (pkt.vlan === null) pkt.vlan = tci & 0x0fff;
    ethType = (u8[o + 2] << 8) | u8[o + 3];
    o += 4;
  }

  if (ethType === ETH_IPV4) return decodeIPv4(u8, o, end, pkt) ? pkt : null;
  if (ethType === ETH_IPV6) return decodeIPv6(u8, o, end, pkt) ? pkt : null;
  if (ethType === ETH_ARP) return decodeArp(u8, o, end, pkt) ? pkt : null;
  if (pkt.srcMac) {
    // non-IP L2 frame (LLDP, STP, etc): still a conversation at MAC level
    pkt.src = pkt.srcMac; pkt.dst = pkt.dstMac; pkt.l3 = "L2";
    pkt.proto = "0x" + ethType.toString(16).padStart(4, "0");
    return pkt;
  }
  return null;
}

function decodeIPv4(u8, o, end, pkt) {
  if (o + 20 > end || (u8[o] >> 4) !== 4) return false;
  const ihl = (u8[o] & 0x0f) * 4;
  const totalLen = (u8[o + 2] << 8) | u8[o + 3];
  const flagsFrag = (u8[o + 6] << 8) | u8[o + 7];
  const fragOffset = flagsFrag & 0x1fff;
  const proto = u8[o + 9];
  pkt.l3 = "IPv4";
  pkt.src = ipv4(u8, o + 12);
  pkt.dst = ipv4(u8, o + 16);
  pkt.proto = IPPROTO_NAMES[proto] || `IP/${proto}`;
  const l4 = o + ihl;
  const l4end = Math.min(end, totalLen ? o + totalLen : end);
  if (fragOffset === 0) decodeL4(u8, l4, l4end, proto, pkt);
  return true;
}

function decodeIPv6(u8, o, end, pkt) {
  if (o + 40 > end || (u8[o] >> 4) !== 6) return false;
  let next = u8[o + 6];
  pkt.l3 = "IPv6";
  pkt.src = ipv6(u8, o + 8);
  pkt.dst = ipv6(u8, o + 24);
  let p = o + 40;
  // walk extension headers
  for (let guard = 0; guard < 8; guard++) {
    if (next === 0 || next === 43 || next === 60 || next === 135) { // HBH, Routing, DstOpts, Mobility
      if (p + 2 > end) break;
      const hl = (u8[p + 1] + 1) * 8;
      next = u8[p]; p += hl;
    } else if (next === 44) { // Fragment
      if (p + 8 > end) break;
      const fragOff = ((u8[p + 2] << 8) | u8[p + 3]) >> 3;
      next = u8[p]; p += 8;
      if (fragOff !== 0) { pkt.proto = IPPROTO_NAMES[next] || `IP/${next}`; return true; }
    } else if (next === 51) { // AH
      if (p + 2 > end) break;
      const hl = (u8[p + 1] + 2) * 4;
      next = u8[p]; p += hl;
    } else break;
  }
  pkt.proto = IPPROTO_NAMES[next] || `IP/${next}`;
  decodeL4(u8, p, end, next, pkt);
  return true;
}

function decodeL4(u8, o, end, proto, pkt) {
  if (proto === 6 || proto === 17 || proto === 132) { // TCP / UDP / SCTP share port layout
    if (o + 4 > end) return;
    pkt.sport = (u8[o] << 8) | u8[o + 1];
    pkt.dport = (u8[o + 2] << 8) | u8[o + 3];
    if (proto === 6 && o + 14 <= end) pkt.tcpFlags = u8[o + 13];
  } else if (proto === 1 || proto === 58) {
    if (o + 1 > end) return;
    pkt.icmpType = u8[o];
  }
}

function decodeArp(u8, o, end, pkt) {
  if (o + 28 > end) return false;
  const hlen = u8[o + 4], plen = u8[o + 5];
  if (hlen !== 6 || plen !== 4) return false;
  const op = (u8[o + 6] << 8) | u8[o + 7];
  pkt.l3 = "ARP";
  pkt.proto = op === 1 ? "ARP-req" : op === 2 ? "ARP-reply" : "ARP";
  pkt.src = ipv4(u8, o + 14);
  pkt.dst = ipv4(u8, o + 24);
  // ARP probe/announce use 0.0.0.0 as sender; fall back to MAC identities
  if (pkt.src === "0.0.0.0") pkt.src = pkt.srcMac;
  return true;
}

// ---------- aggregation ----------
export function isMulticastOrBroadcast(addr) {
  if (!addr) return false;
  if (addr === "255.255.255.255" || addr === "ff:ff:ff:ff:ff:ff") return true;
  if (addr.includes(":") && addr.length === 17) {
    // MAC: group bit
    return (parseInt(addr.slice(0, 2), 16) & 1) === 1;
  }
  if (addr.includes(":")) return addr.toLowerCase().startsWith("ff");
  const first = parseInt(addr.split(".")[0], 10);
  return first >= 224 && first <= 239;
}

export function isPrivate(addr) {
  if (!addr || addr.includes(":")) {
    if (!addr) return false;
    const a = addr.toLowerCase();
    return a.startsWith("fe80") || a.startsWith("fc") || a.startsWith("fd") || a === "::1";
  }
  const p = addr.split(".").map(Number);
  return p[0] === 10 || p[0] === 127 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254);
}

function serviceLabel(pkt) {
  if (pkt.sport === null || pkt.dport === null) return pkt.proto;
  // the lower well-known port is the service; ephemeral side is the client
  const a = PORT_SERVICES[pkt.dport], b = PORT_SERVICES[pkt.sport];
  if (a) return a;
  if (b) return b;
  return `${pkt.proto}/${Math.min(pkt.sport, pkt.dport)}`;
}

/**
 * Build a graph from decoded packets.
 * opts.hideBroadcast  — drop edges whose destination is broadcast/multicast
 * opts.collapseL2     — ignore non-IP L2 frames (default true)
 */
export function buildGraph(packets, opts = {}) {
  const hideBroadcast = opts.hideBroadcast ?? false;
  const collapseL2 = opts.collapseL2 ?? true;
  const nodes = new Map();
  const edges = new Map();
  let first = Infinity, last = -Infinity, totalBytes = 0, counted = 0;

  const node = (addr, pkt) => {
    let n = nodes.get(addr);
    if (!n) {
      n = {
        id: addr, packets: 0, bytes: 0, sent: 0, received: 0,
        macs: new Set(), services: new Map(), peers: new Set(),
        l3: pkt.l3, broadcast: isMulticastOrBroadcast(addr), privateAddr: isPrivate(addr),
        firstSeen: pkt.ts, lastSeen: pkt.ts,
      };
      nodes.set(addr, n);
    }
    n.packets++; n.bytes += pkt.len;
    if (pkt.ts) { n.firstSeen = Math.min(n.firstSeen || pkt.ts, pkt.ts); n.lastSeen = Math.max(n.lastSeen, pkt.ts); }
    return n;
  };

  for (const pkt of packets) {
    if (!pkt.src || !pkt.dst) continue;
    if (collapseL2 && pkt.l3 === "L2") continue;
    const dstBroadcast = isMulticastOrBroadcast(pkt.dst);
    if (hideBroadcast && dstBroadcast) continue;
    counted++;
    totalBytes += pkt.len;
    if (pkt.ts) { first = Math.min(first, pkt.ts); last = Math.max(last, pkt.ts); }

    const s = node(pkt.src, pkt), d = node(pkt.dst, pkt);
    s.sent++; d.received++;
    if (pkt.srcMac) s.macs.add(pkt.srcMac);
    if (pkt.dstMac && !dstBroadcast) d.macs.add(pkt.dstMac);
    s.peers.add(pkt.dst); d.peers.add(pkt.src);

    const svc = serviceLabel(pkt);
    // Server-side node records the service it offered. A bare SYN toward a port
    // proves nothing (scans hit every port), so only count a SYN-ACK/data reply
    // from the server, or a non-SYN packet from the client.
    const bareSyn = pkt.tcpFlags !== undefined && (pkt.tcpFlags & 0x12) === 0x02;
    if (pkt.dport !== null && PORT_SERVICES[pkt.dport]) {
      if (!bareSyn) d.services.set(svc, (d.services.get(svc) || 0) + 1);
    } else if (pkt.sport !== null && PORT_SERVICES[pkt.sport]) {
      s.services.set(svc, (s.services.get(svc) || 0) + 1);
    }

    // undirected key, but keep per-direction counts
    const forward = pkt.src < pkt.dst;
    const a = forward ? pkt.src : pkt.dst, b = forward ? pkt.dst : pkt.src;
    const key = a + "|" + b;
    let e = edges.get(key);
    if (!e) {
      e = {
        id: key, source: a, target: b, packets: 0, bytes: 0,
        ab: 0, ba: 0, services: new Map(), protocols: new Map(),
        firstSeen: pkt.ts, lastSeen: pkt.ts, broadcast: dstBroadcast,
        synOnly: 0, syn: 0,
        // who opened the conversation: first packet seen is the fallback;
        // a bare TCP SYN is stronger evidence and overrides it.
        initiator: pkt.src, initiatorEvidence: "first packet",
      };
      edges.set(key, e);
    }
    e.packets++; e.bytes += pkt.len;
    if (forward) e.ab++; else e.ba++;
    e.services.set(svc, (e.services.get(svc) || 0) + 1);
    e.protocols.set(pkt.proto, (e.protocols.get(pkt.proto) || 0) + 1);
    if (bareSyn) {
      e.syn++;
      if (e.initiatorEvidence !== "TCP SYN") { e.initiator = pkt.src; e.initiatorEvidence = "TCP SYN"; }
    }
    if (pkt.ts) { e.firstSeen = Math.min(e.firstSeen || pkt.ts, pkt.ts); e.lastSeen = Math.max(e.lastSeen, pkt.ts); }
  }

  // mark edges that are only SYNs (scan signature: many SYNs, no replies back)
  for (const e of edges.values()) {
    if (e.syn > 0 && (e.ab === 0 || e.ba === 0) && e.syn === e.packets) e.synOnly = e.syn;
    e.responder = e.initiator === e.source ? e.target : e.source;
    const ini = nodes.get(e.initiator), res = nodes.get(e.responder);
    ini.initiated = (ini.initiated || 0) + 1;
    res.responded = (res.responded || 0) + 1;
  }

  const finish = (m) => [...m.entries()].sort((x, y) => y[1] - x[1]).map(([k, v]) => ({ name: k, count: v }));
  const nodeList = [...nodes.values()].map((n) => ({
    ...n, macs: [...n.macs], peers: n.peers.size, services: finish(n.services),
    initiated: n.initiated || 0, responded: n.responded || 0,
  }));
  const edgeList = [...edges.values()].map((e) => ({
    ...e, services: finish(e.services), protocols: finish(e.protocols),
  }));

  return {
    nodes: nodeList,
    edges: edgeList,
    stats: {
      packets: packets.length, counted, totalBytes,
      hosts: nodeList.length, conversations: edgeList.length,
      duration: Number.isFinite(first) && Number.isFinite(last) ? last - first : 0,
      first: Number.isFinite(first) ? first : null,
    },
  };
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}
