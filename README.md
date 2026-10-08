# pcap-graph

Drop a Wireshark capture (`.pcap` / `.pcapng`) into a browser page and see which systems talk to each other.

Everything runs client-side in `index.html` + `pcap-graph.js`. No build step, no dependencies, nothing leaves the machine.

## Run

```bash
cd projects/pcap-graph
python3 -m http.server 8765
# open http://127.0.0.1:8765/
```

(A local server is needed because `index.html` loads `pcap-graph.js` as an ES module; `file://` blocks that in Chromium.)

Then drag a capture onto the page, or use **Open capture…**. `sample/lab.pcap` and `sample/lab.pcapng` are synthetic test captures: a workstation talking to a DC (DNS/Kerberos/LDAP/SMB), HTTPS to the internet over VLAN 100, an ICMP ping, ARP, mDNS/IPv6 multicast, and a SYN scan from `10.0.0.66`.

## What you see

- **Node** = one address (IPv4, IPv6, or MAC for ARP/non-IP frames). The **number inside** is how many distinct hosts it talked to. Size follows the *size* selector (peers by default). Colour: private IPv4 (blue), public IPv4 (orange), IPv6 (purple), broadcast/multicast (grey), MAC-only (green).
- **Edge** = one conversation, drawn in two halves. **Teal half** starts at the host that *opened* the conversation; **grey half with an arrowhead** points at the host that answered. Width ∝ log packets. Dashed amber = TCP SYNs with no reply in either direction — scan signature.
- **Who opened it**: a bare TCP SYN is taken as proof. Without one (UDP, ICMP, capture started mid-stream) the first packet seen decides, and the details panel says so and warns that this is weaker evidence.
- Click a node: packets in/out, peers split into opened/answered, MACs seen, services it *answered* on, every peer sorted by volume with a → / ← showing who opened each (peers are clickable).
- Click an edge: initiator → responder, how that was determined, per-direction counts, service/port breakdown, protocol breakdown, first/last seen.
- Hover anything for a tooltip. Click a node or line to select it (lines have a generous ~14px hit zone, so you don't need to be pixel-exact). Press-and-move on a node drags it and pins it in place; press-and-move on empty space pans; scroll zooms; **Fit** recentres.

## Controls

| Control | Effect |
|---|---|
| hide broadcast/multicast | drops edges whose destination is a broadcast/multicast address (on by default — they add noise) |
| include non-IP L2 | shows LLDP/STP/etc. frames as MAC↔MAC edges |
| min packets | hides conversations below the threshold (1 … 1000, log steps) |
| filter | substring match on host address or service name (`smb`, `10.0.0.`, `rdp`) |
| size | what node radius encodes: **peers** (default — distinct hosts talked to), packets, or bytes |
| Legend | toggles a floating panel explaining every node colour, line style, the badge number, how direction is decided, and the mouse controls. `Esc` or × closes it |
| ☾ Dark / ☀ Light | switches theme. Light is a warm beige palette with deepened node hues. Choice is remembered in `localStorage`; first visit follows the OS preference |
| CSV | downloads every conversation: initiator, responder, how direction was determined, per-direction packets, bytes, services, SYN-only flag, timestamps |

## Parser coverage

`pcap-graph.js` handles: pcap (µs and ns, both endians), pcapng (multi-section, multi-interface, `if_tsresol`, EPB + SPB); link types Ethernet, Linux SLL/SLL2, NULL/loopback, raw IP; 802.1Q and QinQ tags; IPv4 (fragments, options), IPv6 (extension headers), TCP/UDP/SCTP ports, ICMP/ICMPv6, ARP. Service labels come from a well-known-port table (`PORT_SERVICES`) — it labels, it does not decode payloads.

Known gaps: no name resolution (NRB ignored), no GRE/VXLAN/tunnel unwrapping, O(n²) layout gets sluggish past ~1500 visible hosts (raise *min packets*).
