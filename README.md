# network-design

Network design work, kept separate from the automation tools. The first design is a generator for a
**two-site Cisco Nexus BGP EVPN/VXLAN Multi-Site fabric**:

- an HTML design workbook (topology diagram, address plan, VLAN/VNI/VRF matrix, decisions, migration,
  failure tests),
- complete NX-OS configurations for all 16 switches (spines, leafs, border-service leafs, Multi-Site BGWs),
- PAN-OS commands for the firewall handoff at each site.

```bash
python3 -m fabric_design.build examples/demo-fabric.json --out examples/demo
open examples/demo/demo-fabric-design.html
```

Standard library only (Python 3.9+).

## Design

| Area | Choice |
|---|---|
| Underlay | eBGP IPv4 on /31 links, BFD, MTU 9216. Spines share an ASN per site; every leaf and BGW has its own |
| Overlay | MP-BGP L2VPN EVPN, eBGP between loopbacks; spines are route servers (`retain route-target all`, next-hop unchanged) |
| Hosts | Distributed anycast gateway, symmetric IRB, vPC with `advertise-pip` / `advertise virtual-rmac`, ARP suppression |
| Multi-Site | Anycast BGWs, fabric/DCI tracking, two DCI carriers, only BGW loopbacks in the DCI underlay |
| Edge | Routed /29 transits to the Palo Alto HA pair, eBGP with BFD; default route only, never across the DCI |
| Cloud | AWS Direct Connect and Azure ExpressRoute on the BGWs in the tenant VRF, strict prefix allowlists |

No OSPF anywhere. All infrastructure addressing sits inside each site's own /16 (10.x.240.0/21).

## Layout

| Path | Purpose |
|---|---|
| `fabric_design/build.py` | The generator: design rules, address plan, NX-OS and PAN-OS templates, workbook |
| `examples/demo-fabric.json` | Fictional two-site input (DC1/DC2) |
| `examples/demo/` | Workbook and configs generated from the demo input |
| `tests/` | Consistency checks on generated output (BGP neighbor symmetry, link pairing, no OSPF) |
| `private/` | **Git-ignored.** Real site data and everything generated from it |

## Your own sites

Copy `examples/demo-fabric.json` to `private/<name>.json`, fill in your sites, and build into `private/`:

```bash
python3 -m fabric_design.build private/<name>.json --out private/<name>
```

The data file holds everything environment-specific: site codes and /16s, ASNs, VLANs, firewall names and
ports, cloud allowlists and the workbook narrative.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

## Data handling

Only code, docs and fictional examples are committed. Real addressing, hostnames, firewall details and
generated configs stay in `private/`, which `.gitignore` excludes. The generated configs are templates:
validate them against the exact Nexus models and NX-OS release before use.
