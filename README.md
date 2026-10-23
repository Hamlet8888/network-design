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
| Multi-Site | Dedicated anycast BGWs (no endpoints, no vPC), fabric/DCI tracking, two DCI carriers in a full mesh (or one circuit per BGW), only BGW loopbacks in the DCI underlay |
| Edge | Routed /29 transits to the Palo Alto HA pair, eBGP with BFD; default route only, never across the DCI |
| Cloud | AWS Direct Connect and Azure ExpressRoute on the BGWs in the tenant VRF, strict prefix allowlists |

No OSPF anywhere. All infrastructure addressing sits inside each site's own /16 (10.x.240.0/21).

## Layout

| Path | Purpose |
|---|---|
| `fabric_design/build.py` | The generator: design rules, address plan, NX-OS and PAN-OS templates, workbook |
| `examples/demo-fabric.json` | Fictional two-site input (DC1/DC2) |
| `examples/demo/` | Workbook, configs, day-2 checks, expected state and DCI option diagrams generated from the demo input |
| `tests/` | Input validation and cross-device consistency checks on generated output |
| `private/` | **Git-ignored.** Real site data and everything generated from it |

## Your own sites

Copy `examples/demo-fabric.json` to `private/<name>.json`, fill in your sites, and build into `private/`:

```bash
python3 -m fabric_design.build private/<name>.json --out private/<name>
```

The data file holds everything environment-specific: site codes and /16s, ASNs, VLANs, firewall names and
ports, cloud allowlists and the workbook narrative.

### Topology size

`"topology": {"spines": 2, "leaf_pairs": 2, "bgws": 2}` sets the switch count per site (these are the
defaults). Spines 2-4, leaf pairs 2-5 (the last pair is the border-service pair facing the firewalls) and
2 or 4 BGWs. The site data then needs one vPC domain per leaf pair and an `asn` entry per leaf and BGW;
validation lists any that are missing.

| Item | Grows as |
|---|---|
| Leaf/BGW uplinks | Eth1/49 onward, one per spine; BGW DCI ports follow (Eth1/51-52 with two spines, Eth1/53-54 with four) |
| Loopbacks | Spines .1-.4, leafs .11-.20, BGWs .21-.24, vPC VIPs .101-.105 |
| mgmt0 | Spines .11-.14, leafs .21-.30, BGWs .31-.34 |
| DCI | BGWs pair up: carrier A joins namesakes, carrier B crosses within each pair (full mesh) |
| Cloud | AWS DX and Azure ER stay on BGW-01/02 |

The consistency tests also run on a 4-spine, 3-pair, 4-BGW build in both DCI modes.

### Day-2 checks

`checks/<switch>.txt` lists, for every switch and migration step (M1 build to M6 legacy retirement), the
show commands to run and what they should return: BGP sessions by neighbor and AS, BFD, vPC, NVE VNIs,
Multi-Site fabric/DCI links, the default route before and after the firewall move, remote-site and cloud
routes. `checks/checks.json` carries the same list for automation, and section 13 of the workbook shows it.
The expectations come from the same model as the configs, and the tests check that they agree.

### Expected state

`expected-state.json` is the design as data, for
[network-automation-tools](https://github.com/Hamlet8888/network-automation-tools) to audit live switches
against. For every switch it lists the role, ASN, router-ID and mgmt0 address (where the auditor connects), the routed fabric links with MTU and
address, every BGP session (VRF, address family, neighbor, remote AS, BFD, and the migration step that
brings it up or, for the legacy core, removes it), the VNIs with their VLAN or VRF and route target, the
NVE source addresses, the vPC domain and keepalive, and the Multi-Site site ID, VIP, fabric and DCI links.
`schema_version` changes whenever the format does. A test checks it against the generated configs.

### Management baseline

An optional `"baseline"` block adds the management plane to every switch, all of it in VRF management
from mgmt0: TACACS+ AAA with local fallback, NTP, syslog, SNMPv3 (no communities), DNS, CoPP `strict`,
SSH-only vty limited to the `mgmt_acl` subnets, exec timeouts and a login banner. Secrets are never in
the data file or the output: keys and hashes are `<PLACEHOLDERS>` to fill in from your vault at
deployment, and a test fails if one is ever written in clear. Without the block, the configs say the
baseline is not included.

### Border gateways

The BGWs follow Cisco's standard Multi-Site model: two dedicated anycast BGWs per site, sharing the site's
Multi-Site VIP, all forwarding. They carry routed links only, with no endpoints, access ports, vPC or
BGW-local VLANs. That keeps the site scalable to more BGWs, and the tests enforce it. vPC BGWs only make
sense when hosts must dual-home to the border; BGWs on the spines overload them.

`"platforms": {"bgw": ...}` names the BGW model in the config headers and the workbook (the demo uses
`N9K-C93180YC-FX3`). The port plan assumes 48 x SFP28 + 6 x QSFP28:

| Port | Use |
|---|---|
| Eth1/1, Eth1/2 | AWS Direct Connect, Azure ExpressRoute (routed subinterfaces in VRF TRUST, one port per provider) |
| Eth1/49-50 | Spines (fabric tracking) |
| Eth1/51-52 | DCI carrier A, carrier B in full mesh (DCI tracking) |
| Eth1/53-54 | Spare for DCI growth |

### DCI

`"dci": {"mode": ...}` in the data file picks the DCI circuits. Both modes use two carriers; carrier A is
addressed from the first site's 10.x.246.0/24 and carrier B from the second's.

| Mode | Circuits | Ports | What a single failure does |
|---|---|---|---|
| `pair` (default) | 2: BGW-01 to BGW-01 on carrier A, BGW-02 to BGW-02 on carrier B | Eth1/51 | A carrier or circuit loss takes one BGW per site out of Multi-Site (DCI tracking isolates it); a BGW loss also isolates its partner at the other site. Half the BGWs remain, with no further redundancy |
| `full-mesh` (demo) | 4: carrier A joins 01-01 and 02-02, carrier B crosses over (01-02, 02-01) | Eth1/51 carrier A, Eth1/52 carrier B | Every BGW still in service keeps a circuit to a remote BGW still in service, whether a carrier, a circuit or a BGW fails |

The tests fail each carrier, circuit and BGW in turn and check exactly that.

Every build also writes both options as standalone drawings, `diagrams/topology-full-mesh.svg` and
`diagrams/topology-pair.svg`, and shows them side by side in section 8 of the workbook, whichever mode
the data file picks.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

The build rejects site data that would produce a broken fabric, and lists every problem at once:
host VLANs outside 2-239 (VLAN N is 10.x.N.0/24, and 10.x.240.0/21 is infrastructure), duplicate ASNs,
octets, Multi-Site site IDs, vPC domains or VNIs, and cloud prefixes that overlap a site.

The tests parse the generated NX-OS configs (`tests/nxos.py`) and check them across devices:

- **Addressing:** every address is unique except the known anycast ones (gateway, vPC VTEP, BGW VIP),
  no two subnets overlap, infrastructure stays in the /21, and both ends of every link agree on
  description, port, /31 and MTU.
- **BGP:** sessions are symmetric, router-ID is loopback0, `network` statements are local, multihop
  sessions source from loopback0, single-hop sessions run BFD, and EVPN sessions send extended communities.
- **VNIs and RTs:** VLAN, `vn-segment`, EVPN RT and NVE membership agree on every VTEP, the L3VNI and its RT
  are identical fabric-wide, and BGWs carry no L2VNIs.
- **vPC:** domains, keepalives, anycast VTEP, SVIs, gateway MAC and the backup underlay mirror across each pair.
- **Multi-Site:** site IDs and VIPs, fabric/DCI tracking, `peer-type fabric-external` to every remote BGW,
  only BGW loopbacks in the DCI underlay, no default route over the DCI.
- **Policy:** every route-map, prefix-list and as-path list is defined where used, and a prefix-list name
  means the same thing on every switch of a site.
- **Firewall:** the PAN-OS peers, ASNs, transit subnets and ports match the border leafs.
- **Expected state:** `expected-state.json` matches the configs: sessions, BFD, MTU, VNIs, RTs, vPC, Multi-Site.
- **Demo output:** `examples/demo/` matches what the generator produces now.

GitHub Actions runs the suite on Python 3.9 and 3.13 for every push and pull request.

## Data handling

Only code, docs and fictional examples are committed. Real addressing, hostnames, firewall details and
generated configs stay in `private/`, which `.gitignore` excludes. The generated configs are templates:
validate them against the exact Nexus models and NX-OS release before use.
