"""
Generate a two-site Nexus BGP EVPN/VXLAN Multi-Site design: an HTML workbook, complete
NX-OS configurations for every switch, and PAN-OS firewall handoff commands.

    python3 -m fabric_design.build SITE_DATA.json --out OUTPUT_DIR

Everything specific to an environment (sites, addressing, VLANs, ASNs, cloud prefixes,
firewall details and the workbook narrative) comes from the JSON data file. The code holds
only the design rules: the address plan inside each site's /16, the device layout, the
eBGP-only underlay and overlay, Multi-Site, and the config templates.

Standard library only (Python 3.9+).
"""
import argparse
import html
import ipaddress
import json
import sys
from pathlib import Path

# Filled in by load() from the data file.
DATA = {}
SITES = {}          # code -> site dict (keys as used below: o, asn, site_id, vni, vpc, peer, ...)
SITE_ORDER = []     # [site A, site B]; carrier A belongs to site A, carrier B to site B
ASN_PLAN = {}
TRUST_VLANS = []
DMZ_VLANS = []
CLOUD_AWS = []
CLOUD_AZURE = []
AWS_ASN = 64512
AZURE_ASN = 12076
DCI_MODE = "pair"   # "pair": one DCI link per BGW; "full-mesh": every BGW to both remote BGWs
TOPO = {}           # spines, leaf_pairs (the last pair is the border-service pair), bgws
DEFAULT_TOPO = dict(spines=2, leaf_pairs=2, bgws=2)


def load(data):
    """Install a site data document (see examples/demo-fabric.json) as the design input."""
    global DATA, SITES, SITE_ORDER, ASN_PLAN, TRUST_VLANS, DMZ_VLANS, CLOUD_AWS, CLOUD_AZURE, AWS_ASN, AZURE_ASN, DCI_MODE
    global TOPO, DEVICES, DOWNSTREAM
    validate(data)
    sites = data["sites"]
    DATA = data
    SITE_ORDER = [x["code"] for x in sites]
    SITES = {}
    for i, x in enumerate(sites):
        SITES[x["code"]] = dict(
            code=x["code"], city=x["city"], facility=x["facility"], o=x["octet"], asn=x["rt_admin"],
            site_id=x["site_id"], vni=x["vni_base"], vpc=tuple(x["vpc_domains"]),
            peer=sites[1 - i]["code"], core=x["legacy_core"], core99=x.get("legacy_core_ip"),
            fws=x["firewalls"], fw_pair=x["firewall_pair"], host_vlans=[tuple(v) for v in x["host_vlans"]],
            pending=x.get("pending_vlans", []), fw_static=x.get("firewall_static_replace"))
    ASN_PLAN = {x["code"]: x["asn"] for x in sites}
    m = data["vlan_matrix"]
    TRUST_VLANS = [tuple(r) for r in m["routed"]]
    DMZ_VLANS = [tuple(r) for r in m["dmz"]]
    c = data["cloud"]
    CLOUD_AWS, CLOUD_AZURE = c["aws_prefixes"], c["azure_prefixes"]
    AWS_ASN, AZURE_ASN = c["aws_asn"], c["azure_asn"]
    DCI_MODE = data.get("dci", {}).get("mode", "pair")
    TOPO = topology(data)
    DEVICES = build_devices(TOPO)
    DOWNSTREAM = [d[1] for d in DEVICES if not d[1].startswith("NXSP")]


def validate(data):
    """Reject site data that would generate overlapping addresses, VNIs, ASNs or IDs.

    The address plan puts host VLAN N at 10.<octet>.N.0/24 and all infrastructure in
    10.<octet>.240.0/21, so a VLAN ID doubles as a third octet and must stay below 240.
    """
    errors = []
    sites = data["sites"]
    if len(sites) != 2:
        raise ValueError("the design covers exactly two sites")

    def distinct(label, values):
        seen = set()
        for v in values:
            if v in seen:
                errors.append(f"{label} {v!r} is used more than once")
            seen.add(v)

    distinct("site code", [x["code"] for x in sites])
    distinct("site octet", [x["octet"] for x in sites])
    distinct("Multi-Site site_id", [x["site_id"] for x in sites])
    distinct("vPC domain", [d for x in sites for d in x["vpc_domains"]])
    asns = [a for x in sites for a in x["asn"].values() if a != x["asn"]["spine"]]
    asns += [x["asn"]["spine"] for x in sites] + [data["cloud"]["aws_asn"], data["cloud"]["azure_asn"]]
    distinct("BGP AS", asns)

    steps = [r[0] for r in data["doc"]["migration"]]
    missing = [s for s in STEP.values() if s not in steps]
    if missing:
        errors.append(f"doc migration table needs steps {missing} (the configs and checks refer to them)")

    topo = topology(data)
    limits = dict(spines=(2, 4), leaf_pairs=(2, 5), bgws=(2, 4))
    topo_errors = [f"topology {key} must be {lo}-{hi}" for key, (lo, hi) in limits.items()
                   if not isinstance(topo[key], int) or not lo <= topo[key] <= hi]
    if not topo_errors and topo["bgws"] % 2:
        topo_errors.append("topology bgws must be even (BGWs pair up for the DCI and cloud circuits)")
    if topo_errors:
        # every later check depends on the device list, so stop here
        raise ValueError("invalid site data:\n  " + "\n  ".join(errors + topo_errors))
    devices = build_devices(topo)

    mode = data.get("dci", {}).get("mode", "pair")
    if mode not in ("pair", "full-mesh"):
        errors.append(f"dci mode {mode!r} must be 'pair' or 'full-mesh'")

    legacy = data["legacy"]["vlan"]
    if not 2 <= legacy <= 239:
        errors.append(f"legacy VLAN {legacy} must be 2-239 (it is also the third octet of 10.x.{legacy}.0/24)")
    vnis = {TRUST["l3vni"]: f"L3VNI {TRUST['name']}"}
    for x in sites:
        site = x["code"]
        if not 0 <= x["octet"] <= 255:
            errors.append(f"{site}: octet {x['octet']} is not 0-255")
        if len(x["vpc_domains"]) != topo["leaf_pairs"]:
            errors.append(f"{site}: needs one vpc_domain per leaf pair ({topo['leaf_pairs']})")
        expected = {d[1] for d in devices if not d[1].startswith("NXSP")} | {"spine", "fw", "core"}
        if set(x["asn"]) != expected:
            errors.append(f"{site}: asn keys must be {sorted(expected)}")
        vids = [v for v, _ in x["host_vlans"]]
        distinct(f"{site} host VLAN", vids)
        for v, name in x["host_vlans"]:
            if not 2 <= v <= 239:
                errors.append(f"{site}: host VLAN {v} must be 2-239 (10.{x['octet']}.{v}.0/24; "
                              f"10.{x['octet']}.240.0/21 is infrastructure)")
            if v == legacy:
                errors.append(f"{site}: host VLAN {v} is the legacy core transit VLAN")
            if len(name) > 32:
                errors.append(f"{site}: VLAN {v} name {name!r} is longer than 32 characters")
            vni = x["vni_base"] + v
            if vni in vnis:
                errors.append(f"{site}: VLAN {v} gets VNI {vni}, already used by {vnis[vni]}")
            vnis[vni] = f"{site} VLAN {v}"
            if not 4096 <= vni <= 16777214:
                errors.append(f"{site}: VLAN {v} gets VNI {vni}, outside 4096-16777214")
        core_ip = x.get("legacy_core_ip")
        if core_ip:
            net = ipaddress.ip_network(f"10.{x['octet']}.{legacy}.0/24")
            if ipaddress.ip_address(core_ip) not in net:
                errors.append(f"{site}: legacy_core_ip {core_ip} is outside {net}")
            elif int(core_ip.split(".")[3]) in (11, 12):
                errors.append(f"{site}: legacy_core_ip {core_ip} collides with a border-leaf SVI (.11/.12)")

    bl = data.get("baseline")
    if bl:
        for key in ("dns", "ntp", "syslog", "tacacs"):
            if not bl.get(key):
                errors.append(f"baseline {key}: needs at least one server")
            for ip in bl.get(key, []):
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    errors.append(f"baseline {key}: {ip!r} is not an IP address")
        for ip in bl.get("snmp", {}).get("hosts", []):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                errors.append(f"baseline snmp hosts: {ip!r} is not an IP address")
        for net in bl.get("mgmt_acl", []):
            try:
                ipaddress.ip_network(net)
            except ValueError:
                errors.append(f"baseline mgmt_acl: {net!r} is not a network")
        if not 0 <= bl.get("syslog_level", 5) <= 7:
            errors.append("baseline syslog_level must be 0-7")
        if any("^" in line for line in bl.get("banner", [])):
            errors.append("baseline banner may not contain '^' (the banner delimiter)")

    site_nets = {x["code"]: ipaddress.ip_network(f"10.{x['octet']}.0.0/16") for x in sites if 0 <= x["octet"] <= 255}
    for kind in ("aws_prefixes", "azure_prefixes"):
        for p in data["cloud"][kind]:
            try:
                net = ipaddress.ip_network(p)
            except ValueError as exc:
                errors.append(f"cloud {kind}: {exc}")
                continue
            for site, sn in site_nets.items():
                if net.overlaps(sn):
                    errors.append(f"cloud {kind}: {p} overlaps {site} {sn}")
    if errors:
        raise ValueError("invalid site data:\n  " + "\n  ".join(errors))


def A():
    return SITE_ORDER[0]


def B():
    return SITE_ORDER[1]


def fw_ports():
    return DATA["firewall"]["ports"]


def legacy_vlan():
    return DATA["legacy"]["vlan"]


def topology(data):
    return {**DEFAULT_TOPO, **data.get("topology", {})}


def build_devices(topo):
    """(role, suffix, lo0, lo1, vpc vip, mgmt0, vpc pair index) for every switch of one site.

    Spines take lo0 .1-.4 and mgmt0 .11-.14; leafs lo0/lo1 .11-.20, vPC VIPs .101-.105, mgmt0 .21-.30;
    BGWs lo0/lo1 .21-.24, mgmt0 .31-.34. The last leaf pair is the border-service pair (firewalls).
    """
    devs = [("Spine / EVPN route server", f"NXSP-{i + 1:02d}", i + 1, None, None, 11 + i, None)
            for i in range(topo["spines"])]
    for i in range(2 * topo["leaf_pairs"]):
        pair = i // 2
        role = "Border-service leaf / VTEP" if pair == topo["leaf_pairs"] - 1 else "Leaf / VTEP"
        devs.append((role, f"NXLF-{i + 1:02d}", 11 + i, 11 + i, 101 + pair, 21 + i, pair))
    devs += [("Multi-Site anycast BGW", f"NXBGW-{j + 1:02d}", 21 + j, 21 + j, None, 31 + j, None)
             for j in range(topo["bgws"])]
    return devs


TOPO = dict(DEFAULT_TOPO)
DEVICES = build_devices(TOPO)
DOWNSTREAM = [d[1] for d in DEVICES if not d[1].startswith("NXSP")]
BGW_VIP = 200
# BGW port plan (Nexus 9300 with 48 x SFP28 + 6 x QSFP28, e.g. N9K-C93180YC-FX3): spines from Eth1/49,
# then the DCI (Eth1/51-52 with two spines), the rest spare; cloud circuits on BGW-01/02 only, on their
# own SFP28 ports, one per provider, since DX and ER arrive as separate cross-connects.
AWS_PORT, AZURE_PORT = "Ethernet1/1", "Ethernet1/2"


def spines():
    return [d[1] for d in DEVICES if d[1].startswith("NXSP")]


def leafs():
    return [d[1] for d in DEVICES if d[1].startswith("NXLF")]


def bgws():
    return [d[1] for d in DEVICES if d[1].startswith("NXBGW")]


def leaf_pairs():
    ls = leafs()
    return [(ls[i], ls[i + 1]) for i in range(0, len(ls), 2)]


def border_pair():
    return leaf_pairs()[-1]


def uplink(si):
    """Leaf/BGW port toward spine si (0-based)."""
    return f"Ethernet1/{49 + si}"


def dci_port(carrier):
    return f"Ethernet1/{49 + TOPO['spines'] + (0 if carrier == 'A' or DCI_MODE != 'full-mesh' else 1)}"


def has_cloud(bgw):
    return bgw in bgws()[:2]


def short(suf):
    """'NXLF-03' -> 'LF-03'"""
    return suf[2:]


def uplink_cfg(site, di, tracking=False):
    """Routed uplinks from downstream device di to every spine."""
    blocks = []
    for si, spine in enumerate(spines()):
        _, a = p2p(site, si, di)
        lines = [f"interface {uplink(si)}", f"  description {host(site, spine)} Eth1/{di + 1}", "  no switchport",
                 "  mtu 9216", "  no ip redirects", f"  ip address {a}/31"]
        lines += ["  evpn multisite fabric-tracking"] if tracking else []
        blocks.append("\n".join(lines + ["  no shutdown"]))
    return ("\n" if tracking else "\n\n").join(blocks)


def spine_bgp_cfg(site, di, ul_out=None):
    """(underlay neighbors, EVPN neighbors) toward every spine, as router bgp lines."""
    o = SITES[site]["o"]
    spine_asn = ASN_PLAN[site]["spine"]
    ul, ev = [], []
    for si, spine in enumerate(spines()):
        s_ip, _ = p2p(site, si, di)
        ul += [f"  neighbor {s_ip}", f"    remote-as {spine_asn}", f"    description {host(site, spine)} underlay",
               "    bfd", "    address-family ipv4 unicast"]
        ul += [f"      route-map {ul_out} out"] if ul_out else []
        ev += [f"  neighbor 10.{o}.240.{si + 1}", f"    remote-as {spine_asn}", f"    description {host(site, spine)} EVPN",
               "    update-source loopback0", "    ebgp-multihop 2", "    address-family l2vpn evpn",
               "      send-community", "      send-community extended"]
    return "\n".join(ul), "\n".join(ev)
ANYCAST_MAC = "2020.0000.00aa"

TRUST = dict(name="TRUST", id=10, l3vni=50010, vlan=3910, rt="65000:50010")

# Migration steps the configs and checks refer to; the data file's migration table must use the same IDs.
STEP = dict(build="M1", legacy="M2", gateways="M3", firewall="M4", multisite="M5", cleanup="M6")

def cloud_links(site, bgw):
    """(AWS /30 net, BGW IP, AWS IP, Azure /30 net, BGW IP, MSEE IP, label) for one BGW.

    BGW-01 carries DX connection 1 and the ER primary link, BGW-02 DX connection 2 and the ER secondary.
    Azure uses the first usable address of each /30 for the customer and the second for Microsoft.
    """
    o = SITES[site]["o"]
    k = bgws().index(bgw)
    aws = 0 + k * 8
    az = 16 + k * 4
    return (f"10.{o}.244.{aws}/30", f"10.{o}.244.{aws + 1}", f"10.{o}.244.{aws + 2}",
            f"10.{o}.244.{az}/30", f"10.{o}.244.{az + 1}", f"10.{o}.244.{az + 2}",
            ("connection 1", "primary") if k == 0 else ("connection 2", "secondary"))


def dci_links():
    """Every DCI /31: dict(carrier, port, net, ends) with ends = [(site, BGW suffix, IP), ...].

    Carrier A circuits are addressed from site A's 10.x.246.0/24, carrier B from site B's; the
    owning site takes the even address. "pair" gives each BGW one circuit to its namesake: carrier A
    for BGW-01 (and -03), carrier B for BGW-02 (and -04). "full-mesh" gives each BGW one circuit per
    carrier to a different remote BGW: carrier A joins namesakes (01-01, 02-02), carrier B crosses
    over within each BGW pair (01-02, 02-01). A carrier or a BGW can then fail and every surviving
    BGW keeps a DCI path, so no BGW is isolated by a single failure. Ports follow the spine uplinks
    (Eth1/51, and Eth1/52 for carrier B in full mesh, with two spines).
    """
    a, b = A(), B()
    oa, ob = SITES[a]["o"], SITES[b]["o"]
    g = bgws()
    if DCI_MODE == "full-mesh":
        spec = [("A", oa, a, g[i], b, g[i]) for i in range(len(g))]
        spec += [("B", ob, b, g[i ^ 1], a, g[i]) for i in range(len(g))]
    else:
        spec = [("A", oa, a, g[i], b, g[i]) if i % 2 == 0 else ("B", ob, b, g[i], a, g[i]) for i in range(len(g))]
    spec = [(c, dci_port(c), *rest) for c, *rest in spec]
    links, used = [], {}
    for carrier, port, o, own_site, own_bgw, far_site, far_bgw in spec:
        k = used.get(o, 0)
        used[o] = k + 2
        links.append(dict(carrier=carrier, port=port, net=f"10.{o}.246.{k}/31",
                          ends=[(own_site, own_bgw, f"10.{o}.246.{k}"), (far_site, far_bgw, f"10.{o}.246.{k + 1}")]))
    return links


def bgw_dci(site, bgw):
    """(carrier, port, my IP, remote site, remote BGW, remote IP) for each DCI link of one BGW."""
    out = []
    for link in dci_links():
        for i, (s_, b_, ip) in enumerate(link["ends"]):
            if (s_, b_) == (site, bgw):
                fs, fb, fip = link["ends"][1 - i]
                out.append((link["carrier"], link["port"], ip, fs, fb, fip))
    return sorted(out)


def bgw_platform():
    return DATA.get("platforms", {}).get("bgw", "Nexus 9300")


def short_port(port):
    return "Eth" + port[len("Ethernet"):]


def host(s, suffix):
    return DATA["hostname_format"].format(site=s, role=suffix)


def p2p(site, spine_idx, down_idx):
    """(spine_ip, downstream_ip) for the /31 between spine N and downstream device M."""
    o = SITES[site]["o"]
    base = spine_idx * 32 + down_idx * 2
    return f"10.{o}.242.{base}", f"10.{o}.242.{base + 1}"


def vni_range(site, vlan_label):
    if not vlan_label[0].isdigit():
        return "TBD"
    base = SITES[site]["vni"]
    parts = vlan_label.split("–")
    if len(parts) == 2:
        return f"{base + int(parts[0])}–{base + int(parts[1])}"
    return str(base + int(parts[0]))


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------
def esc(s):
    return html.escape(str(s))


def table(headers, rows, cls=""):
    out = [f'<div class="tw"><table class="{cls}"><thead><tr>']
    out += [f"<th>{esc(h)}</th>" for h in headers]
    out.append("</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def code(text):
    return f"<pre><code>{esc(text.strip())}</code></pre>"


def mono(s):
    return f"<code>{esc(s)}</code>"


# ---------------------------------------------------------------------------
# Address tables
# ---------------------------------------------------------------------------
def device_rows(site):
    S = SITES[site]
    o = S["o"]
    rows = []
    for role, suf, lo0, lo1, vip, mg, _ in DEVICES:
        lo1s = f"10.{o}.241.{lo1}/32" if lo1 else "—"
        extra = []
        if vip:
            extra.append(f"vPC anycast VTEP {mono(f'10.{o}.241.{vip}/32')}")
        if suf.startswith("NXBGW"):
            extra.append(f"Multi-Site VIP {mono(f'10.{o}.241.{BGW_VIP}/32')}")
        rows.append([f"<b>{esc(host(site, suf))}</b>", esc(role), mono(f"10.{o}.240.{lo0}/32"), mono(lo1s) if lo1 else "—",
                     "<br>".join(extra) or "—", mono(f"10.{o}.245.{mg}/24"), str(dev_asn(site, suf))])
    return rows


def p2p_rows(site):
    rows = []
    for si, spine in enumerate(spines()):
        for di, down in enumerate(DOWNSTREAM):
            a, b = p2p(site, si, di)
            rows.append([esc(host(site, spine)), f"Eth1/{di + 1}", mono(f"{a}/31"),
                         esc(host(site, down)), f"Eth1/{49 + si}", mono(f"{b}/31")])
    return rows


def blocks_rows():
    rows = []
    vtep_max = max(d[3] for d in DEVICES if d[3])
    spine_p2p = ", ".join(f"spine-{i + 1:02d} from .{i * 32}" for i in range(len(spines())))
    pairs = ", ".join(f"pair {'ABCDE'[i]} .{i * 8}–.{i * 8 + 7}" for i in range(len(leaf_pairs())))
    b1, b2 = (short(x) for x in border_pair())
    words = {2: "two", 4: "four"}
    spec = [
        ("240.0/24", "Loopback0: router-ID and EVPN peering", "One /32 per device"),
        ("241.0/24", "Loopback1: VTEP (NVE source), vPC anycast VTEP, Multi-Site VIP (loopback100)", f"Leafs/BGWs .11–.{vtep_max}, vPC VIPs .101–.{100 + len(leaf_pairs())}, BGW VIP .{BGW_VIP}"),
        ("242.0/24", "Underlay point-to-point /31s (spine to leaf/BGW)", spine_p2p[0].upper() + spine_p2p[1:] + "; spine side even"),
        ("243.0/24", "vPC peer-keepalive and backup underlay VLAN 3900 (/30s)", pairs[0].upper() + pairs[1:]),
        ("244.0/24", "Day-one cloud peering in VRF TRUST: AWS Direct Connect and Azure ExpressRoute (one /29 slot per peering)", f".0/29 DX conn 1 (BGW-01), .8/29 DX conn 2 (BGW-02), .16/29 ER = primary .16/30 (BGW-01) + secondary .20/30 (BGW-02). .64/29 + .72/29: firewall eBGP transit ({b1}, {b2}). The rest is reserved for per-VRF firewall transit"),
        ("245.0/24", "New OOB management for mgmt0 (gateway on the firewall, not on the fabric)", f"Gateway .1, devices .11–.{max(d[5] for d in DEVICES)}"),
        ("246.0/24", "DCI point-to-point /31s (each site owns one carrier)",
         f"{A()}: carrier A, {B()}: carrier B" + (f", {words[len(bgws())]} circuits each (full mesh)" if DCI_MODE == "full-mesh" else "")),
        ("247.0/24", "Reserved for growth (more leafs, a second pod)", ""),
    ]
    for suffix, use, detail in spec:
        rows.append([mono(f"10.{SITES[A()]['o']}.{suffix}"), mono(f"10.{SITES[B()]['o']}.{suffix}"), esc(use), esc(detail)])
    return rows


def fw_rows():
    rows = []
    for site in SITE_ORDER:
        for leaf in border_pair():
            vlan, net, fw_ip, leaf_ip, fw_port = fw_transit(site, leaf)
            rows.append([f"{site} firewall", f"{SITES[site]['fw_pair']} {fw_port} " + mono(f"{fw_ip}/29") + f" (AS {ASN_PLAN[site]['fw']})",
                         f"{esc(host(site, leaf))} VLAN {vlan} SVI " + mono(f"{leaf_ip}/29") + f" (AS {dev_asn(site, leaf)})",
                         "eBGP + BFD, VRF TRUST. FW-01 on Eth1/45, FW-02 on Eth1/46"])
    return rows


def asn_rows():
    labels = [("spine", "Spines (both)" if len(spines()) == 2 else "Spines (all)")]
    labels += [(x, short(x) + (" (border-service)" if x in border_pair() else "")) for x in leafs()]
    labels += [(x, short(x)) for x in bgws()]
    labels += [("fw", "Palo Alto HA pair"), ("core", "Legacy core (migration only)")]
    rows = [[esc(l), str(ASN_PLAN[A()][k]), str(ASN_PLAN[B()][k])] for k, l in labels]
    rows.append(["AWS DX gateway / Azure ER", f"{AWS_ASN} / {AZURE_ASN}", f"{AWS_ASN} / {AZURE_ASN}"])
    return rows


def cloud_rows():
    rows = []
    for site in SITE_ORDER:
        for bgw in bgws()[:2]:
            aws_net, aws_me, aws_peer, az_net, az_me, az_peer, (dx, er) = cloud_links(site, bgw)
            rows.append([f"{site} AWS DX {dx}", f"{esc(host(site, bgw))} {short_port(AWS_PORT)}.&lt;VIF VLAN&gt; " + mono(f"{aws_me}/30"),
                         f"AWS (AS {AWS_ASN}) " + mono(aws_peer), "Private VIF, VRF TRUST, BFD, MD5"])
            rows.append([f"{site} Azure ER {er}", f"{esc(host(site, bgw))} {short_port(AZURE_PORT)}.&lt;ER VLAN&gt; " + mono(f"{az_me}/30"),
                         f"Microsoft MSEE (AS {AZURE_ASN}) " + mono(az_peer), "Private peering, VRF TRUST, BFD"])
    return rows


def vpc_rows(site):
    S = SITES[site]
    o = S["o"]
    rows = []
    for i, (a, b) in enumerate(leaf_pairs()):
        k = i * 8
        rows.append([str(S["vpc"][i]), f"{esc(host(site, a))} + {esc(host(site, b))}",
                     f"{mono(f'10.{o}.243.{k + 1}/30')} / {mono(f'10.{o}.243.{k + 2}/30')} (Eth1/48, VRF KEEPALIVE)",
                     f"{mono(f'10.{o}.243.{k + 5}/30')} / {mono(f'10.{o}.243.{k + 6}/30')}",
                     mono(f"10.{o}.241.{101 + i}/32"), "Po10 (Eth1/53–54)"])
    return rows


# ---------------------------------------------------------------------------
# NX-OS templates: BGP only (eBGP underlay + eBGP EVPN overlay, no OSPF anywhere)
# ---------------------------------------------------------------------------
def dev_asn(site, suf):
    return ASN_PLAN[site]["spine" if suf.startswith("NXSP") else suf]


def fabric_as_regex(site):
    """AS-path regex matching any of this site's fabric ASNs (spines, leafs, BGWs)."""
    a = ASN_PLAN[site]
    fabric = sorted({a[k] for k in a if k not in ("fw", "core")})
    return "_(" + "|".join(str(x) for x in fabric) + ")_"


def cfg_spine(site, idx):
    S = SITES[site]
    o = S["o"]
    me = DEVICES[idx]
    asn = dev_asn(site, me[1])
    lo0 = f"10.{o}.240.{me[2]}"
    lines = [f"hostname {host(site, me[1])}", "", "nv overlay evpn", "feature bgp", "feature bfd", "",
             "route-map RM-NH-UNCHANGED permit 10", "  set ip next-hop unchanged", "",
             "interface loopback0", "  description Router-ID / EVPN peering", f"  ip address {lo0}/32", ""]
    for di, down in enumerate(DOWNSTREAM):
        a, _ = p2p(site, idx, di)
        lines += [f"interface Ethernet1/{di + 1}", f"  description {host(site, down)} Eth1/{49 + idx}",
                  "  no switchport", "  mtu 9216", "  no ip redirects", f"  ip address {a}/31", "  no shutdown", ""]
    lines += [f"router bgp {asn}", f"  router-id {lo0}", "  bestpath as-path multipath-relax",
              "  address-family ipv4 unicast", f"    network {lo0}/32", "    maximum-paths 8",
              "  address-family l2vpn evpn",
              "    retain route-target all          ! no VRFs here; keep every EVPN route to pass on"]
    for di, down in enumerate(DOWNSTREAM):
        _, b = p2p(site, idx, di)
        lines += [f"  neighbor {b}", f"    remote-as {dev_asn(site, down)}",
                  f"    description {host(site, down)} underlay", "    bfd", "    address-family ipv4 unicast"]
    for down in DOWNSTREAM:
        l0 = next(d[2] for d in DEVICES if d[1] == down)
        lines += [f"  neighbor 10.{o}.240.{l0}", f"    remote-as {dev_asn(site, down)}",
                  f"    description {host(site, down)} EVPN", "    update-source loopback0", "    ebgp-multihop 2",
                  "    address-family l2vpn evpn", "      send-community", "      send-community extended",
                  "      route-map RM-NH-UNCHANGED out   ! next hop stays the originating VTEP"]
    return "\n".join(lines)


def site_host_vlans(site):
    """(vlan, name) for every routed VLAN in §6.1 that can be configured now. Third octet = VLAN ID."""
    return SITES[site]["host_vlans"]


def host_vlan_cfg(site):
    S = SITES[site]
    o = S["o"]
    vl = site_host_vlans(site)
    pending = ["!   " + n for n in S["pending"]]
    lines = ["! ---- host VLANs: same VLAN ID, subnet and .1 gateway as today ----------",
             "! Every routed VLAN from section 6.1. Prune to the VLANs whose hosts attach to this pair."]
    lines += (["! Not included yet:"] + pending if pending else []) + [""]
    for v, n in vl:
        lines += [f"vlan {v}", f"  name {n}", f"  vn-segment {S['vni'] + v}"]
    lines.append("")
    for v, n in vl:
        lines += [f"interface Vlan{v}", f"  description {n} (anycast gateway)",
                  f"  shutdown                        ! no shutdown at this VLAN's gateway cut-over ({STEP['gateways']})",
                  "  mtu 9216", f"  vrf member {TRUST['name']}", "  no ip redirects",
                  f"  ip address 10.{o}.{v}.1/24", "  fabric forwarding mode anycast-gateway", ""]
    lines.append("! Explicit RTs: with a different ASN per leaf, 'auto' would give every leaf a different RT.")
    lines.append("evpn")
    for v, _ in vl:
        rt = f"{S['asn']}:{S['vni'] + v}"
        lines += [f"  vni {S['vni'] + v} l2", "    rd auto", f"    route-target import {rt}", f"    route-target export {rt}"]
    lines += ["", "! ARP suppression needs TCAM space on -EX/-FX platforms first (then reload):",
              "!   hardware access-list tcam region arp-ether 256 double-wide",
              "interface nve1", "  no shutdown", "  host-reachability protocol bgp", "  source-interface loopback1",
              "  advertise virtual-rmac", "  global ingress-replication protocol bgp", "  global suppress-arp",
              f"  member vni {TRUST['l3vni']} associate-vrf"]
    lines += [f"  member vni {S['vni'] + v}" for v, _ in vl]
    return "\n".join(lines)


def _leaf_common(site, idx):
    S = SITES[site]
    o = S["o"]
    me = DEVICES[idx]
    asn = dev_asn(site, me[1])
    spine_asn = ASN_PLAN[site]["spine"]
    pair = me[6]
    mate = DEVICES[idx + 1] if idx % 2 == 0 else DEVICES[idx - 1]
    k = pair * 8
    first = idx % 2 == 0
    ka_me, ka_peer = (k + 1, k + 2) if first else (k + 2, k + 1)
    bk_me, bk_peer = (k + 5, k + 6) if first else (k + 6, k + 5)
    lo0, lo1, vip = f"10.{o}.240.{me[2]}", f"10.{o}.241.{me[3]}", f"10.{o}.241.{me[4]}"
    di = DOWNSTREAM.index(me[1])
    spine_ul, spine_ev = spine_bgp_cfg(site, di)
    return f"""
hostname {host(site, me[1])}

nv overlay evpn
feature bgp
feature bfd
feature interface-vlan
feature vn-segment-vlan-based
feature nv overlay
feature vpc
feature lacp
fabric forwarding anycast-gateway-mac {ANYCAST_MAC}

! ---- underlay (eBGP, AS {asn}) ---------------------------------------
interface loopback0
  description Router-ID / EVPN peering
  ip address {lo0}/32

interface loopback1
  description VTEP (primary) + vPC anycast VTEP (secondary)
  ip address {lo1}/32
  ip address {vip}/32 secondary

{uplink_cfg(site, di)}

! ---- vPC ---------------------------------------------------------------
vrf context KEEPALIVE

interface Ethernet1/48
  description vPC keepalive to {host(site, mate[1])}
  no switchport
  vrf member KEEPALIVE
  ip address 10.{o}.243.{ka_me}/30
  no shutdown

spanning-tree vlan 1-3967 priority 8192

vpc domain {S['vpc'][pair]}
  peer-switch
  role priority {10 if first else 20}
  peer-keepalive destination 10.{o}.243.{ka_peer} source 10.{o}.243.{ka_me} vrf KEEPALIVE
  peer-gateway
  ip arp synchronize

interface port-channel10
  description vPC peer-link to {host(site, mate[1])}
  switchport mode trunk
  spanning-tree port type network
  vpc peer-link

interface Ethernet1/53-54
  description vPC peer-link
  switchport mode trunk
  channel-group 10 mode active
  no shutdown

vlan 3900
  name VPC-BACKUP-UNDERLAY
system nve infra-vlans 3900

interface Vlan3900
  description vPC backup underlay to {host(site, mate[1])} (eBGP)
  no shutdown
  mtu 9216
  no ip redirects
  ip address 10.{o}.243.{bk_me}/30

! ---- tenant VRF and L3VNI ---------------------------------------------
vrf context {TRUST['name']}
  vni {TRUST['l3vni']}
  rd auto
  address-family ipv4 unicast
    route-target both {TRUST['rt']}
    route-target both {TRUST['rt']} evpn

vlan {TRUST['vlan']}
  name L3VNI-{TRUST['name']}
  vn-segment {TRUST['l3vni']}

interface Vlan{TRUST['vlan']}
  description L3VNI {TRUST['name']}
  no shutdown
  mtu 9216
  vrf member {TRUST['name']}
  no ip redirects
  ip forward

{host_vlan_cfg(site)}

! ---- BGP: underlay + overlay ------------------------------------------
ip prefix-list PL-{site}-SITE seq 10 permit 10.{o}.0.0/16 le 32
route-map RM-DIRECT permit 10
  match ip address prefix-list PL-{site}-SITE

router bgp {asn}
  router-id {lo0}
  bestpath as-path multipath-relax
  address-family ipv4 unicast
    network {lo0}/32
    network {lo1}/32
    network {vip}/32
    maximum-paths 4
  address-family l2vpn evpn
    advertise-pip
{spine_ul}
  neighbor 10.{o}.243.{bk_peer}
    remote-as {dev_asn(site, mate[1])}
    description {host(site, mate[1])} vPC backup underlay
    bfd
    address-family ipv4 unicast
{spine_ev}
  vrf {TRUST['name']}
    address-family ipv4 unicast
      redistribute direct route-map RM-DIRECT
      maximum-paths 4
""".strip("\n")


def cfg_leaf(site, idx):
    return _leaf_common(site, idx)


def fw_transit(site, leaf):
    """(vlan, net, firewall IP, leaf IP, firewall port) for one border leaf's firewall transit."""
    o = SITES[site]["o"]
    k = border_pair().index(leaf)
    base = 64 + k * 8
    return (3011 + k, f"10.{o}.244.{base}/29", f"10.{o}.244.{base + 1}", f"10.{o}.244.{base + 2}",
            fw_ports()[k])


def cfg_border_extra(site, idx):
    S = SITES[site]
    o = S["o"]
    me = DEVICES[idx]
    asn = dev_asn(site, me[1])
    other = S["peer"]
    oo = SITES[other]["o"]
    vlan, net, fw_ip, leaf_ip, fw_port = fw_transit(site, me[1])
    lv = legacy_vlan()
    svi99 = f"10.{o}.{lv}.{11 + border_pair().index(me[1])}"
    core_ip = S["core99"] or f"<{site}-CORE-VLAN{lv}-IP>"
    fw1, fw2 = S["fws"]
    return f"""
! ---- border-service: firewall handoff (eBGP, VRF {TRUST['name']}) ---------
! Routed transit, no ae8 and no vPC to the firewall. FW-01 and FW-02 share the HA-synced
! address, so both firewalls' ports sit in one local VLAN; only the active one forwards.
vlan {vlan}
  name FW-TRANSIT-{me[1][-5:]}

interface Vlan{vlan}
  description Firewall transit {net} ({S['fw_pair']} {fw_port})
  no shutdown
  vrf member {TRUST['name']}
  no ip redirects
  ip address {leaf_ip}/29          ! firewall {fw_ip}

interface Ethernet1/45
  description {fw1} {fw_port}
  switchport mode access
  switchport access vlan {vlan}
  spanning-tree port type edge
  no shutdown
interface Ethernet1/46
  description {fw2} {fw_port}
  switchport mode access
  switchport access vlan {vlan}
  spanning-tree port type edge
  no shutdown

interface port-channel10
  switchport trunk allowed vlan remove {vlan}   ! local VLAN: keep it off the vPC peer-link

ip prefix-list PL-DEFAULT seq 10 permit 0.0.0.0/0
ip prefix-list PL-{other}-SITE seq 10 permit 10.{oo}.0.0/16 le 32

route-map RM-FW-IN permit 10          ! the firewall sends only the default route
  match ip address prefix-list PL-DEFAULT
route-map RM-FW-OUT permit 10         ! both sites' specifics (beat the firewall's IPsec statics)
  match ip address prefix-list PL-{site}-SITE PL-{other}-SITE

! ---- migration only ({STEP['legacy']} until {STEP['cleanup']}): eBGP to the legacy core over VLAN {lv} -
! The legacy core must run BGP (AS {ASN_PLAN[site]['core']}) for the migration window and
! redistribute its connected/OSPF routes into it. Remove this block at {STEP['cleanup']}.
vlan {lv}
  name LEGACY-CORE-10.{o}.{lv}.0

interface Vlan{lv}
  description Legacy core transit (migration)
  no shutdown
  vrf member {TRUST['name']}
  no ip redirects
  ip address {svi99}/24              ! confirm free in 10.{o}.{lv}.0/24

interface port-channel30
  description Legacy core {S['core']} (migration)
  switchport mode trunk
  switchport trunk allowed vlan {lv}
  spanning-tree port type normal
  vpc 30
  shutdown
interface Ethernet1/43
  description Legacy core switch 01 (migration)
  switchport mode trunk
  switchport trunk allowed vlan {lv}
  channel-group 30 mode active
  shutdown
interface Ethernet1/44
  description Legacy core switch 02 (migration)
  switchport mode trunk
  switchport trunk allowed vlan {lv}
  channel-group 30 mode active
  shutdown

ip as-path access-list AL-{site}-FABRIC seq 10 permit "{fabric_as_regex(site)}"
route-map RM-LEGACY-IN deny 5         ! never take our own routes back from the core
  match as-path AL-{site}-FABRIC
route-map RM-LEGACY-IN permit 10      ! legacy subnets not yet migrated
  match ip address prefix-list PL-{site}-SITE
route-map RM-LEGACY-IN permit 20      ! legacy default until the firewall moves ({STEP['firewall']})
  match ip address prefix-list PL-DEFAULT
  set local-preference 50
route-map RM-LEGACY-OUT permit 10
  match ip address prefix-list PL-{site}-SITE PL-{other}-SITE PL-DEFAULT

router bgp {asn}
  vrf {TRUST['name']}
    neighbor {fw_ip}
      remote-as {ASN_PLAN[site]['fw']}
      description {site}-FW (active member) {fw_port}
      bfd
      address-family ipv4 unicast
        route-map RM-FW-IN in
        route-map RM-FW-OUT out
        maximum-prefix 10
    neighbor {core_ip}
      remote-as {ASN_PLAN[site]['core']}
      description Legacy core (migration only)
      shutdown
      address-family ipv4 unicast
        route-map RM-LEGACY-IN in
        route-map RM-LEGACY-OUT out
""".strip("\n")


def panos_handoff(site):
    S = SITES[site]
    o = S["o"]
    b1, b2 = border_pair()
    t3 = fw_transit(site, b1)
    t4 = fw_transit(site, b2)
    fw_as = ASN_PLAN[site]["fw"]
    fw = DATA["firewall"]
    p1, p2 = fw_ports()
    fs = S["fw_static"]
    sac_static = ""
    if fs:
        sac_static = f"""
# 5. {fs['name']} static points at the legacy core over {fw['old_interface']}. Replace it with two floating statics.
delete network virtual-router {fw['vr']} routing-table ip static-route {fs['name']}
set network virtual-router {fw['vr']} routing-table ip static-route {fs['name']}-LF03 destination {fs['prefix']} interface {t3[4]} nexthop ip-address {t3[3]} metric 255
set network virtual-router {fw['vr']} routing-table ip static-route {fs['name']}-LF04 destination {fs['prefix']} interface {t4[4]} nexthop ip-address {t4[3]} metric 255
"""
    bgp = f"set network virtual-router {fw['vr']} protocol bgp"
    vr = f"set network virtual-router {fw['vr']}"
    oa, ob = SITES[A()]["o"], SITES[B()]["o"]
    return f"""
# =============================================================================
# {S['fws'][0]} / {S['fws'][1]} · firewall handoff to the fabric ({fw['panos']}, configure mode)
# {DATA['doc']['classification_short']} Apply on the active member in the {STEP['firewall']} change window; HA syncs the peer.
# Replaces {fw['old_interface']} (10.{o}.{legacy_vlan()}.{fw['old_host']}/24) + OSPF with two routed interfaces + eBGP (AS {fw_as}).
# Before committing: check that no security, NAT or PBF rule references {fw['old_interface']}, and review
# "show config diff". Validate each command on the box.
# =============================================================================

# 1. Remove {fw['old_interface']} (OSPF, virtual router, zone, interface) and free its members.
delete network virtual-router {fw['vr']} protocol ospf area 0.0.0.0 interface {fw['old_interface']}
delete network virtual-router {fw['vr']} interface {fw['old_interface']}
delete zone {fw['zone']} network layer3 {fw['old_interface']}
delete network interface aggregate-ethernet {fw['old_interface']}
delete network interface ethernet {p1} aggregate-group
delete network interface ethernet {p2} aggregate-group

# 2. Two routed transit interfaces ({fw['zone']} zone, VR {fw['vr']}).
set network interface ethernet {p1} layer3 ip {t3[2]}/29
set network interface ethernet {p1} comment "{host(site, b1)} Eth1/45-46 VLAN {t3[0]} ({t3[1]})"
set network interface ethernet {p2} layer3 ip {t4[2]}/29
set network interface ethernet {p2} comment "{host(site, b2)} Eth1/45-46 VLAN {t4[0]} ({t4[1]})"
{vr} interface [ {p1} {p2} ]
set zone {fw['zone']} network layer3 [ {p1} {p2} ]

# 3. eBGP to both border leafs, ECMP across them. OSPF is no longer used.
{bgp} enable yes
{bgp} router-id {t3[2]}
{bgp} local-as {fw_as}
{bgp} install-route yes
{bgp} allow-redist-default-route yes
{bgp} routing-options ecmp-multi-as yes
{bgp} peer-group FABRIC enable yes type ebgp import-nexthop original export-nexthop resolve remove-private-as no
{bgp} peer-group FABRIC peer {host(site, b1)} enable yes peer-as {dev_asn(site, b1)} local-address interface {t3[4]} ip {t3[2]}/29 peer-address ip {t3[3]} bfd profile default
{bgp} peer-group FABRIC peer {host(site, b2)} enable yes peer-as {dev_asn(site, b2)} local-address interface {t4[4]} ip {t4[2]}/29 peer-address ip {t4[3]} bfd profile default
{vr} ecmp enable yes max-path 2
{vr} protocol ospf enable no

# 4. Policy: send only the default route; accept only the {A()} and {B()} site prefixes.
{bgp} redist-rules 0.0.0.0/0 enable yes set-origin igp address-family-identifier ipv4
{bgp} policy export rules DEFAULT-ONLY enable yes used-by FABRIC match address-prefix 0.0.0.0/0 exact yes
{bgp} policy export rules DEFAULT-ONLY action allow
{bgp} policy export rules DENY-REST enable yes used-by FABRIC action deny
{bgp} policy import rules SITE-PREFIXES enable yes used-by FABRIC match address-prefix 10.{oa}.0.0/16 exact no
{bgp} policy import rules SITE-PREFIXES match address-prefix 10.{ob}.0.0/16 exact no
{bgp} policy import rules SITE-PREFIXES action allow
{bgp} policy import rules DENY-REST enable yes used-by FABRIC action deny
{sac_static}
# Commit, then check:
#   show routing protocol bgp peer          -> 2 peers Established ({dev_asn(site, b1)}, {dev_asn(site, b2)})
#   show routing route type bgp             -> site prefixes via both next hops
""".strip("\n") + "\n"


def cfg_bgw(site, idx):
    S = SITES[site]
    o = S["o"]
    me = DEVICES[idx]
    asn = dev_asn(site, me[1])
    spine_asn = ASN_PLAN[site]["spine"]
    peer = S["peer"]
    P = SITES[peer]
    po = P["o"]
    lo0, lo1 = f"10.{o}.240.{me[2]}", f"10.{o}.241.{me[3]}"
    di = DOWNSTREAM.index(me[1])
    spine_ul, spine_ev = spine_bgp_cfg(site, di, ul_out="RM-FABRIC-UL-OUT")
    dci = bgw_dci(site, me[1])
    remote_ev = "\n".join(f"""  neighbor 10.{po}.240.{d[2]}
    remote-as {dev_asn(peer, d[1])}
    description {host(peer, d[1])} EVPN
    update-source loopback0
    ebgp-multihop 5
    peer-type fabric-external
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map RM-DCI-EVPN-IN in
      route-map RM-DCI-EVPN-OUT out""" for d in DEVICES if d[1].startswith("NXBGW"))
    dci_if = "\n".join(f"""interface {port}
  description DCI carrier {carrier} to {host(rs, rb)}
  no switchport
  mtu 9216                         ! set to the carrier's maximum if lower
  no ip redirects
  ip address {ip}/31
  evpn multisite dci-tracking
  no shutdown""" for carrier, port, ip, rs, rb, _ in dci)
    dci_nbr = "\n".join(f"""  ! DCI underlay (carrier {carrier})
  neighbor {rip}
    remote-as {dev_asn(rs, rb)}
    description {host(rs, rb)} underlay (carrier {carrier})
    bfd
    address-family ipv4 unicast
      route-map RM-DCI-UL-IN in
      route-map RM-DCI-UL-OUT out""" for carrier, _, _, rs, rb, rip in dci)
    aws_net, aws_me, aws_peer, az_net, az_me, az_peer, (dx_conn, er_link) = cloud_links(site, me[1])
    pl_aws = "\n".join(f"ip prefix-list PL-CLOUD-AWS seq {10 * (i + 1)} permit {n} le 24" for i, n in enumerate(CLOUD_AWS))
    pl_az = "\n".join(f"ip prefix-list PL-CLOUD-AZURE seq {10 * (i + 1)} permit {n} le 24" for i, n in enumerate(CLOUD_AZURE))

    def bgw_locals(oct_):
        g = [d for d in DEVICES if d[1].startswith("NXBGW")]
        return ([f"10.{oct_}.240.{d[2]}/32" for d in g] + [f"10.{oct_}.241.{d[3]}/32" for d in g]
                + [f"10.{oct_}.241.{BGW_VIP}/32"])
    cloud_if = cloud_nbr = ""
    if has_cloud(me[1]):
        cloud_if = f"""! ---- day-one cloud handoff (VRF TRUST) --------------------------------
! Routed subinterfaces only: an anycast BGW takes no endpoints, access ports or BGW-local VLANs.
interface {AWS_PORT}
  description AWS Direct Connect {dx_conn} (10G cross-connect)
  no switchport
  mtu 9216
  no shutdown

interface {AWS_PORT}.<AWS-VIF-VLAN>
  description AWS Direct Connect private VIF ({dx_conn})
  encapsulation dot1q <AWS-VIF-VLAN>    ! VLAN set on the VIF / by the hosted provider
  mtu 1500                              ! 9001 if the VIF is created with jumbo frames
  vrf member {TRUST['name']}
  no ip redirects
  ip address {aws_me}/30
  no shutdown

interface {AZURE_PORT}
  description Azure ExpressRoute {er_link} link (10G cross-connect)
  no switchport
  mtu 9216
  no shutdown

interface {AZURE_PORT}.<ER-VLAN>
  description Azure ExpressRoute private peering ({er_link} link)
  encapsulation dot1q <ER-VLAN>         ! VLAN ID configured on the ER private peering
  mtu 1500                              ! ExpressRoute MTU is 1500
  vrf member {TRUST['name']}
  no ip redirects
  ip address {az_me}/30
  no shutdown

"""
        cloud_nbr = f"""    neighbor {aws_peer}
      remote-as {AWS_ASN}
      description AWS Direct Connect private VIF ({dx_conn})
      password <AWS-BGP-MD5-KEY>          ! from the vault, same key as on the VIF
      bfd
      address-family ipv4 unicast
        route-map RM-AWS-IN in
        route-map RM-TO-CLOUD out
        maximum-prefix 100 warning-only
    neighbor {az_peer}
      remote-as {AZURE_ASN}
      description Azure ExpressRoute private peering ({er_link} link)
      bfd
      address-family ipv4 unicast
        route-map RM-AZURE-IN in
        route-map RM-TO-CLOUD out
        maximum-prefix 100 warning-only
"""
    pl_local = "\n".join(f"ip prefix-list PL-BGW-LOCAL seq {10 * (i + 1)} permit {n}" for i, n in enumerate(bgw_locals(o)))
    pl_remote = "\n".join(f"ip prefix-list PL-BGW-REMOTE seq {10 * (i + 1)} permit {n}" for i, n in enumerate(bgw_locals(po)))
    return f"""
hostname {host(site, me[1])}

nv overlay evpn
feature bgp
feature bfd
feature interface-vlan
feature vn-segment-vlan-based
feature nv overlay

evpn multisite border-gateway {S['site_id']}
  delay-restore time 300

interface loopback0
  ip address {lo0}/32
interface loopback1
  description VTEP
  ip address {lo1}/32
interface loopback100
  description Multi-Site VIP (shared by {"both" if len(bgws()) == 2 else "all"} {site} BGWs)
  ip address 10.{o}.241.{BGW_VIP}/32

{uplink_cfg(site, di, tracking=True)}

{dci_if}

{cloud_if}vrf context {TRUST['name']}
  vni {TRUST['l3vni']}
  rd auto
  address-family ipv4 unicast
    route-target both {TRUST['rt']}
    route-target both {TRUST['rt']} evpn
vlan {TRUST['vlan']}
  vn-segment {TRUST['l3vni']}
interface Vlan{TRUST['vlan']}
  no shutdown
  mtu 9216
  vrf member {TRUST['name']}
  ip forward

interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback1
  multisite border-gateway interface loopback100
  member vni {TRUST['l3vni']} associate-vrf

! ---- underlay filters: only BGW loopbacks cross the DCI ----------------
{pl_local}
{pl_remote}
route-map RM-FABRIC-UL-OUT permit 10    ! into the local fabric: own BGW loopbacks only
  match ip address prefix-list PL-BGW-LOCAL
route-map RM-DCI-UL-OUT permit 10
  match ip address prefix-list PL-BGW-LOCAL
route-map RM-DCI-UL-IN permit 10
  match ip address prefix-list PL-BGW-REMOTE

! ---- overlay filters: what may cross the DCI ---------------------------
ip prefix-list PL-{site}-SITE seq 10 permit 10.{o}.0.0/16 le 32
ip prefix-list PL-{peer}-SITE seq 10 permit 10.{po}.0.0/16 le 32
{pl_aws}
{pl_az}
ip prefix-list PL-TO-CLOUD seq 10 permit 10.{o}.0.0/16
ip prefix-list PL-TO-CLOUD-BACKUP seq 10 permit 10.{po}.0.0/16

route-map RM-DCI-EVPN-OUT permit 10     ! own site prefixes; never 0.0.0.0/0
  match ip address prefix-list PL-{site}-SITE
route-map RM-DCI-EVPN-OUT permit 20     ! cloud prefixes learned at this site (type-5)
  match ip address prefix-list PL-CLOUD-AWS PL-CLOUD-AZURE
route-map RM-DCI-EVPN-IN permit 10
  match ip address prefix-list PL-{peer}-SITE
route-map RM-DCI-EVPN-IN permit 20
  match ip address prefix-list PL-CLOUD-AWS PL-CLOUD-AZURE

! ---- what may be exchanged with AWS / Azure ----------------------------
route-map RM-AWS-IN permit 10           ! approved VPC CIDRs only; no default, no on-prem prefixes
  match ip address prefix-list PL-CLOUD-AWS
route-map RM-AZURE-IN permit 10         ! approved VNet CIDRs only
  match ip address prefix-list PL-CLOUD-AZURE
route-map RM-TO-CLOUD permit 10         ! this site's /16, preferred
  match ip address prefix-list PL-TO-CLOUD
route-map RM-TO-CLOUD permit 20         ! the other site's /16 as backup over the DCI
  match ip address prefix-list PL-TO-CLOUD-BACKUP
  set as-path prepend {asn} {asn} {asn}

router bgp {asn}
  router-id {lo0}
  bestpath as-path multipath-relax
  address-family ipv4 unicast
    network {lo0}/32
    network {lo1}/32
    network 10.{o}.241.{BGW_VIP}/32
    maximum-paths 4
  address-family l2vpn evpn
  ! local fabric: eBGP underlay on the links, eBGP EVPN to the spine loopbacks
{spine_ul}
{spine_ev}
{dci_nbr}
  ! DCI overlay to {"both" if len(bgws()) == 2 else "all"} remote BGWs
{remote_ev}
  ! cloud peerings: learned prefixes become type-5 routes in the local fabric and, through
  ! RM-DCI-EVPN-OUT, at the other site (which prefers its own cloud links: shorter AS path)
  vrf {TRUST['name']}
    address-family ipv4 unicast
      aggregate-address 10.{o}.0.0/16
      aggregate-address 10.{po}.0.0/16
      maximum-paths 4
{cloud_nbr}""".strip("\n")


def mgmt_cfg(site, idx):
    o = SITES[site]["o"]
    bl = DATA.get("baseline")
    dns = ""
    if bl:
        dns = "".join(f"\n  ip name-server {ip}" for ip in bl["dns"]) + f"\n  ip domain-name {bl['domain']}"
    return f"""
! ---- out-of-band management (10.{o}.245.0/24, gateway on the firewall) ---
vrf context management
  ip route 0.0.0.0/0 10.{o}.245.1{dns}
interface mgmt0
  vrf member management
  ip address 10.{o}.245.{DEVICES[idx][5]}/24
""".strip("\n")


def baseline_cfg(site, idx):
    """Management-plane baseline from the data file's "baseline" block. Every service runs in VRF
    management from mgmt0; secrets stay <placeholders> and are filled in from the vault at deployment."""
    bl = DATA.get("baseline")
    if not bl:
        return ""
    S = SITES[site]
    tacacs = bl["tacacs"]
    lines = ["! ---- baseline: hardening -------------------------------------------",
             "no feature telnet", "feature ssh", "password strength-check",
             "copp profile strict", "",
             "ip access-list ACL-VTY"]
    for i, net in enumerate(bl["mgmt_acl"]):
        lines.append(f"  {10 * (i + 1)} permit tcp {net} any eq 22")
    lines += ["  1000 deny ip any any log",
              "line console", f"  exec-timeout {bl['exec_timeout']}",
              "line vty", f"  exec-timeout {bl['exec_timeout']}", "  access-class ACL-VTY in", "",
              "! ---- baseline: AAA (TACACS+, local fallback when no server answers) -----",
              "feature tacacs+"]
    lines += [f"tacacs-server host {ip} key 7 <TACACS-KEY-TYPE7>" for ip in tacacs]
    lines += ["aaa group server tacacs+ TACACS"] + [f"  server {ip}" for ip in tacacs]
    lines += ["  use-vrf management", "  source-interface mgmt0",
              "aaa authentication login default group TACACS",
              "aaa authentication login console local",
              "aaa authorization commands default group TACACS local",
              "aaa accounting default group TACACS",
              "aaa authentication login error-enable",
              "username admin password 5 <LOCAL-ADMIN-HASH> role network-admin", "",
              "! ---- baseline: time, logging, SNMPv3 ----------------------------------",
              f"clock timezone {bl['timezone']} 0 0"]
    for i, ip in enumerate(bl["ntp"]):
        lines.append(f"ntp server {ip} use-vrf management" + (" prefer" if i == 0 else ""))
    lines += ["ntp source-interface mgmt0", ""]
    lines += [f"logging server {ip} {bl['syslog_level']} use-vrf management" for ip in bl["syslog"]]
    lines += ["logging source-interface mgmt0", "logging timestamp milliseconds", ""]
    snmp = bl["snmp"]
    lines += [f"snmp-server contact {snmp['contact']}",
              f"snmp-server location {S['code']} {S['facility']}, {S['city']}",
              f"snmp-server user {snmp['user']} network-operator auth sha <SNMP-AUTH-KEY> priv aes-128 <SNMP-PRIV-KEY>"]
    for ip in snmp["hosts"]:
        lines += [f"snmp-server host {ip} traps version 3 priv {snmp['user']}",
                  f"snmp-server host {ip} use-vrf management"]
    lines += ["snmp-server source-interface traps mgmt0", "snmp-server enable traps bgp", "",
              "banner motd ^", *bl["banner"], "^"]
    return "\n".join(lines)


def header(site, idx):
    role, suf = DEVICES[idx][0], DEVICES[idx][1]
    platform = f" · {bgw_platform()}" if suf.startswith("NXBGW") else ""
    if DATA.get("baseline"):
        baseline_line = "Baseline included: AAA/TACACS+, NTP, syslog, SNMPv3, CoPP, SSH-only vty, banner."
    else:
        baseline_line = f"Not included: AAA/TACACS, NTP, SNMP, syslog, banners, users. {DATA['doc']['baseline_note']}"
    return f"""
!==============================================================================
! {host(site, suf)} · {role} · BGP AS {dev_asn(site, suf)}{platform}
! {DATA['doc']['config_title']}
! {DATA['doc']['classification']}
! Template: validate against the exact Nexus model and NX-OS release before use.
! Fill in every <placeholder>. Host-gateway SVIs ship shut (migration step {STEP['gateways']}).
! {baseline_line}
!==============================================================================
""".strip("\n")


def full_config(site, idx):
    suf = DEVICES[idx][1]
    if suf.startswith("NXSP"):
        body = cfg_spine(site, idx)
    elif suf.startswith("NXBGW"):
        body = cfg_bgw(site, idx)
    else:
        body = _leaf_common(site, idx)
        if suf in border_pair():
            body += "\n\n" + cfg_border_extra(site, idx)
    lines = body.split("\n")
    base = baseline_cfg(site, idx)
    extra = ["", base] if base else []
    return "\n".join([header(site, idx), "", lines[0], "", mgmt_cfg(site, idx)] + extra + lines[1:]) + "\n"


# ---------------------------------------------------------------------------
# Day-2 checks: what each switch should show after each migration step
# ---------------------------------------------------------------------------
def bgp_sessions(site, idx):
    """Every BGP session one switch should have: (step, vrf, afi, neighbor IP, remote AS, peer name)."""
    S = SITES[site]
    o = S["o"]
    me = DEVICES[idx]
    suf = me[1]
    spine_asn = ASN_PLAN[site]["spine"]
    out = []
    if suf.startswith("NXSP"):
        for di, down in enumerate(DOWNSTREAM):
            _, b = p2p(site, idx, di)
            l0 = next(d[2] for d in DEVICES if d[1] == down)
            out.append((STEP["build"], "default", "ipv4", b, dev_asn(site, down), host(site, down)))
            out.append((STEP["build"], "default", "evpn", f"10.{o}.240.{l0}", dev_asn(site, down), host(site, down)))
        return out
    di = DOWNSTREAM.index(suf)
    for si, spine in enumerate(spines()):
        a, _ = p2p(site, si, di)
        out.append((STEP["build"], "default", "ipv4", a, spine_asn, host(site, spine)))
        out.append((STEP["build"], "default", "evpn", f"10.{o}.240.{si + 1}", spine_asn, host(site, spine)))
    if suf.startswith("NXLF"):
        pair = me[6]
        mate = DEVICES[idx + 1] if idx % 2 == 0 else DEVICES[idx - 1]
        k = pair * 8
        bk_peer = k + 6 if idx % 2 == 0 else k + 5
        out.append((STEP["build"], "default", "ipv4", f"10.{o}.243.{bk_peer}", dev_asn(site, mate[1]), host(site, mate[1])))
        if suf in border_pair():
            core_ip = S["core99"] or f"<{site}-CORE-VLAN{legacy_vlan()}-IP>"
            out.append((STEP["legacy"], TRUST["name"], "ipv4", core_ip, ASN_PLAN[site]["core"], "legacy core"))
            _, _, fw_ip, _, _ = fw_transit(site, suf)
            out.append((STEP["firewall"], TRUST["name"], "ipv4", fw_ip, ASN_PLAN[site]["fw"], S["fw_pair"]))
        return out
    peer = S["peer"]
    po = SITES[peer]["o"]
    for _, _, _, rs, rb, rip in bgw_dci(site, suf):
        out.append((STEP["multisite"], "default", "ipv4", rip, dev_asn(rs, rb), host(rs, rb)))
    for d in DEVICES:
        if d[1].startswith("NXBGW"):
            out.append((STEP["multisite"], "default", "evpn", f"10.{po}.240.{d[2]}", dev_asn(peer, d[1]), host(peer, d[1])))
    if has_cloud(suf):
        _, _, aws_peer, _, _, az_peer, _ = cloud_links(site, suf)
        out.append((STEP["multisite"], TRUST["name"], "ipv4", aws_peer, AWS_ASN, "AWS Direct Connect"))
        out.append((STEP["multisite"], TRUST["name"], "ipv4", az_peer, AZURE_ASN, "Azure ExpressRoute"))
    return out


def device_checks(site, idx):
    """(step, command, expected result) for one switch, in migration order."""
    S = SITES[site]
    o = S["o"]
    suf = DEVICES[idx][1]
    sessions = bgp_sessions(site, idx)
    checks = []

    def peers(step, vrf, afi, upto=False):
        rows = [x for x in sessions if x[1] == vrf and x[2] == afi
                and (x[0] <= step if upto else x[0] == step)]
        return ", ".join(f"{ip} (AS {asn}, {name})" for _, _, _, ip, asn, name in rows)

    def bgp(step, vrf, afi, upto=False):
        if not any(x[0] == step and x[1] == vrf and x[2] == afi for x in sessions):
            return
        cmd = {"ipv4": "show bgp ipv4 unicast summary", "evpn": "show bgp l2vpn evpn summary"}[afi]
        if vrf != "default":
            cmd = f"show bgp vrf {vrf} ipv4 unicast summary"
        checks.append((step, cmd, "Established: " + peers(step, vrf, afi, upto)))

    b = STEP["build"]
    bgp(b, "default", "ipv4")
    bgp(b, "default", "evpn")
    bfd = [ip for st, vrf, afi, ip, _, _ in sessions if st == b and vrf == "default" and afi == "ipv4"]
    checks.append((b, "show bfd neighbors", f"Up: {', '.join(bfd)}"))
    if suf.startswith("NXLF"):
        pair = DEVICES[idx][6]
        k = pair * 8
        ka_peer = k + 2 if idx % 2 == 0 else k + 1
        checks.append((b, "show vpc brief", f"Domain {S['vpc'][pair]}: peer adjacency formed ok, peer-keepalive alive "
                                            f"(10.{o}.243.{ka_peer}, VRF KEEPALIVE), peer-link Po10 up, type-1 consistency success"))
        l2 = ", ".join(str(S["vni"] + v) for v, _ in site_host_vlans(site))
        checks.append((b, "show nve vni", f"Up: L3VNI {TRUST['l3vni']} (VRF {TRUST['name']}); L2VNIs {l2} (BGP, SA)"))
        checks.append((b, "show nve interface nve1 detail",
                       f"Source loopback1 primary 10.{o}.241.{DEVICES[idx][3]}, secondary 10.{o}.241.{DEVICES[idx][4]}; "
                       "advertise-pip and advertise virtual-rmac enabled"))
    if suf.startswith("NXBGW"):
        checks.append((b, "show nve multisite fabric-links", "Up: " + ", ".join(uplink(i) for i in range(len(spines())))))
        checks.append((b, "show nve vni", f"Up: L3VNI {TRUST['l3vni']} (VRF {TRUST['name']}); no L2VNIs"))
    bl = DATA.get("baseline")
    if bl:
        checks.append((b, "show ntp peer-status", f"Synchronized (*) to one of {', '.join(bl['ntp'])}, VRF management"))
        checks.append((b, "show tacacs-server", f"Servers {', '.join(bl['tacacs'])}; test login with a TACACS account"))

    if suf in border_pair():
        bgp(STEP["legacy"], TRUST["name"], "ipv4")
        checks.append((STEP["legacy"], f"show ip route vrf {TRUST['name']} 0.0.0.0/0",
                       f"Via the legacy core (AS {ASN_PLAN[site]['core']}), local preference 50"))
    if suf.startswith("NXLF"):
        svis = ", ".join(f"Vlan{v} 10.{o}.{v}.1" for v, _ in site_host_vlans(site))
        checks.append((STEP["gateways"], f"show ip interface brief vrf {TRUST['name']}",
                       f"Up/up as each VLAN is cut over: {svis}"))
        checks.append((STEP["gateways"], f"show fabric forwarding ip local-host-db vrf {TRUST['name']}",
                       "Hosts of the migrated VLANs on this pair are learned"))
    if suf in border_pair():
        _, _, fw_ip, _, _ = fw_transit(site, suf)
        checks.append((STEP["firewall"], f"show bgp vrf {TRUST['name']} ipv4 unicast summary",
                       f"Established: {peers(STEP['firewall'], TRUST['name'], 'ipv4')}; 1 prefix received"))
        checks.append((STEP["firewall"], f"show ip route vrf {TRUST['name']} 0.0.0.0/0", f"Via {fw_ip} (eBGP), not the legacy core"))
    elif suf.startswith("NXLF"):
        b1, b2 = (next(d for d in DEVICES if d[1] == x) for x in border_pair())
        checks.append((STEP["firewall"], f"show ip route vrf {TRUST['name']} 0.0.0.0/0",
                       f"Via 10.{o}.241.{b1[3]} and 10.{o}.241.{b2[3]} ({short(b1[1])}/{short(b2[1])} PIPs), encap VXLAN"))

    if suf.startswith("NXBGW"):
        m = STEP["multisite"]
        ports = ", ".join(sorted(port for _, port, _, _, _, _ in bgw_dci(site, suf)))
        checks.append((m, "show nve multisite dci-links", f"Up: {ports}"))
        bgp(m, "default", "ipv4", upto=True)
        bgp(m, "default", "evpn", upto=True)
        bgp(m, TRUST["name"], "ipv4")
        po = SITES[S["peer"]]["o"]
        checks.append((m, "show nve peers", f"Includes 10.{po}.241.{BGW_VIP} (the {S['peer']} Multi-Site VIP), Up"))
        _, _, aws_peer, _, _, az_peer, _ = cloud_links(site, suf) if has_cloud(suf) else (None,) * 7
        if CLOUD_AWS and aws_peer:
            checks.append((m, f"show ip route vrf {TRUST['name']} {CLOUD_AWS[0]}", f"Via {aws_peer} (AWS, AS {AWS_ASN})"))
        if CLOUD_AZURE and az_peer:
            checks.append((m, f"show ip route vrf {TRUST['name']} {CLOUD_AZURE[0]}", f"Via {az_peer} (Azure, AS {AZURE_ASN})"))
    elif suf.startswith("NXLF"):
        P = SITES[S["peer"]]
        if P["host_vlans"]:
            v = P["host_vlans"][0][0]
            checks.append((STEP["multisite"], f"show ip route vrf {TRUST['name']} 10.{P['o']}.{v}.0/24",
                           f"Via 10.{o}.241.{BGW_VIP} (local BGW Multi-Site VIP), encap VXLAN"))

    if suf in border_pair():
        core_ip = S["core99"] or f"<{site}-CORE-VLAN{legacy_vlan()}-IP>"
        checks.append((STEP["cleanup"], f"show bgp vrf {TRUST['name']} ipv4 unicast summary",
                       f"No neighbor {core_ip}; migration block removed (Po30, Vlan{legacy_vlan()}, RM-LEGACY-*)"))
    order = list(STEP.values())
    return sorted(checks, key=lambda c: order.index(c[0]))


def checks_text(site, idx):
    name = host(site, DEVICES[idx][1])
    titles = {r[0]: r[1] for r in DATA["doc"]["migration"]}
    lines = [f"# {name} · day-2 checks by migration step", f"# {DATA['doc']['classification']}", ""]
    step = None
    for st, cmd, expect in device_checks(site, idx):
        if st != step:
            lines += ["", f"## {st} · {titles.get(st, '')}"] if step else [f"## {st} · {titles.get(st, '')}"]
            step = st
        lines += [f"{name}# {cmd}", f"  expect: {expect}"]
    return "\n".join(lines) + "\n"


def write_checks(outdir):
    outdir.mkdir(exist_ok=True)
    everything = []
    for site in SITE_ORDER:
        for idx, dev in enumerate(DEVICES):
            name = host(site, dev[1])
            (outdir / f"{name}.txt").write_text(checks_text(site, idx), encoding="utf-8")
            everything += [dict(device=name, step=st, command=cmd, expect=exp) for st, cmd, exp in device_checks(site, idx)]
    (outdir / "checks.json").write_text(json.dumps(everything, indent=1) + "\n", encoding="utf-8")
    return len(everything)


# ---------------------------------------------------------------------------
# Expected state: the design as data, for network-automation-tools to audit against
# ---------------------------------------------------------------------------
EXPECTED_STATE_SCHEMA = 1


def device_role(suf):
    if suf.startswith("NXSP"):
        return "spine"
    if suf.startswith("NXBGW"):
        return "bgw"
    return "border-leaf" if suf in border_pair() else "leaf"


def fabric_interfaces(site, idx):
    """{interface: dict(mtu, peer, address)} for every routed fabric link of one switch.

    Spine links on every switch, the vPC backup underlay SVI on leafs and the DCI ports on BGWs.
    """
    o = SITES[site]["o"]
    me = DEVICES[idx]
    suf = me[1]
    out = {}
    if suf.startswith("NXSP"):
        for di, down in enumerate(DOWNSTREAM):
            a, _ = p2p(site, idx, di)
            out[f"Ethernet1/{di + 1}"] = dict(mtu=9216, peer=host(site, down), address=f"{a}/31")
        return out
    di = DOWNSTREAM.index(suf)
    for si, spine in enumerate(spines()):
        _, a = p2p(site, si, di)
        out[uplink(si)] = dict(mtu=9216, peer=host(site, spine), address=f"{a}/31")
    if suf.startswith("NXLF"):
        mate = DEVICES[idx + 1] if idx % 2 == 0 else DEVICES[idx - 1]
        k = me[6] * 8
        bk_me = k + 5 if idx % 2 == 0 else k + 6
        out["Vlan3900"] = dict(mtu=9216, peer=host(site, mate[1]), address=f"10.{o}.243.{bk_me}/30")
    for carrier, port, ip, rs, rb, _ in (bgw_dci(site, suf) if suf.startswith("NXBGW") else []):
        out[port] = dict(mtu=9216, peer=host(rs, rb), address=f"{ip}/31", dci_carrier=carrier)
    return out


def expected_device(site, idx):
    """Everything an auditor should find on one switch once the migration is done, step by step."""
    S = SITES[site]
    o = S["o"]
    me = DEVICES[idx]
    suf = me[1]
    dev = dict(hostname=host(site, suf), site=site, role=device_role(suf), asn=dev_asn(site, suf),
               router_id=f"10.{o}.240.{me[2]}", mgmt=f"10.{o}.245.{me[5]}",
               interfaces=fabric_interfaces(site, idx), bgp=[])
    for step, vrf, afi, ip, asn, name in bgp_sessions(site, idx):
        legacy = name == "legacy core"
        s = dict(step=step, vrf=vrf, afi=afi, neighbor=ip, remote_as=asn, peer=name,
                 bfd=afi == "ipv4" and not legacy)
        if legacy:
            s["until"] = STEP["cleanup"]
        dev["bgp"].append(s)
    if suf.startswith("NXSP"):
        return dev
    l3 = dict(vni=TRUST["l3vni"], type="L3", vrf=TRUST["name"], vlan=TRUST["vlan"], rd="auto",
              route_target=TRUST["rt"])
    l2 = [dict(vni=S["vni"] + v, type="L2", vlan=v, rd="auto", route_target=f"{S['asn']}:{S['vni'] + v}")
          for v, _ in site_host_vlans(site)] if suf.startswith("NXLF") else []
    dev["vnis"] = [l3] + l2
    dev["nve"] = dict(source_interface="loopback1", primary=f"10.{o}.241.{me[3]}")
    if suf.startswith("NXLF"):
        pair = me[6]
        mate = DEVICES[idx + 1] if idx % 2 == 0 else DEVICES[idx - 1]
        k = pair * 8
        dev["nve"]["secondary"] = f"10.{o}.241.{me[4]}"
        dev["vpc"] = dict(domain=S["vpc"][pair], peer=host(site, mate[1]),
                          keepalive=f"10.{o}.243.{k + 2 if idx % 2 == 0 else k + 1}", peer_link="port-channel10")
    else:
        dev["multisite"] = dict(site_id=S["site_id"], vip=f"10.{o}.241.{BGW_VIP}",
                                fabric_links=[uplink(i) for i in range(len(spines()))],
                                dci_links=sorted(port for _, port, _, _, _, _ in bgw_dci(site, suf)))
    return dev


def expected_state():
    return dict(
        schema_version=EXPECTED_STATE_SCHEMA,
        generator="network-design",
        classification=DATA["doc"]["classification"],
        dci_mode=DCI_MODE,
        steps=[dict(id=r[0], title=r[1]) for r in DATA["doc"]["migration"]],
        sites=[dict(code=s, octet=SITES[s]["o"], multisite_site_id=SITES[s]["site_id"],
                    multisite_vip=f"10.{SITES[s]['o']}.241.{BGW_VIP}") for s in SITE_ORDER],
        devices=[expected_device(s, i) for s in SITE_ORDER for i in range(len(DEVICES))])


def write_expected_state(path):
    path.write_text(json.dumps(expected_state(), indent=1) + "\n", encoding="utf-8")
    return path


def write_configs(outdir):
    outdir.mkdir(exist_ok=True)
    written = []
    for site in SITE_ORDER:
        for idx, dev in enumerate(DEVICES):
            path = outdir / f"{host(site, dev[1])}.cfg"
            path.write_text(full_config(site, idx), encoding="utf-8")
            written.append(path)
        path = outdir / f"{site}-FW-handoff.panos.txt"
        path.write_text(panos_handoff(site), encoding="utf-8")
        written.append(path)
    return written


# ---------------------------------------------------------------------------
# Topology diagram
# ---------------------------------------------------------------------------
def node(x, y, w, h, title, lines, cls):
    out = [f'<g class="node {cls}"><rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8"/>',
           f'<text x="{x + w / 2}" y="{y + 17}" class="nt">{esc(title)}</text>']
    for i, line in enumerate(lines):
        out.append(f'<text x="{x + w / 2}" y="{y + 33 + i * 14}" class="ns">{esc(line)}</text>')
    out.append("</g>")
    return "".join(out)


def svg_geometry():
    """Panel width (grows with the leaf count) and extra height (grows with the BGW count)."""
    W = max(660, 30 + 163 * len(leafs()) - 22)
    extra = 78 * (len(bgws()) - 2)
    return W, extra


def site_svg(site, x0):
    S = SITES[site]
    o = S["o"]
    parts = []
    W, extra = svg_geometry()
    c = x0 + W / 2 if W != 660 else x0 + 330
    parts.append(f'<rect x="{x0}" y="50" width="{W}" height="{715 + extra}" rx="14" class="panel"/>')
    parts.append(f'<text x="{x0 + 18}" y="78" class="pt">{site} · {esc(S["city"])} ({esc(S["facility"])})</text>')
    parts.append(f'<text x="{x0 + 18}" y="96" class="ps">10.{o}.0.0/16 · AS {S["asn"]} · Multi-Site ID {S["site_id"]}</text>')
    # firewalls
    fw = [(int(c - 130), 115), (int(c + 40), 115)]
    for i, (x, y) in enumerate(fw):
        parts.append(node(x, y, 140, 52, S["fws"][i], ["Palo Alto HA A/P", f"eBGP AS {ASN_PLAN[site]['fw']}"], "fw"))
    parts.append(f'<line x1="{int(c + 10)}" y1="141" x2="{int(c + 40)}" y2="141" class="ha"/>')
    # spines, centred; 270 apart with two, closer with more
    ns = len(spines())
    gap = 270 if ns == 2 else min(270, (W - 40) // ns)
    spx = [int(c - 75 + (i - (ns - 1) / 2) * gap) for i in range(ns)]
    for i, x in enumerate(spx):
        parts.append(node(x, 235, 150, 56, host(site, spines()[i]), [f"Nexus 9500 · AS {ASN_PLAN[site]['spine']}", f"Lo0 10.{o}.240.{i + 1}"], "spine"))
    # leafs
    ls = leafs()
    lx = [x0 + 15 + 163 * i for i in range(len(ls))]
    for i, x in enumerate(lx):
        border = ls[i] in border_pair()
        parts.append(node(x, 415, 141, 70, host(site, ls[i]),
                          [("Border-service leaf" if border else "Nexus 9300 leaf"), f"Lo0 10.{o}.240.{11 + i}", f"Lo1 10.{o}.241.{11 + i}"], "leaf"))
    for pi in range(len(leaf_pairs())):
        cx = (lx[2 * pi] + lx[2 * pi + 1] + 141) / 2
        parts.append(f'<text x="{cx}" y="506" class="ann">vPC {S["vpc"][pi]} · VTEP VIP 10.{o}.241.{101 + pi}</text>')
    # BGWs near the DCI
    left = site == A()
    bx = x0 + W - 175 if left else x0 + 15
    by = [590 + 78 * j for j in range(len(bgws()))]
    for i, y in enumerate(by):
        parts.append(node(bx, y, 160, 56, host(site, bgws()[i]),
                          [f"Anycast · {bgw_platform().replace('N9K-C', '')}", f"Lo0 10.{o}.240.{21 + i}"], "bgw"))
    vx = bx + 80
    parts.append(f'<text x="{vx}" y="{744 + extra}" class="ann">Multi-Site VIP 10.{o}.241.200</text>')
    # day-one cloud on BGW-01/02 (VRF TRUST)
    cx0 = x0 + 250 if left else x0 + W - 410
    clouds = [("AWS Direct Connect", f"private VIF · 10.{o}.244.0/28", 597), ("Azure ExpressRoute", f"private peering · 10.{o}.244.16/29", 675)]
    for title, sub, y in clouds:
        parts.append(node(cx0, y, 170, 44, title, [sub], "cloud"))
        cx_edge = cx0 + 170 if left else cx0
        b_edge = bx if left else bx + 160
        for byy in by[:2]:
            parts.append(f'<line x1="{cx_edge}" y1="{y + 22}" x2="{b_edge}" y2="{byy + 28}" class="cl"/>')
    parts.append(f'<text x="{cx0 + 85}" y="590" class="ann">eBGP in VRF TRUST (day one)</text>')
    # links: spine to leafs/BGWs
    for sx in spx:
        scx = sx + 75
        for x in lx:
            parts.append(f'<line x1="{scx}" y1="291" x2="{x + 70}" y2="415" class="ul"/>')
        for y in by:
            parts.append(f'<line x1="{scx}" y1="291" x2="{vx}" y2="{y}" class="ul faint"/>')
    # firewall to border-service leafs
    for (fx, fy) in fw:
        for x in lx[-2:]:
            parts.append(f'<line x1="{fx + 70}" y1="167" x2="{x + 70}" y2="415" class="fwl"/>')
    e1, e2 = (pt.replace("ethernet", "e") for pt in fw_ports())
    b1, b2 = (short(x) for x in border_pair())
    parts.append(f'<text x="{x0 + W - 20}" y="205" class="ann end">{e1}→{b1} · {e2}→{b2} · 10.{o}.244.64/28 · eBGP</text>')
    # internet
    parts.append(f'<text x="{int(c + 10)}" y="40" class="ann">Internet / ISPs / IPsec mesh (unchanged)</text>')
    parts.append(f'<line x1="{int(c - 60)}" y1="46" x2="{int(c - 60)}" y2="115" class="fwl"/>')
    parts.append(f'<line x1="{int(c + 110)}" y1="46" x2="{int(c + 110)}" y2="115" class="fwl"/>')
    return "".join(parts), bx, by


def topology_svg(mode=None, title=None):
    """The two-site drawing. mode draws the DCI as "pair" or "full-mesh" instead of the configured mode."""
    global DCI_MODE
    if mode and mode != DCI_MODE:
        saved, DCI_MODE = DCI_MODE, mode
        try:
            return topology_svg(title=title)
        finally:
            DCI_MODE = saved
    W, extra = svg_geometry()
    mid = W + 40
    lvd, lbx, lby = site_svg(A(), 20)
    sac, sbx, sby = site_svg(B(), W + 60)
    dci = []
    row = {g: j for j, g in enumerate(bgws())}
    for link in dci_links():
        (s1, b1, _), (s2, b2, _) = link["ends"]
        ya, yb = (lby[row[b1]], sby[row[b2]]) if s1 == A() else (lby[row[b2]], sby[row[b1]])
        dash = ' stroke-dasharray="8 5"' if link["carrier"] == "B" else ""
        dci.append(f'<line x1="{lbx + 160}" y1="{ya + 28}" x2="{sbx}" y2="{yb + 28}" class="dci"{dash}/>')
    if DCI_MODE == "full-mesh":
        # straight circuits are carrier A; carrier B crosses over (dashed)
        dci.append(f'<text x="{mid}" y="580" class="ann">L3 DCI</text>')
        for y in lby:
            dci.append(f'<text x="{mid}" y="{y + 22}" class="ann small">A</text>')
        dci.append(f'<text x="{mid}" y="{762 + extra}" class="ann small">B: dashed, crossed</text>')
    else:
        dci.append(f'<text x="{mid}" y="{660 + extra}" class="ann">L3 DCI</text>')
        for j, y in enumerate(lby):
            dci.append(f'<text x="{mid}" y="{y + 22}" class="ann small">{"AB"[j % 2]}</text>')
    dci.append(f'<text x="{mid}" y="{790 + extra}" class="ann">eBGP between BGWs: IPv4 (BGW loopbacks) + L2VPN EVPN (VRF TRUST type-5: site /16 + approved cloud prefixes)</text>')
    ly = 815 + extra
    legend = ('<g class="legend">'
              f'<line x1="40" y1="{ly}" x2="80" y2="{ly}" class="ul"/><text x="88" y="{ly + 4}">eBGP underlay /31 + MP-BGP EVPN (eBGP, loopbacks)</text>'
              f'<line x1="360" y1="{ly}" x2="400" y2="{ly}" class="fwl"/><text x="408" y="{ly + 4}">Firewall handoff (routed /29, eBGP)</text>'
              f'<line x1="700" y1="{ly}" x2="740" y2="{ly}" class="dci"/><text x="748" y="{ly + 4}">DCI (eBGP)</text>'
              f'<line x1="880" y1="{ly}" x2="920" y2="{ly}" class="ha"/><text x="928" y="{ly + 4}">HA link</text>'
              f'<line x1="1020" y1="{ly}" x2="1060" y2="{ly}" class="cl"/><text x="1068" y="{ly + 4}">AWS / Azure (eBGP)</text></g>')
    head = f'<text x="20" y="28" class="pt">{esc(title)}</text>' if title else ""
    return (f'<svg viewBox="0 0 {2 * W + 80} {835 + extra}" role="img" aria-label="{A()} and {B()} EVPN Multi-Site topology" class="topo">'
            f'{head}{lvd}{sac}{"".join(dci)}{legend}</svg>')


DCI_OPTIONS = {
    "full-mesh": ("Full-mesh DCI", "each BGW has one circuit on each carrier, to a different remote BGW",
                  "Losing a carrier, a circuit or a BGW leaves every surviving BGW in Multi-Site"),
    "pair": ("Pair DCI", "each BGW has one circuit, to its namesake at the other site",
             "Losing a carrier or a circuit takes a BGW out of Multi-Site at each site; losing a BGW also "
             "isolates its partner"),
}


def dci_option_title(mode):
    name, how, _ = DCI_OPTIONS[mode]
    n = len(bgws()) * (2 if mode == "full-mesh" else 1)
    return f"{A()}–{B()} · {name}: {n} circuits, {how}"


def standalone_svg(mode):
    """A self-contained SVG file of the topology with the given DCI option (styles inlined)."""
    css = PAGE[PAGE.index("<style>") + 7:PAGE.index("</style>")]
    svg = topology_svg(mode, dci_option_title(mode))
    svg = svg.replace("<svg ", '<svg xmlns="http://www.w3.org/2000/svg" style="font-family:-apple-system,'
                      'BlinkMacSystemFont,&quot;Segoe UI&quot;,Inter,Roboto,sans-serif" ', 1)
    i = svg.index(">") + 1
    return (svg[:i] + f"<style>{css}</style>" + '<rect width="100%" height="100%" style="fill:var(--bg)"/>'
            + svg[i:] + "\n")


def write_diagrams(outdir):
    outdir.mkdir(exist_ok=True)
    for mode in DCI_OPTIONS:
        (outdir / f"topology-{mode}.svg").write_text(standalone_svg(mode), encoding="utf-8")
    return len(DCI_OPTIONS)


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------
def build():
    d = DATA["doc"]
    a, b = A(), B()
    oa, ob = SITES[a]["o"], SITES[b]["o"]
    sec = []

    sec.append(("summary", "1. Summary", "\n" + d["summary"] + "\n"))

    cur = d["current"]
    sec.append(("current", "2. What exists today",
                "\n" + cur["intro"] + "\n" + table(["", a, b], cur["rows"]) + "\n" + cur["outro"] + "\n"))

    sec.append(("topology", "3. Target topology",
                f"\n<figure>{topology_svg()}<figcaption>{d['topology_caption']}</figcaption></figure>\n"))

    sec.append(("decisions", "4. Design decisions", table(["#", "Area", "Decision", "Why", "Status"], d["decisions"], "dec")
                + "<h3>Cisco best-practice alignment</h3>" + table(["Practice", "In this design", "Where"], d["best_practice"])))

    dci_rows = []
    for link in dci_links():
        port = short_port(link["port"])
        (s1, b1, ip1), (s2, b2, ip2) = link["ends"]
        dci_rows.append([f"Carrier {link['carrier']}", host(s1, b1) + f" {port} " + mono(f"{ip1}/31"),
                         host(s2, b2) + f" {port} " + mono(f"{ip2}/31"), f"{s1} owns the addressing"])
    dev_h = ["Hostname", "Role", "Lo0 / router-ID", "Lo1 / VTEP", "Shared addresses", "mgmt0 (OOB)", "AS"]
    p2p_h = ["Spine", "Port", "Spine IP", "Peer", "Port", "Peer IP"]
    sec.append(("addressing", "5. Infrastructure addressing", f"""
{d['addressing_intro']}
<h3>Block plan</h3>
{table([a, b, "Use", "Allocation"], blocks_rows())}
<h3>Devices: {a}</h3>
{table(dev_h, device_rows(a))}
<h3>Devices: {b}</h3>
{table(dev_h, device_rows(b))}
<h3>Underlay links: {a}</h3>
{table(p2p_h, p2p_rows(a), "compact")}
<h3>Underlay links: {b}</h3>
{table(p2p_h, p2p_rows(b), "compact")}
<h3>vPC pairs</h3>
{table(["Domain", "Members", "Peer-keepalive", "Backup underlay VLAN 3900", "Anycast VTEP", "Peer-link"], vpc_rows(a) + vpc_rows(b))}
<h3>DCI, firewall and cloud handoff</h3>
{table(["Link", "Side A", "Side B", "Notes"], dci_rows + fw_rows() + cloud_rows())}
<h3>BGP AS plan</h3>
{table(["Role", a, b], asn_rows())}
"""))

    def cell(site, subnet, vlan):
        return (mono(subnet), esc(vni_range(site, vlan))) if subnet != "—" else ("—", "—")
    trust_rows, dmz_rows = [], []
    for vlan, name, sa, sb, note in TRUST_VLANS:
        trust_rows.append([esc(vlan), esc(name), *cell(a, sa, vlan), *cell(b, sb, vlan), esc(note)])
    for vlan, name, sa, sb in DMZ_VLANS:
        dmz_rows.append([esc(vlan), esc(name), *cell(a, sa, vlan), *cell(b, sb, vlan)])
    t = d["tenants"]
    vh = ["VLAN", "Name", f"{a} subnet", f"{a} L2VNI", f"{b} subnet", f"{b} L2VNI"]
    sec.append(("tenants", "6. VLAN, VNI and VRF matrix", f"""
<h3>6.1 Routed VLANs: anycast gateway in VRF {TRUST['name']}</h3>
{t['routed_intro']}
{table(vh + ["Notes"], trust_rows)}
<h3>6.2 DMZ VLANs: gateway stays on the firewall (optional phase)</h3>
{t['dmz_intro']}
{table(vh, dmz_rows)}
<h3>6.3 Stays directly on the firewall</h3>
{t['firewall_direct']}
<h3>6.4 VRFs</h3>
{table(["VRF", "ID", "L3VNI", "L3VNI VLAN", "Route target", "Sites", "Contents"], t['vrfs'])}
{t['vrf_note']}
"""))

    panos = "".join(f"\n<details><summary>PAN-OS commands: {site}</summary>{code(panos_handoff(site))}</details>"
                    for site in SITE_ORDER)
    sec.append(("firewall", "7. Firewall integration", "\n" + d["firewall"] + panos + "\n"))

    ms = d["multisite"]
    bgw_lo0 = "/.".join(str(x[2]) for x in DEVICES if x[1].startswith("NXBGW"))
    ms_rows = [
        ["Multi-Site site ID", str(SITES[a]["site_id"]), str(SITES[b]["site_id"])],
        ["BGW Multi-Site VIP (loopback100)", mono(f"10.{oa}.241.{BGW_VIP}/32"), mono(f"10.{ob}.241.{BGW_VIP}/32")],
        ["BGW Lo0", mono(f"10.{oa}.240.{bgw_lo0}"), mono(f"10.{ob}.240.{bgw_lo0}")],
        (["DCI underlay", f"Full mesh: every BGW has one circuit on each carrier, to a different {b} BGW",
          f"Full mesh: every BGW has one circuit on each carrier, to a different {a} BGW"]
         if DCI_MODE == "full-mesh" else
         ["DCI underlay", f"eBGP to {b} over carrier A (BGW-01) and B (BGW-02)", f"eBGP to {a} over carrier A (BGW-01) and B (BGW-02)"]),
        ["DCI overlay", f"eBGP EVPN multihop, Lo0 to both {b} BGWs, peer-type fabric-external", f"Same, toward the {a} BGWs"],
        ["Advertised over DCI", f"Type-5 routes in 10.{oa}.0.0/16, AWS/Azure prefixes learned at {a}, BGW loopbacks",
         f"Type-5 routes in 10.{ob}.0.0/16, AWS/Azure prefixes learned at {b}, BGW loopbacks"],
        ["Never advertised over DCI", "0.0.0.0/0, prefixes outside the site /16 and cloud allowlists, L2VNIs", "Same"],
    ]
    allow = table(["Allowlist", "Prefixes (each le /24)"], [
        ["PL-CLOUD-AWS", ", ".join(mono(n) for n in CLOUD_AWS)],
        ["PL-CLOUD-AZURE", ", ".join(mono(n) for n in CLOUD_AZURE)],
    ])
    options = []
    for mode, (name, how, failure) in DCI_OPTIONS.items():
        chosen = " (this design)" if mode == DCI_MODE else ""
        options.append(f'<figure>{topology_svg(mode, dci_option_title(mode))}<figcaption><b>{name}{chosen}.</b> '
                       f'{failure}. Same drawing as <a href="diagrams/topology-{mode}.svg">diagrams/topology-{mode}.svg</a>.'
                       '</figcaption></figure>')
    sec.append(("multisite", "8. Multi-Site, DCI and cloud",
                "\n" + table(["Item", a, b], ms_rows) + "\n" + ms["body"] + "\n" + allow + "\n" + ms["allowlist_note"] + "\n"
                + "<h3>DCI options compared</h3>" + "".join(options) + "\n"))

    cfgs = []
    for site in SITE_ORDER:
        cfgs.append(f"<h3>{site}</h3>")
        for idx, dev in enumerate(DEVICES):
            name = host(site, dev[1])
            cfgs.append(f'<details><summary>{name} ({esc(dev[0])}) · <a href="configs/{name}.cfg">{name}.cfg</a></summary>'
                        f'{code(full_config(site, idx))}</details>')
    c = d["configs"]
    sec.append(("configs", "9. NX-OS configuration templates", "\n" + c["intro"] + "\n" + c["note"] + "\n" + "".join(cfgs) + "\n"))

    sec.append(("migration", d.get("migration_title", "10. Migration from the legacy core"),
                table(["Step", "What", "Detail", "Risk"], d["migration"])
                + "<p>Every switch has a check list for each step in <code>checks/</code> (and section 13).</p>"))
    sec.append(("tests", "11. Failure test matrix", table(["Failure", "Expected result", "Evidence"], d["tests"])))
    sec.append(("open", "12. Open items before implementation", table(["Item", "What is needed"], d["open_items"])))
    chk = []
    for site in SITE_ORDER:
        chk.append(f"<h3>{site}</h3>")
        for idx, dev in enumerate(DEVICES):
            name = host(site, dev[1])
            rows = [[esc(st), mono(cmd), esc(exp)] for st, cmd, exp in device_checks(site, idx)]
            chk.append(f'<details><summary>{name} · {len(rows)} checks · <a href="checks/{name}.txt">{name}.txt</a></summary>'
                       f'{table(["Step", "Command", "Expect"], rows, "compact")}</details>')
    sec.append(("checks", "13. Day-2 checks by migration step",
                "\n<p>What each switch should show once each migration step is done. The same list is in "
                "<code>checks/&lt;switch&gt;.txt</code> and, for automation, <code>checks/checks.json</code>. "
                "Expected BGP sessions, VNIs, vPC and DCI links are generated from the same model as the "
                "configs, and the tests check that the two agree.</p>" + "".join(chk) + "\n"))

    nav = "".join(f'<a href="#{sid}">{esc(t_)}</a>' for sid, t_, _ in sec)
    body = "".join(f'<section id="{sid}"><h2>{esc(t_)}</h2>{content}</section>' for sid, t_, content in sec)
    page = PAGE
    for key in ("html_title", "title", "subtitle", "badge", "footer"):
        page = page.replace("{{" + key.upper() + "}}", d[key])
    return page.replace("{{NAV}}", nav).replace("{{BODY}}", body)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fabric_design.build", description=__doc__.strip().splitlines()[0])
    ap.add_argument("data", type=Path, help="site data JSON (see examples/demo-fabric.json)")
    ap.add_argument("--out", type=Path, required=True, help="output folder for the workbook and configs/")
    args = ap.parse_args(argv)
    try:
        load(json.loads(args.data.read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError) as exc:
        detail = exc if isinstance(exc, ValueError) else repr(exc)
        print(f"fabric_design: cannot load {args.data}: {detail}", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    page = args.out / DATA["doc"].get("output_html", "design.html")
    page.write_text(build(), encoding="utf-8")
    print("wrote", page)
    files = write_configs(args.out / "configs")
    print("wrote", len(files), "files to", args.out / "configs")
    n = write_checks(args.out / "checks")
    print("wrote", n, "checks to", args.out / "checks")
    print("wrote", write_expected_state(args.out / "expected-state.json"))
    write_diagrams(args.out / "diagrams")
    print("wrote", len(DCI_OPTIONS), "DCI option diagrams to", args.out / "diagrams")
    return 0


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{HTML_TITLE}}</title>
<style>
:root{--bg:#f7f8fa;--surface:#fff;--ink:#1a1f2b;--muted:#5b6474;--line:#dde2ea;--accent:#2457c5;--code:#f1f3f7;
--spine:#e8f0ff;--spine-b:#5b7fd6;--leaf:#e9f7ef;--leaf-b:#3c9a63;--bgw:#fff1e6;--bgw-b:#d1782f;--fw:#fdecec;--fw-b:#c94a4a;
--ul:#3c9a63;--fwl:#9a5ad1;--dci:#d1782f;--warn:#fff7e0;--warn-b:#e0b84c;--cloud:#e8f4fb;--cloud-b:#2b8cbe}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#11141a;--surface:#181c24;--ink:#e6e9ef;--muted:#9aa3b2;--line:#2b313d;--accent:#7ea2ff;--code:#1f2430;
--spine:#1c2740;--spine-b:#7ea2ff;--leaf:#16291f;--leaf-b:#5cc48a;--bgw:#2e2116;--bgw-b:#f0a060;--fw:#2e1a1a;--fw-b:#f07a7a;--ul:#5cc48a;--fwl:#c08cf0;--dci:#f0a060;--warn:#2b2614;--warn-b:#a88a35;--cloud:#14242e;--cloud-b:#5fb4e0}}
:root[data-theme="dark"]{--bg:#11141a;--surface:#181c24;--ink:#e6e9ef;--muted:#9aa3b2;--line:#2b313d;--accent:#7ea2ff;--code:#1f2430;
--spine:#1c2740;--spine-b:#7ea2ff;--leaf:#16291f;--leaf-b:#5cc48a;--bgw:#2e2116;--bgw-b:#f0a060;--fw:#2e1a1a;--fw-b:#f07a7a;--ul:#5cc48a;--fwl:#c08cf0;--dci:#f0a060;--warn:#2b2614;--warn-b:#a88a35;--cloud:#14242e;--cloud-b:#5fb4e0}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif}
header{padding:32px 16px 20px;max-width:1180px;margin:0 auto}
h1{font-size:26px;margin:0 0 6px}
.sub{color:var(--muted);margin:0}
.badge{display:inline-block;margin-top:10px;padding:3px 10px;border-radius:999px;background:var(--warn);border:1px solid var(--warn-b);font-size:12.5px}
nav{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line);padding:8px 16px;overflow-x:auto;white-space:nowrap}
nav a{color:var(--muted);text-decoration:none;margin-right:16px;font-size:13.5px}
nav a:hover{color:var(--accent)}
main{max-width:1180px;margin:0 auto;padding:0 16px 60px}
section{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin:22px 0}
h2{font-size:20px;margin:0 0 12px}
h3{font-size:15.5px;margin:22px 0 8px}
ul{padding-left:20px}li{margin:4px 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.8px;background:var(--code);padding:1px 4px;border-radius:4px;white-space:nowrap}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:14px;overflow-x:auto;font-size:12.5px;line-height:1.45}
pre code{background:none;padding:0;white-space:pre}
.tw{overflow-x:auto;margin:8px 0 4px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{border-bottom:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12.5px;text-transform:uppercase;letter-spacing:.03em}
table.compact td{padding:4px 9px}
table.dec td:last-child{white-space:nowrap;font-weight:600}
.note{background:var(--warn);border:1px solid var(--warn-b);border-radius:8px;padding:10px 14px;margin:12px 0;font-size:14px}
.small{font-size:12.5px;color:var(--muted)}
details{border:1px solid var(--line);border-radius:8px;margin:8px 0;padding:0 12px}
summary{cursor:pointer;padding:10px 0;font-weight:600}
figure{margin:0}
figcaption{color:var(--muted);font-size:13px;margin-top:6px}
svg.topo{width:100%;height:auto;display:block}
.panel{fill:none;stroke:var(--line);stroke-width:1.5}
.pt{fill:var(--ink);font-weight:700;font-size:15px}
.ps{fill:var(--muted);font-size:12px}
.node rect{stroke-width:1.5}
.node.spine rect{fill:var(--spine);stroke:var(--spine-b)}
.node.leaf rect{fill:var(--leaf);stroke:var(--leaf-b)}
.node.bgw rect{fill:var(--bgw);stroke:var(--bgw-b)}
.node.fw rect{fill:var(--fw);stroke:var(--fw-b)}
.node.cloud rect{fill:var(--cloud);stroke:var(--cloud-b)}
.cl{stroke:var(--cloud-b);stroke-width:1.6}
.nt{fill:var(--ink);font-weight:700;font-size:11.5px;text-anchor:middle}
.ns{fill:var(--muted);font-size:10.5px;text-anchor:middle;font-family:ui-monospace,Menlo,monospace}
.ann{fill:var(--muted);font-size:11px;text-anchor:middle}
.ann.end{text-anchor:end}
.ann.small{font-weight:700;fill:var(--dci)}
.ul{stroke:var(--ul);stroke-width:1.2;opacity:.75}
.ul.faint{opacity:.35}
.fwl{stroke:var(--fwl);stroke-width:1.4;stroke-dasharray:5 4}
.dci{stroke:var(--dci);stroke-width:3}
.ha{stroke:var(--fw-b);stroke-width:2;stroke-dasharray:2 3}
.legend text{fill:var(--muted);font-size:12px}
footer{max-width:1180px;margin:0 auto;padding:0 16px 40px;color:var(--muted);font-size:12.5px}
@media print{nav{display:none}section{break-inside:avoid-page;border:none}details{border:none}details>*{display:block}body{background:#fff}}
</style></head>
<body>
<header>
<h1>{{TITLE}}</h1>
<p class="sub">{{SUBTITLE}}</p>
<span class="badge">{{BADGE}}</span>
</header>
<nav>{{NAV}}</nav>
<main>{{BODY}}</main>
<footer>{{FOOTER}}</footer>
</body></html>
"""

if __name__ == "__main__":
    sys.exit(main())
