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


def load(data):
    """Install a site data document (see examples/demo-fabric.json) as the design input."""
    global DATA, SITES, SITE_ORDER, ASN_PLAN, TRUST_VLANS, DMZ_VLANS, CLOUD_AWS, CLOUD_AZURE, AWS_ASN, AZURE_ASN
    sites = data["sites"]
    if len(sites) != 2:
        raise ValueError("the design covers exactly two sites")
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


def A():
    return SITE_ORDER[0]


def B():
    return SITE_ORDER[1]


def fw_ports():
    return DATA["firewall"]["ports"]


def legacy_vlan():
    return DATA["legacy"]["vlan"]


# role, suffix, lo0, lo1, vpc vip, mgmt0, vpc pair index
DEVICES = [
    ("Spine / EVPN route server", "NXSP-01", 1, None, None, 11, None),
    ("Spine / EVPN route server", "NXSP-02", 2, None, None, 12, None),
    ("Leaf / VTEP", "NXLF-01", 11, 11, 101, 21, 0),
    ("Leaf / VTEP", "NXLF-02", 12, 12, 101, 22, 0),
    ("Border-service leaf / VTEP", "NXLF-03", 13, 13, 102, 23, 1),
    ("Border-service leaf / VTEP", "NXLF-04", 14, 14, 102, 24, 1),
    ("Multi-Site BGW", "NXBGW-01", 21, 21, None, 31, None),
    ("Multi-Site BGW", "NXBGW-02", 22, 22, None, 32, None),
]
DOWNSTREAM = ["NXLF-01", "NXLF-02", "NXLF-03", "NXLF-04", "NXBGW-01", "NXBGW-02"]
BGW_VIP = 200
ANYCAST_MAC = "2020.0000.00aa"

TRUST = dict(name="TRUST", id=10, l3vni=50010, vlan=3910, rt="65000:50010")

def cloud_links(site, bgw):
    """(AWS /30 net, BGW IP, AWS IP, Azure /30 net, BGW IP, MSEE IP, label) for one BGW.

    BGW-01 carries DX connection 1 and the ER primary link, BGW-02 DX connection 2 and the ER secondary.
    Azure uses the first usable address of each /30 for the customer and the second for Microsoft.
    """
    o = SITES[site]["o"]
    k = 0 if bgw == "NXBGW-01" else 1
    aws = 0 + k * 8
    az = 16 + k * 4
    return (f"10.{o}.244.{aws}/30", f"10.{o}.244.{aws + 1}", f"10.{o}.244.{aws + 2}",
            f"10.{o}.244.{az}/30", f"10.{o}.244.{az + 1}", f"10.{o}.244.{az + 2}",
            ("connection 1", "primary") if k == 0 else ("connection 2", "secondary"))


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
    for si, spine in enumerate(["NXSP-01", "NXSP-02"]):
        for di, down in enumerate(DOWNSTREAM):
            a, b = p2p(site, si, di)
            rows.append([esc(host(site, spine)), f"Eth1/{di + 1}", mono(f"{a}/31"),
                         esc(host(site, down)), f"Eth1/{49 + si}", mono(f"{b}/31")])
    return rows


def blocks_rows():
    rows = []
    spec = [
        ("240.0/24", "Loopback0: router-ID and EVPN peering", "One /32 per device"),
        ("241.0/24", "Loopback1: VTEP (NVE source), vPC anycast VTEP, Multi-Site VIP (loopback100)", "Leafs/BGWs .11–.22, vPC VIPs .101–.102, BGW VIP .200"),
        ("242.0/24", "Underlay point-to-point /31s (spine to leaf/BGW)", "Spine-01 from .0, spine-02 from .32; spine side even"),
        ("243.0/24", "vPC peer-keepalive and backup underlay VLAN 3900 (/30s)", "Pair A .0–.7, pair B .8–.15"),
        ("244.0/24", "Day-one cloud peering in VRF TRUST: AWS Direct Connect and Azure ExpressRoute (one /29 slot per peering)", ".0/29 DX conn 1 (BGW-01), .8/29 DX conn 2 (BGW-02), .16/29 ER = primary .16/30 (BGW-01) + secondary .20/30 (BGW-02). .64/29 + .72/29: firewall eBGP transit (LF-03, LF-04). The rest is reserved for per-VRF firewall transit"),
        ("245.0/24", "New OOB management for mgmt0 (gateway on the firewall, not on the fabric)", "Gateway .1, devices .11–.32"),
        ("246.0/24", "DCI point-to-point /31s (each site owns one carrier)", f"{A()}: carrier A, {B()}: carrier B"),
        ("247.0/24", "Reserved for growth (more leafs, a second pod)", ""),
    ]
    for suffix, use, detail in spec:
        rows.append([mono(f"10.{SITES[A()]['o']}.{suffix}"), mono(f"10.{SITES[B()]['o']}.{suffix}"), esc(use), esc(detail)])
    return rows


def fw_rows():
    rows = []
    for site in SITE_ORDER:
        for leaf in ("NXLF-03", "NXLF-04"):
            vlan, net, fw_ip, leaf_ip, fw_port = fw_transit(site, leaf)
            rows.append([f"{site} firewall", f"{SITES[site]['fw_pair']} {fw_port} " + mono(f"{fw_ip}/29") + f" (AS {ASN_PLAN[site]['fw']})",
                         f"{esc(host(site, leaf))} VLAN {vlan} SVI " + mono(f"{leaf_ip}/29") + f" (AS {dev_asn(site, leaf)})",
                         "eBGP + BFD, VRF TRUST. FW-01 on Eth1/45, FW-02 on Eth1/46"])
    return rows


def asn_rows():
    labels = [("spine", "Spines (both)"), ("NXLF-01", "LF-01"), ("NXLF-02", "LF-02"), ("NXLF-03", "LF-03 (border-service)"),
              ("NXLF-04", "LF-04 (border-service)"), ("NXBGW-01", "BGW-01"), ("NXBGW-02", "BGW-02"),
              ("fw", "Palo Alto HA pair"), ("core", "Legacy core (migration only)")]
    rows = [[esc(l), str(ASN_PLAN[A()][k]), str(ASN_PLAN[B()][k])] for k, l in labels]
    rows.append(["AWS DX gateway / Azure ER", f"{AWS_ASN} / {AZURE_ASN}", f"{AWS_ASN} / {AZURE_ASN}"])
    return rows


def cloud_rows():
    rows = []
    for site in SITE_ORDER:
        for bgw in ("NXBGW-01", "NXBGW-02"):
            aws_net, aws_me, aws_peer, az_net, az_me, az_peer, (dx, er) = cloud_links(site, bgw)
            rows.append([f"{site} AWS DX {dx}", f"{esc(host(site, bgw))} Eth1/52.&lt;VIF VLAN&gt; " + mono(f"{aws_me}/30"),
                         f"AWS (AS {AWS_ASN}) " + mono(aws_peer), "Private VIF, VRF TRUST, BFD, MD5"])
            rows.append([f"{site} Azure ER {er}", f"{esc(host(site, bgw))} Eth1/52.&lt;ER VLAN&gt; " + mono(f"{az_me}/30"),
                         f"Microsoft MSEE (AS {AZURE_ASN}) " + mono(az_peer), "Private peering, VRF TRUST, BFD"])
    return rows


def vpc_rows(site):
    S = SITES[site]
    o = S["o"]
    rows = []
    for i, (a, b) in enumerate([("NXLF-01", "NXLF-02"), ("NXLF-03", "NXLF-04")]):
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
                  "  shutdown                        ! no shutdown at this VLAN's gateway cut-over (migration M4)",
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
    s1, a1 = p2p(site, 0, di)
    s2, a2 = p2p(site, 1, di)
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

interface Ethernet1/49
  description {host(site, 'NXSP-01')} Eth1/{di + 1}
  no switchport
  mtu 9216
  no ip redirects
  ip address {a1}/31
  no shutdown

interface Ethernet1/50
  description {host(site, 'NXSP-02')} Eth1/{di + 1}
  no switchport
  mtu 9216
  no ip redirects
  ip address {a2}/31
  no shutdown

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
  neighbor {s1}
    remote-as {spine_asn}
    description {host(site, 'NXSP-01')} underlay
    bfd
    address-family ipv4 unicast
  neighbor {s2}
    remote-as {spine_asn}
    description {host(site, 'NXSP-02')} underlay
    bfd
    address-family ipv4 unicast
  neighbor 10.{o}.243.{bk_peer}
    remote-as {dev_asn(site, mate[1])}
    description {host(site, mate[1])} vPC backup underlay
    bfd
    address-family ipv4 unicast
  neighbor 10.{o}.240.1
    remote-as {spine_asn}
    description {host(site, 'NXSP-01')} EVPN
    update-source loopback0
    ebgp-multihop 2
    address-family l2vpn evpn
      send-community
      send-community extended
  neighbor 10.{o}.240.2
    remote-as {spine_asn}
    description {host(site, 'NXSP-02')} EVPN
    update-source loopback0
    ebgp-multihop 2
    address-family l2vpn evpn
      send-community
      send-community extended
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
    k = 0 if leaf == "NXLF-03" else 1
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
    svi99 = f"10.{o}.{lv}.{11 if me[1] == 'NXLF-03' else 12}"
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

! ---- migration only (M2-M5): eBGP to the legacy core over VLAN {lv} -------
! The legacy core must run BGP (AS {ASN_PLAN[site]['core']}) for the migration window and
! redistribute its connected/OSPF routes into it. Remove this block at M7.
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
route-map RM-LEGACY-IN permit 20      ! legacy default until the firewall moves (M5)
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
    t3 = fw_transit(site, "NXLF-03")
    t4 = fw_transit(site, "NXLF-04")
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
# {DATA['doc']['classification_short']} Apply on the active member in the M5 change window; HA syncs the peer.
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
set network interface ethernet {p1} comment "{host(site, 'NXLF-03')} Eth1/45-46 VLAN {t3[0]} ({t3[1]})"
set network interface ethernet {p2} layer3 ip {t4[2]}/29
set network interface ethernet {p2} comment "{host(site, 'NXLF-04')} Eth1/45-46 VLAN {t4[0]} ({t4[1]})"
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
{bgp} peer-group FABRIC peer {host(site, 'NXLF-03')} enable yes peer-as {dev_asn(site, 'NXLF-03')} local-address interface {t3[4]} ip {t3[2]}/29 peer-address ip {t3[3]} bfd profile default
{bgp} peer-group FABRIC peer {host(site, 'NXLF-04')} enable yes peer-as {dev_asn(site, 'NXLF-04')} local-address interface {t4[4]} ip {t4[2]}/29 peer-address ip {t4[3]} bfd profile default
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
#   show routing protocol bgp peer          -> 2 peers Established ({dev_asn(site, 'NXLF-03')}, {dev_asn(site, 'NXLF-04')})
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
    s1, a1 = p2p(site, 0, di)
    s2, a2 = p2p(site, 1, di)
    first = me[1] == "NXBGW-01"
    # carrier A: A-BGW-01 <-> B-BGW-01 in site A's 10.x.246.0/31; carrier B: B-BGW-02 <-> A-BGW-02 in site B's
    if first:
        carrier, net_o = "A", SITES[A()]["o"]
        mine = 0 if site == A() else 1
    else:
        carrier, net_o = "B", SITES[B()]["o"]
        mine = 0 if site == B() else 1
    dci_me, dci_peer = f"10.{net_o}.246.{mine}", f"10.{net_o}.246.{1 - mine}"
    remote_bgw = host(peer, me[1])
    aws_net, aws_me, aws_peer, az_net, az_me, az_peer, (dx_conn, er_link) = cloud_links(site, me[1])
    pl_aws = "\n".join(f"ip prefix-list PL-CLOUD-AWS seq {10 * (i + 1)} permit {n} le 24" for i, n in enumerate(CLOUD_AWS))
    pl_az = "\n".join(f"ip prefix-list PL-CLOUD-AZURE seq {10 * (i + 1)} permit {n} le 24" for i, n in enumerate(CLOUD_AZURE))

    def bgw_locals(oct_):
        return [f"10.{oct_}.240.21/32", f"10.{oct_}.240.22/32", f"10.{oct_}.241.21/32", f"10.{oct_}.241.22/32",
                f"10.{oct_}.241.{BGW_VIP}/32"]
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
  description Multi-Site VIP (shared by both {site} BGWs)
  ip address 10.{o}.241.{BGW_VIP}/32

interface Ethernet1/49
  description {host(site, 'NXSP-01')} Eth1/{di + 1}
  no switchport
  mtu 9216
  no ip redirects
  ip address {a1}/31
  evpn multisite fabric-tracking
  no shutdown
interface Ethernet1/50
  description {host(site, 'NXSP-02')} Eth1/{di + 1}
  no switchport
  mtu 9216
  no ip redirects
  ip address {a2}/31
  evpn multisite fabric-tracking
  no shutdown

interface Ethernet1/51
  description DCI carrier {carrier} to {remote_bgw}
  no switchport
  mtu 9216                         ! set to the carrier's maximum if lower
  no ip redirects
  ip address {dci_me}/31
  evpn multisite dci-tracking
  no shutdown

! ---- day-one cloud handoff (VRF TRUST) --------------------------------
interface Ethernet1/52
  description Cloud handoff: AWS DX {dx_conn} + Azure ER {er_link}
  no switchport
  mtu 9216
  no shutdown

interface Ethernet1/52.<AWS-VIF-VLAN>
  description AWS Direct Connect private VIF ({dx_conn})
  encapsulation dot1q <AWS-VIF-VLAN>    ! VLAN set on the VIF / by the hosted provider
  mtu 1500                              ! 9001 if the VIF is created with jumbo frames
  vrf member {TRUST['name']}
  no ip redirects
  ip address {aws_me}/30
  no shutdown

interface Ethernet1/52.<ER-VLAN>
  description Azure ExpressRoute private peering ({er_link} link)
  encapsulation dot1q <ER-VLAN>         ! VLAN ID configured on the ER private peering
  mtu 1500                              ! ExpressRoute MTU is 1500
  vrf member {TRUST['name']}
  no ip redirects
  ip address {az_me}/30
  no shutdown

vrf context {TRUST['name']}
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
  neighbor {s1}
    remote-as {spine_asn}
    description {host(site, 'NXSP-01')} underlay
    bfd
    address-family ipv4 unicast
      route-map RM-FABRIC-UL-OUT out
  neighbor {s2}
    remote-as {spine_asn}
    description {host(site, 'NXSP-02')} underlay
    bfd
    address-family ipv4 unicast
      route-map RM-FABRIC-UL-OUT out
  neighbor 10.{o}.240.1
    remote-as {spine_asn}
    description {host(site, 'NXSP-01')} EVPN
    update-source loopback0
    ebgp-multihop 2
    address-family l2vpn evpn
      send-community
      send-community extended
  neighbor 10.{o}.240.2
    remote-as {spine_asn}
    description {host(site, 'NXSP-02')} EVPN
    update-source loopback0
    ebgp-multihop 2
    address-family l2vpn evpn
      send-community
      send-community extended
  ! DCI underlay (carrier {carrier})
  neighbor {dci_peer}
    remote-as {dev_asn(peer, me[1])}
    description {remote_bgw} underlay
    bfd
    address-family ipv4 unicast
      route-map RM-DCI-UL-IN in
      route-map RM-DCI-UL-OUT out
  ! DCI overlay to both remote BGWs
  neighbor 10.{po}.240.21
    remote-as {dev_asn(peer, 'NXBGW-01')}
    description {host(peer, 'NXBGW-01')} EVPN
    update-source loopback0
    ebgp-multihop 5
    peer-type fabric-external
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map RM-DCI-EVPN-IN in
      route-map RM-DCI-EVPN-OUT out
  neighbor 10.{po}.240.22
    remote-as {dev_asn(peer, 'NXBGW-02')}
    description {host(peer, 'NXBGW-02')} EVPN
    update-source loopback0
    ebgp-multihop 5
    peer-type fabric-external
    address-family l2vpn evpn
      send-community
      send-community extended
      route-map RM-DCI-EVPN-IN in
      route-map RM-DCI-EVPN-OUT out
  ! cloud peerings: learned prefixes become type-5 routes in the local fabric and, through
  ! RM-DCI-EVPN-OUT, at the other site (which prefers its own cloud links: shorter AS path)
  vrf {TRUST['name']}
    address-family ipv4 unicast
      aggregate-address 10.{o}.0.0/16
      aggregate-address 10.{po}.0.0/16
      maximum-paths 4
    neighbor {aws_peer}
      remote-as {AWS_ASN}
      description AWS Direct Connect private VIF ({dx_conn})
      password <BGP MD5 key from Secret Server>
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
""".strip("\n")


def mgmt_cfg(site, idx):
    o = SITES[site]["o"]
    return f"""
! ---- out-of-band management (10.{o}.245.0/24, gateway on the firewall) ---
vrf context management
  ip route 0.0.0.0/0 10.{o}.245.1
interface mgmt0
  vrf member management
  ip address 10.{o}.245.{DEVICES[idx][5]}/24
""".strip("\n")


def header(site, idx):
    role, suf = DEVICES[idx][0], DEVICES[idx][1]
    return f"""
!==============================================================================
! {host(site, suf)} · {role} · BGP AS {dev_asn(site, suf)}
! {DATA['doc']['config_title']}
! {DATA['doc']['classification']}
! Template: validate against the exact Nexus model and NX-OS release before use.
! Fill in every <placeholder>. Host-gateway SVIs ship shut (migration step M4).
! Not included: AAA/TACACS, NTP, SNMP, syslog, banners, users. {DATA['doc']['baseline_note']}
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
        if suf in ("NXLF-03", "NXLF-04"):
            body += "\n\n" + cfg_border_extra(site, idx)
    lines = body.split("\n")
    return "\n".join([header(site, idx), "", lines[0], "", mgmt_cfg(site, idx)] + lines[1:]) + "\n"


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


def site_svg(site, x0):
    S = SITES[site]
    o = S["o"]
    parts = []
    W = 660
    parts.append(f'<rect x="{x0}" y="50" width="{W}" height="715" rx="14" class="panel"/>')
    parts.append(f'<text x="{x0 + 18}" y="78" class="pt">{site} · {esc(S["city"])} ({esc(S["facility"])})</text>')
    parts.append(f'<text x="{x0 + 18}" y="96" class="ps">10.{o}.0.0/16 · AS {S["asn"]} · Multi-Site ID {S["site_id"]}</text>')
    # firewalls
    fw = [(x0 + 200, 115), (x0 + 370, 115)]
    for i, (x, y) in enumerate(fw):
        parts.append(node(x, y, 140, 52, S["fws"][i], ["Palo Alto HA A/P", f"eBGP AS {ASN_PLAN[site]['fw']}"], "fw"))
    parts.append(f'<line x1="{x0 + 340}" y1="141" x2="{x0 + 370}" y2="141" class="ha"/>')
    # spines
    spx = [x0 + 120, x0 + 390]
    for i, x in enumerate(spx):
        parts.append(node(x, 235, 150, 56, host(site, f"NXSP-0{i + 1}"), [f"Nexus 9500 · AS {ASN_PLAN[site]['spine']}", f"Lo0 10.{o}.240.{i + 1}"], "spine"))
    # leafs
    lx = [x0 + 15, x0 + 178, x0 + 341, x0 + 504]
    for i, x in enumerate(lx):
        parts.append(node(x, 415, 141, 70, host(site, f"NXLF-0{i + 1}"),
                          [("Border-service leaf" if i >= 2 else "Nexus 9300 leaf"), f"Lo0 10.{o}.240.{11 + i}", f"Lo1 10.{o}.241.{11 + i}"], "leaf"))
    for pi, (a, b) in enumerate([(0, 1), (2, 3)]):
        cx = (lx[a] + lx[b] + 141) / 2
        parts.append(f'<text x="{cx}" y="506" class="ann">vPC {S["vpc"][pi]} · VTEP VIP 10.{o}.241.{101 + pi}</text>')
    # BGWs near the DCI
    left = site == A()
    bx = x0 + W - 175 if left else x0 + 15
    by = [590, 668]
    for i, y in enumerate(by):
        parts.append(node(bx, y, 160, 56, host(site, f"NXBGW-0{i + 1}"), ["Multi-Site BGW", f"Lo0 10.{o}.240.{21 + i}"], "bgw"))
    vx = bx + 80
    parts.append(f'<text x="{vx}" y="744" class="ann">Multi-Site VIP 10.{o}.241.200</text>')
    # day-one cloud on the BGWs (VRF TRUST)
    cx0 = x0 + 250
    clouds = [("AWS Direct Connect", f"private VIF · 10.{o}.244.0/28", 597), ("Azure ExpressRoute", f"private peering · 10.{o}.244.16/29", 675)]
    for title, sub, y in clouds:
        parts.append(node(cx0, y, 170, 44, title, [sub], "cloud"))
        cx_edge = cx0 + 170 if left else cx0
        b_edge = bx if left else bx + 160
        for byy in by:
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
        for x in (lx[2], lx[3]):
            parts.append(f'<line x1="{fx + 70}" y1="167" x2="{x + 70}" y2="415" class="fwl"/>')
    e1, e2 = (pt.replace("ethernet", "e") for pt in fw_ports())
    parts.append(f'<text x="{x0 + W - 20}" y="205" class="ann end">{e1}→LF-03 · {e2}→LF-04 · 10.{o}.244.64/28 · eBGP</text>')
    # internet
    parts.append(f'<text x="{x0 + 340}" y="40" class="ann">Internet / ISPs / IPsec mesh (unchanged)</text>')
    parts.append(f'<line x1="{x0 + 270}" y1="46" x2="{x0 + 270}" y2="115" class="fwl"/>')
    parts.append(f'<line x1="{x0 + 440}" y1="46" x2="{x0 + 440}" y2="115" class="fwl"/>')
    return "".join(parts), bx, by


def topology_svg():
    lvd, lbx, lby = site_svg(A(), 20)
    sac, sbx, sby = site_svg(B(), 720)
    dci = []
    for i in range(2):
        y = lby[i] + 28
        dci.append(f'<line x1="{lbx + 160}" y1="{y}" x2="{sbx}" y2="{y}" class="dci"/>')
    dci.append('<text x="700" y="660" class="ann">L3 DCI</text>')
    dci.append(f'<text x="700" y="{lby[0] + 22}" class="ann small">A</text>')
    dci.append(f'<text x="700" y="{lby[1] + 22}" class="ann small">B</text>')
    dci.append('<text x="700" y="790" class="ann">eBGP between BGWs: IPv4 (BGW loopbacks) + L2VPN EVPN (VRF TRUST type-5: site /16 + approved cloud prefixes)</text>')
    legend = ('<g class="legend">'
              '<line x1="40" y1="815" x2="80" y2="815" class="ul"/><text x="88" y="819">eBGP underlay /31 + MP-BGP EVPN (eBGP, loopbacks)</text>'
              '<line x1="360" y1="815" x2="400" y2="815" class="fwl"/><text x="408" y="819">Firewall handoff (routed /29, eBGP)</text>'
              '<line x1="700" y1="815" x2="740" y2="815" class="dci"/><text x="748" y="819">DCI (eBGP)</text>'
              '<line x1="880" y1="815" x2="920" y2="815" class="ha"/><text x="928" y="819">HA link</text>'
              '<line x1="1020" y1="815" x2="1060" y2="815" class="cl"/><text x="1068" y="819">AWS / Azure (eBGP)</text></g>')
    return (f'<svg viewBox="0 0 1400 835" role="img" aria-label="{A()} and {B()} EVPN Multi-Site topology" class="topo">'
            f'{lvd}{sac}{"".join(dci)}{legend}</svg>')


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

    dci_rows = [
        ["Carrier A", host(a, "NXBGW-01") + " Eth1/51 " + mono(f"10.{oa}.246.0/31"),
         host(b, "NXBGW-01") + " Eth1/51 " + mono(f"10.{oa}.246.1/31"), f"{a} owns the addressing"],
        ["Carrier B", host(b, "NXBGW-02") + " Eth1/51 " + mono(f"10.{ob}.246.0/31"),
         host(a, "NXBGW-02") + " Eth1/51 " + mono(f"10.{ob}.246.1/31"), f"{b} owns the addressing"],
    ]
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
    ms_rows = [
        ["Multi-Site site ID", str(SITES[a]["site_id"]), str(SITES[b]["site_id"])],
        ["BGW Multi-Site VIP (loopback100)", mono(f"10.{oa}.241.{BGW_VIP}/32"), mono(f"10.{ob}.241.{BGW_VIP}/32")],
        ["BGW Lo0", mono(f"10.{oa}.240.21/.22"), mono(f"10.{ob}.240.21/.22")],
        ["DCI underlay", f"eBGP to {b} over carrier A (BGW-01) and B (BGW-02)", f"eBGP to {a} over carrier A (BGW-01) and B (BGW-02)"],
        ["DCI overlay", f"eBGP EVPN multihop, Lo0 to both {b} BGWs, peer-type fabric-external", f"Same, toward the {a} BGWs"],
        ["Advertised over DCI", f"Type-5 routes in 10.{oa}.0.0/16, AWS/Azure prefixes learned at {a}, BGW loopbacks",
         f"Type-5 routes in 10.{ob}.0.0/16, AWS/Azure prefixes learned at {b}, BGW loopbacks"],
        ["Never advertised over DCI", "0.0.0.0/0, prefixes outside the site /16 and cloud allowlists, L2VNIs", "Same"],
    ]
    allow = table(["Allowlist", "Prefixes (each le /24)"], [
        ["PL-CLOUD-AWS", ", ".join(mono(n) for n in CLOUD_AWS)],
        ["PL-CLOUD-AZURE", ", ".join(mono(n) for n in CLOUD_AZURE)],
    ])
    sec.append(("multisite", "8. Multi-Site, DCI and cloud",
                "\n" + table(["Item", a, b], ms_rows) + "\n" + ms["body"] + "\n" + allow + "\n" + ms["allowlist_note"] + "\n"))

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
                table(["Step", "What", "Detail", "Risk"], d["migration"])))
    sec.append(("tests", "11. Failure test matrix", table(["Failure", "Expected result", "Evidence"], d["tests"])))
    sec.append(("open", "12. Open items before implementation", table(["Item", "What is needed"], d["open_items"])))

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
        print(f"fabric_design: cannot load {args.data}: {exc!r}", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    page = args.out / DATA["doc"].get("output_html", "design.html")
    page.write_text(build(), encoding="utf-8")
    print("wrote", page)
    files = write_configs(args.out / "configs")
    print("wrote", len(files), "files to", args.out / "configs")
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
