"""Cross-device consistency checks on the generated demo fabric: addressing, VNIs and route
targets, vPC pairs, Multi-Site BGWs, policy references and the firewall handoff.

    python3 -m unittest discover -s tests -t .
"""

import collections
import ipaddress
import json
import re
import tempfile
import unittest
from pathlib import Path

from fabric_design import build
from tests.nxos import Config, ifname_short

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demo-fabric.json"


class FabricConsistencyTest(unittest.TestCase):
    """Runs against the demo data as committed (full-mesh DCI)."""

    dci_mode = None     # None: as in the demo file; subclasses override

    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(DEMO.read_text())
        if cls.dci_mode:
            cls.data["dci"] = {"mode": cls.dci_mode}
        cls.tmp = tempfile.TemporaryDirectory()
        out = Path(cls.tmp.name)
        src = out / "input.json"
        src.write_text(json.dumps(cls.data))
        build.main([str(src), "--out", str(out)])
        cls.cfg = {f.stem: Config(f.stem, f.read_text()) for f in sorted((out / "configs").glob("*.cfg"))}
        cls.panos = {f.name.split("-FW")[0]: f.read_text() for f in (out / "configs").glob("*.panos.txt")}
        cls.sites = {s["code"]: s for s in cls.data["sites"]}
        cls.fmt = cls.data["hostname_format"]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # -- helpers --------------------------------------------------------------
    def dev(self, site, role):
        return self.cfg[self.fmt.format(site=site, role=role)]

    def role_devs(self, prefix, site=None):
        sites = [site] if site else list(self.sites)
        return [self.dev(s, r) for s in sites for r in self.roles() if r.startswith(prefix)]

    @staticmethod
    def roles():
        return [d[1] for d in build.DEVICES]

    def vteps(self, site=None):
        return self.role_devs("NXLF", site) + self.role_devs("NXBGW", site)

    @staticmethod
    def is_dci(c, ifname):
        node = c.interfaces.get(ifname)
        return node is not None and node.find("evpn multisite dci-tracking") != []

    def dci_links(self):
        """[(carrier, (bgw, ifname, ip_interface), (bgw, ifname, ip_interface))], read from the configs."""
        ends = collections.defaultdict(list)
        for c in self.role_devs("NXBGW"):
            for ifname, node in c.interfaces.items():
                if self.is_dci(c, ifname):
                    m = re.fullmatch(r"DCI carrier (\S+) to (\S+)", node.values("description")[0])
                    addr = ipaddress.ip_interface(node.values("ip address")[0])
                    ends[addr.network].append((m.group(1), m.group(2), c.name, ifname, addr))
        links = []
        for net, e in sorted(ends.items(), key=lambda kv: int(kv[0].network_address)):
            self.assertEqual(len(e), 2, f"DCI {net} has {len(e)} ends")
            (ca, fa, na, ia, aa), (cb, fb, nb, ib, ab) = e
            self.assertEqual(ca, cb, f"DCI {net}: carrier {ca} vs {cb}")
            self.assertEqual((fa, fb), (nb, na), f"DCI {net}: descriptions do not name each other")
            links.append((ca, (na, ia, aa), (nb, ib, ab)))
        return links

    def vpc_pairs(self):
        for site in self.sites:
            for a, b in (("NXLF-01", "NXLF-02"), ("NXLF-03", "NXLF-04")):
                yield site, self.dev(site, a), self.dev(site, b)

    # -- addressing -----------------------------------------------------------
    def test_every_address_is_unique_except_known_anycast(self):
        owners = collections.defaultdict(set)
        for c in self.cfg.values():
            for ifname, addr, _, vrf in c.addresses():
                if ifname == "mgmt0" and addr.ip == addr.network.network_address:
                    continue
                owners[(vrf if vrf == "KEEPALIVE" else "", str(addr.ip))].add(c.name)
        for (_, ip), devs in owners.items():
            if len(devs) == 1:
                continue
            last = int(ip.split(".")[3])
            third = int(ip.split(".")[2])
            sites = {d.split("-")[0] for d in devs}
            self.assertEqual(len(sites), 1, f"{ip} shared across sites: {sorted(devs)}")
            if third < 240 and last == 1:
                # anycast gateway: every leaf in the site
                self.assertEqual(devs, {c.name for c in self.role_devs("NXLF", sites.pop())}, ip)
            elif third == 241 and last == build.BGW_VIP:
                self.assertEqual(devs, {c.name for c in self.role_devs("NXBGW", sites.pop())}, ip)
            elif third == 241:
                # vPC anycast VTEP: exactly one vPC pair
                pairs = [{a.name, b.name} for _, a, b in self.vpc_pairs()]
                self.assertIn(devs, pairs, ip)
            else:
                self.fail(f"{ip} configured on {sorted(devs)}")

    def test_no_two_different_subnets_overlap(self):
        nets = collections.defaultdict(set)
        for c in self.cfg.values():
            for ifname, addr, _, vrf in c.addresses():
                if addr.network.prefixlen < 32:
                    nets[addr.network].add(f"{c.name} {ifname}")
        seen = sorted(nets, key=lambda n: (int(n.network_address), n.prefixlen))
        for i, a in enumerate(seen):
            for b in seen[i + 1:]:
                if a != b and a.overlaps(b):
                    self.fail(f"{a} ({sorted(nets[a])}) overlaps {b} ({sorted(nets[b])})")

    def test_addresses_stay_inside_the_site_block(self):
        dci = {f"10.{s['octet']}.246.0/24" for s in self.sites.values()}
        for site, s in self.sites.items():
            block = ipaddress.ip_network(f"10.{s['octet']}.0.0/16")
            for c in self.cfg.values():
                if not c.name.startswith(site + "-"):
                    continue
                for ifname, addr, _, _ in c.addresses():
                    if addr.ip in block:
                        continue
                    in_dci = any(addr.ip in ipaddress.ip_network(n) for n in dci)
                    self.assertTrue(in_dci and self.is_dci(c, ifname), f"{c.name} {ifname} {addr}")

    def test_infrastructure_stays_inside_the_infra_block(self):
        """Only host and legacy-core SVIs (and the other site's DCI /31) sit outside 10.x.240.0/21."""
        legacy = self.data["legacy"]["vlan"]
        for site, s in self.sites.items():
            infra = ipaddress.ip_network(f"10.{s['octet']}.240.0/21")
            host_svis = {f"Vlan{v}" for v, _ in s["host_vlans"]}
            for c in self.cfg.values():
                if not c.name.startswith(site + "-"):
                    continue
                for ifname, addr, _, _ in c.addresses():
                    if ifname in host_svis or ifname == f"Vlan{legacy}":
                        self.assertNotIn(addr.ip, infra, f"{c.name} {ifname} {addr} collides with infra")
                    elif not (self.is_dci(c, ifname) and addr.ip not in ipaddress.ip_network(f"10.{s['octet']}.0.0/16")):
                        self.assertIn(addr.ip, infra, f"{c.name} {ifname} {addr}")

    def test_underlay_links_agree_on_both_ends(self):
        """Descriptions name the far end and its port, the far port has the other /31 address, MTUs match."""
        checked = 0
        for c in self.cfg.values():
            for ifname, node in c.interfaces.items():
                if not re.fullmatch(r"Ethernet1/\d+", ifname):
                    continue
                desc = (node.values("description") or [""])[0]
                m = re.fullmatch(r"(\S+) (Eth\d+/\d+)", desc)
                if not m or m.group(1) not in self.cfg:
                    continue
                far = self.cfg[m.group(1)]
                far_if = far.interfaces.get(ifname_short(m.group(2)))
                self.assertIsNotNone(far_if, f"{c.name} {ifname}: {desc} does not exist")
                far_desc = (far_if.values("description") or [""])[0]
                self.assertEqual(far_desc, f"{c.name} Eth{ifname[8:]}", f"{far.name} {ifname_short(m.group(2))}")
                mine = ipaddress.ip_interface(node.values("ip address")[0].split()[0])
                theirs = ipaddress.ip_interface(far_if.values("ip address")[0].split()[0])
                self.assertEqual(mine.network, theirs.network, f"{c.name} {ifname}")
                self.assertEqual(mine.network.prefixlen, 31)
                self.assertNotEqual(mine.ip, theirs.ip)
                self.assertEqual(node.values("mtu"), far_if.values("mtu"), f"{c.name} {ifname}")
                checked += 1
        self.assertEqual(checked, 2 * 2 * 2 * 6)  # 2 sites x 2 spines x 6 downstream, both ends

    def test_dci_links_join_bgws_of_different_sites(self):
        links = self.dci_links()
        expect = {"pair": 2, "full-mesh": 4}[build.DCI_MODE]
        self.assertEqual(len(links), expect)
        owners = {f"10.{s['octet']}.246.0/24": code for code, s in self.sites.items()}
        for carrier, (na, ia, aa), (nb, ib, ab) in links:
            self.assertNotEqual(na.split("-")[0], nb.split("-")[0], f"{na}-{nb}")
            self.assertEqual(aa.network.prefixlen, 31)
            self.assertNotEqual(aa.ip, ab.ip)
            # carrier A is addressed from the first site's /16, carrier B from the second's
            owner = next(code for blk, code in owners.items() if aa.ip in ipaddress.ip_network(blk))
            self.assertEqual(owner, build.SITE_ORDER["AB".index(carrier)], f"{na}-{nb}")
            for me, far, far_ip in ((na, nb, ab.ip), (nb, na, aa.ip)):
                n = [x for vrf, ip, x in self.cfg[me].neighbors() if ip == str(far_ip)]
                self.assertEqual(len(n), 1, f"{me} has no DCI underlay session to {far}")
                self.assertEqual(n[0].values("remote-as"), [str(self.cfg[far].asn)])
                self.assertTrue(n[0].find("bfd"))
                rms = {(rm, d) for nbr, rm, d in self.cfg[me].neighbor_route_maps() if nbr == str(far_ip)}
                self.assertEqual(rms, {("RM-DCI-UL-IN", "in"), ("RM-DCI-UL-OUT", "out")}, me)

    def test_full_mesh_gives_every_bgw_one_circuit_per_carrier(self):
        if build.DCI_MODE != "full-mesh":
            self.skipTest("pair mode")
        per_bgw = collections.defaultdict(list)
        pairs = set()
        for carrier, (na, ia, _), (nb, ib, _) in self.dci_links():
            per_bgw[na].append((carrier, nb, ia))
            per_bgw[nb].append((carrier, na, ib))
            pairs.add(frozenset((na, nb)))
        self.assertEqual(len(pairs), 4, "every BGW pair across the sites is joined once")
        for bgw, links in per_bgw.items():
            self.assertEqual(sorted(c for c, _, _ in links), ["A", "B"], bgw)
            self.assertEqual(len({far for _, far, _ in links}), 2, f"{bgw}: both circuits go to the same BGW")
            self.assertEqual(len({i for _, _, i in links}), 2, f"{bgw}: both circuits on one port")

    def test_single_failure_isolates_no_surviving_bgw(self):
        """Fail each carrier, each circuit and each BGW in turn; every BGW left in service must keep a DCI
        circuit to a BGW that is also in service. Pair mode is expected to fail this (a carrier or BGW loss
        cuts its partner off), full mesh to pass it."""
        links = self.dci_links()
        bgws = [c.name for c in self.role_devs("NXBGW")]
        failures = [("carrier", c) for c in "AB"] + [("circuit", i) for i in range(len(links))] + [("bgw", b) for b in bgws]
        isolated = []
        for kind, what in failures:
            down_bgw = {what} if kind == "bgw" else set()
            up = [l for i, l in enumerate(links)
                  if not (kind == "carrier" and l[0] == what) and not (kind == "circuit" and i == what)
                  and l[1][0] not in down_bgw and l[2][0] not in down_bgw]
            for b in bgws:
                if b in down_bgw:
                    continue
                if not any(b in (l[1][0], l[2][0]) for l in up):
                    isolated.append(f"{kind} {what} isolates {b}")
        if build.DCI_MODE == "full-mesh":
            self.assertEqual(isolated, [])
        else:
            self.assertNotEqual(isolated, [], "pair mode was expected to have single points of isolation")

    def test_bgp_network_statements_are_local_addresses(self):
        for c in self.cfg.values():
            for af in c.bgp.find("address-family ipv4 unicast"):
                for v in af.values("network"):
                    ip = v.split("/")[0]
                    self.assertTrue(c.owns(ip), f"{c.name}: network {v} is not configured locally")

    def test_router_id_is_loopback0(self):
        for c in self.cfg.values():
            self.assertEqual(c.bgp.values("router-id"), [str(c.loopback(0))], c.name)

    def test_asns_are_unique_per_device(self):
        by_asn = collections.defaultdict(set)
        for c in self.cfg.values():
            role = c.name.split("-", 1)[1]
            by_asn[c.asn].add((c.name.split("-")[0], "spine" if role.startswith("NXSP") else c.name))
        for asn, owners in by_asn.items():
            self.assertEqual(len(owners), 1, f"AS {asn} used by {sorted(owners)}")

    # -- VNIs and route targets ---------------------------------------------
    def test_l3vni_is_consistent_on_every_vtep(self):
        vni, vlan, rt = build.TRUST["l3vni"], build.TRUST["vlan"], build.TRUST["rt"]
        for c in self.vteps():
            vrf = c.vrfs()[build.TRUST["name"]]
            self.assertEqual(vrf["vni"], vni, c.name)
            self.assertEqual(vrf["rts"], {("both", rt, False), ("both", rt, True)}, c.name)
            self.assertEqual(c.vlan_segments().get(vlan), vni, c.name)
            self.assertIn(f"Vlan{vlan}", c.interfaces, c.name)
            _, _, l3 = c.nve()
            self.assertEqual(l3, {vni}, c.name)

    def test_l2vnis_match_vlans_evpn_and_nve(self):
        for site, s in self.sites.items():
            expect = {v: s["vni_base"] + v for v, _ in s["host_vlans"]}
            for c in self.role_devs("NXLF", site):
                segs = {v: n for v, n in c.vlan_segments().items() if n and n != build.TRUST["l3vni"]}
                self.assertEqual(segs, expect, c.name)
                evpn = c.evpn_l2vnis()
                self.assertEqual(set(evpn), set(expect.values()), c.name)
                for vni, rts in evpn.items():
                    self.assertEqual(rts["import"], rts["export"], f"{c.name} vni {vni}")
                    self.assertEqual(rts["import"], {f"{s['rt_admin']}:{vni}"}, f"{c.name} vni {vni}")
                _, l2, _ = c.nve()
                self.assertEqual(l2, set(expect.values()), c.name)

    def test_vnis_do_not_collide(self):
        l3 = build.TRUST["l3vni"]
        seen = {}
        for site, s in self.sites.items():
            for v, _ in s["host_vlans"]:
                vni = s["vni_base"] + v
                self.assertNotEqual(vni, l3, f"{site} VLAN {v}")
                self.assertNotIn(vni, seen, f"{site} VLAN {v} reuses VNI {vni} from {seen.get(vni)}")
                seen[vni] = f"{site} VLAN {v}"
                self.assertLessEqual(vni, 16777215)

    def test_bgws_carry_no_l2vnis(self):
        for c in self.role_devs("NXBGW"):
            _, l2, _ = c.nve()
            self.assertEqual(l2, set(), c.name)

    # -- vPC ------------------------------------------------------------------
    def test_vpc_pairs_mirror_each_other(self):
        for site, a, b in self.vpc_pairs():
            da, db = a.top("vpc domain")[0], b.top("vpc domain")[0]
            self.assertEqual(da.line, db.line, f"{a.name}/{b.name} domain")
            self.assertNotEqual(da.values("role priority"), db.values("role priority"))
            ka_a = da.values("peer-keepalive")[0].split()
            ka_b = db.values("peer-keepalive")[0].split()
            # destination X source Y vrf KEEPALIVE
            self.assertEqual((ka_a[1], ka_a[3]), (ka_b[3], ka_b[1]), f"{a.name}/{b.name} keepalive")
            self.assertTrue(a.owns(ka_a[3]) and b.owns(ka_b[3]))
            for knob in ("peer-switch", "peer-gateway", "ip arp synchronize"):
                self.assertTrue(da.find(knob) and db.find(knob), f"{a.name}/{b.name} {knob}")
            self.assertNotEqual(a.loopback(1), b.loopback(1))
            sec_a = {str(x.ip) for i, x, s, _ in a.addresses() if i == "loopback1" and s}
            sec_b = {str(x.ip) for i, x, s, _ in b.addresses() if i == "loopback1" and s}
            self.assertEqual(sec_a, sec_b, f"{a.name}/{b.name} anycast VTEP")
            self.assertEqual(len(sec_a), 1)

    def test_vpc_pairs_share_vlans_and_gateways(self):
        for site, a, b in self.vpc_pairs():
            local = {int(n.line.split()[1]) for c in (a, b) for n in c.top("vlan")
                     if n.values("name") and n.values("name")[0].startswith("FW-TRANSIT")}
            va = {k: v for k, v in a.vlan_segments().items() if k not in local}
            vb = {k: v for k, v in b.vlan_segments().items() if k not in local}
            self.assertEqual(va, vb, f"{a.name}/{b.name}")
            for v in va:
                if v in (3900,):
                    continue
                ia, ib = a.interfaces.get(f"Vlan{v}"), b.interfaces.get(f"Vlan{v}")
                if ia is None and ib is None:
                    continue
                skip = ("description", "ip address")
                ca = [x.line for x in ia.children if not x.line.startswith(skip)]
                cb = [x.line for x in ib.children if not x.line.startswith(skip)]
                self.assertEqual(ca, cb, f"{a.name}/{b.name} Vlan{v}")
                if "fabric forwarding mode anycast-gateway" in ca:
                    self.assertEqual(ia.values("ip address"), ib.values("ip address"), f"Vlan{v}")
            self.assertEqual(a.top("fabric forwarding anycast-gateway-mac")[0].line,
                             b.top("fabric forwarding anycast-gateway-mac")[0].line)

    def test_vpc_backup_underlay_peers_with_the_mate(self):
        for site, a, b in self.vpc_pairs():
            for me, mate in ((a, b), (b, a)):
                mine = ipaddress.ip_interface(me.interfaces["Vlan3900"].values("ip address")[0])
                theirs = ipaddress.ip_interface(mate.interfaces["Vlan3900"].values("ip address")[0])
                self.assertEqual(mine.network, theirs.network)
                n = [x for _, ip, x in me.neighbors() if ip == str(theirs.ip)]
                self.assertEqual(len(n), 1, f"{me.name} has no backup-underlay session to {mate.name}")
                self.assertEqual(n[0].values("remote-as"), [str(mate.asn)])
            self.assertIn("system nve infra-vlans 3900", [x.line for x in a.root.children])

    def test_firewall_transit_vlan_is_kept_off_the_peer_link(self):
        for c in self.role_devs("NXLF"):
            fw_vlans = [int(n.line.split()[1]) for n in c.top("vlan")
                        if n.values("name") and n.values("name")[0].startswith("FW-TRANSIT")]
            pl = c.interfaces["port-channel10"]
            removed = [int(x.split()[-1]) for x in pl.values("switchport trunk allowed vlan remove")]
            self.assertEqual(sorted(fw_vlans), sorted(removed), c.name)

    # -- Multi-Site -----------------------------------------------------------
    def test_bgws_share_site_id_and_vip_per_site(self):
        ids = {}
        for site, s in self.sites.items():
            bgws = self.role_devs("NXBGW", site)
            sid = {c.top("evpn multisite border-gateway")[0].line.split()[-1] for c in bgws}
            vip = {str(c.loopback(100)) for c in bgws}
            self.assertEqual(sid, {str(s["site_id"])}, site)
            self.assertEqual(len(vip), 1, site)
            ids[site] = sid.pop()
            for c in bgws:
                nve, _, _ = c.nve()
                self.assertIn("multisite border-gateway interface loopback100", [x.line for x in nve.children])
                for spine_if in ("Ethernet1/49", "Ethernet1/50"):
                    self.assertIn("evpn multisite fabric-tracking",
                                  [x.line for x in c.interfaces[spine_if].children], c.name)
        self.assertEqual(len(set(ids.values())), len(ids), "Multi-Site site IDs must differ per site")

    def test_dci_overlay_is_fabric_external_to_every_remote_bgw(self):
        for site in self.sites:
            other = next(s for s in self.sites if s != site)
            remote = {str(c.loopback(0)): c for c in self.role_devs("NXBGW", other)}
            for c in self.role_devs("NXBGW", site):
                ext = {ip: n for _, ip, n in c.neighbors() if n.find("peer-type")}
                self.assertEqual(set(ext), set(remote), c.name)
                for ip, n in ext.items():
                    self.assertEqual(n.values("peer-type"), ["fabric-external"])
                    self.assertEqual(n.values("update-source"), ["loopback0"])
                    self.assertEqual(n.values("remote-as"), [str(remote[ip].asn)])

    def test_dci_underlay_only_carries_bgw_loopbacks(self):
        for c in self.role_devs("NXBGW"):
            pl = c.prefix_lists()
            site = c.name.split("-")[0]
            own = {str(x.loopback(n)) + "/32" for x in self.role_devs("NXBGW", site) for n in (0, 1)}
            own.add(str(c.loopback(100)) + "/32")
            listed = {line.split()[-1] for line in pl["PL-BGW-LOCAL"]}
            self.assertEqual(listed, own, c.name)
            other = next(s for s in self.sites if s != site)
            remote = {str(x.loopback(n)) + "/32" for x in self.role_devs("NXBGW", other) for n in (0, 1, 100)}
            self.assertEqual({line.split()[-1] for line in pl["PL-BGW-REMOTE"]}, remote, c.name)

    def test_default_route_never_crosses_the_dci(self):
        for c in self.role_devs("NXBGW"):
            for name, lines in c.prefix_lists().items():
                for line in lines:
                    self.assertNotIn(" 0.0.0.0/0", line, f"{c.name} {name}")

    # -- policy references ----------------------------------------------------
    def test_route_maps_and_lists_are_defined_where_used(self):
        for c in self.cfg.values():
            pls, rms, aspl = c.prefix_lists(), c.route_maps(), c.as_path_lists()
            for rm, kind, name in c.route_map_matches():
                if kind == "prefix-list":
                    self.assertIn(name, pls, f"{c.name} route-map {rm} uses undefined prefix-list {name}")
                else:
                    self.assertIn(name, aspl, f"{c.name} route-map {rm} uses undefined as-path list {name}")
            for nbr, rm, d in c.neighbor_route_maps():
                self.assertIn(d, ("in", "out"))
                self.assertIn(rm, rms, f"{c.name} neighbor {nbr} uses undefined route-map {rm}")
            for vrf in c.bgp.find("vrf"):
                for af in vrf.find("address-family"):
                    for v in af.values("redistribute"):
                        self.assertIn(v.split()[-1], rms, f"{c.name} {v}")
            # every prefix-list line is well formed
            for name, lines in pls.items():
                seqs = [int(l.split()[4]) for l in lines]
                self.assertEqual(len(seqs), len(set(seqs)), f"{c.name} {name} duplicate seq")
                for l in lines:
                    ipaddress.ip_network(l.split()[6])

    def test_prefix_lists_are_identical_across_devices(self):
        """A prefix-list of the same name must say the same thing on every switch of a site."""
        for site in self.sites:
            seen = {}
            for c in self.cfg.values():
                if not c.name.startswith(site + "-"):
                    continue
                for name, lines in c.prefix_lists().items():
                    if name in ("PL-BGW-LOCAL", "PL-BGW-REMOTE"):
                        continue
                    if name in seen:
                        self.assertEqual(lines, seen[name][1], f"{name}: {c.name} vs {seen[name][0]}")
                    else:
                        seen[name] = (c.name, lines)

    def test_every_ebgp_multihop_session_uses_a_loopback(self):
        for c in self.cfg.values():
            for vrf, ip, n in c.neighbors():
                if n.find("ebgp-multihop"):
                    self.assertEqual(n.values("update-source"), ["loopback0"], f"{c.name} {ip}")
                elif vrf == "default":
                    self.assertTrue(n.find("bfd"), f"{c.name} {ip}: single-hop session without BFD")

    def test_evpn_sessions_send_extended_communities(self):
        for c in self.cfg.values():
            for _, ip, n in c.neighbors():
                for af in n.find("address-family l2vpn evpn"):
                    lines = [x.line for x in af.children]
                    self.assertIn("send-community extended", lines, f"{c.name} {ip}")

    # -- firewall handoff -----------------------------------------------------
    def test_panos_handoff_matches_the_border_leafs(self):
        for site, text in self.panos.items():
            fw_as = re.search(r"protocol bgp local-as (\d+)", text).group(1)
            peers = re.findall(r"peer (\S+) enable yes peer-as (\d+) local-address interface (\S+) ip (\S+) "
                               r"peer-address ip (\S+)", text)
            self.assertEqual(len(peers), 2, site)
            for name, peer_as, port, fw_ip, leaf_ip in peers:
                leaf = self.cfg[name]
                self.assertEqual(int(peer_as), leaf.asn, f"{site} {name}")
                self.assertTrue(leaf.owns(leaf_ip), f"{name} does not own {leaf_ip}")
                fw = ipaddress.ip_interface(fw_ip)
                leaf_addr = [a for _, a, _, _ in leaf.addresses() if str(a.ip) == leaf_ip][0]
                self.assertEqual(fw.network, leaf_addr.network, f"{site} {name}")
                n = [x for vrf, ip, x in leaf.neighbors() if ip == str(fw.ip)]
                self.assertEqual(len(n), 1, f"{name} has no session to the firewall {fw.ip}")
                self.assertEqual(n[0].values("remote-as"), [fw_as])
                fw_ports = [x.values("description")[0] for i, x in leaf.interfaces.items()
                            if i in ("Ethernet1/45", "Ethernet1/46")]
                self.assertTrue(all(d.endswith(port) for d in fw_ports), f"{name}: {fw_ports} vs {port}")
            accepted = set(re.findall(r"policy import rules SITE-PREFIXES .*match address-prefix (\S+)", text))
            self.assertEqual(accepted, {f"10.{s['octet']}.0.0/16" for s in self.sites.values()}, site)


class PairDciConsistencyTest(FabricConsistencyTest):
    """The same checks with the original one-circuit-per-BGW DCI."""

    dci_mode = "pair"


if __name__ == "__main__":
    unittest.main()
