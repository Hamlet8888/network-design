"""Site data that would generate a broken fabric is rejected before anything is written.

    python3 -m unittest discover -s tests -t .
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from fabric_design import build

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demo-fabric.json"


class ValidateTest(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(DEMO.read_text())

    def rejects(self, mutate, *fragments):
        data = copy.deepcopy(self.data)
        mutate(data)
        with self.assertRaises(ValueError) as cm:
            build.validate(data)
        for f in fragments:
            self.assertIn(f, str(cm.exception))

    def test_demo_is_valid(self):
        build.validate(self.data)

    def test_one_site(self):
        self.rejects(lambda d: d["sites"].pop(), "exactly two sites")

    def test_host_vlan_in_infra_block(self):
        self.rejects(lambda d: d["sites"][0]["host_vlans"].append([242, "X"]), "host VLAN 242", "infrastructure")

    def test_host_vlan_above_255(self):
        self.rejects(lambda d: d["sites"][0]["host_vlans"].append([300, "X"]), "host VLAN 300")

    def test_host_vlan_is_legacy_vlan(self):
        self.rejects(lambda d: d["sites"][1]["host_vlans"].append([99, "X"]), "legacy core transit VLAN")

    def test_duplicate_host_vlan(self):
        self.rejects(lambda d: d["sites"][0]["host_vlans"].append([20, "AGAIN"]), "DC1 host VLAN 20")

    def test_same_octet(self):
        self.rejects(lambda d: d["sites"][1].update(octet=110), "site octet 110")

    def test_same_site_id(self):
        self.rejects(lambda d: d["sites"][1].update(site_id=110), "site_id 110")

    def test_same_vpc_domain(self):
        self.rejects(lambda d: d["sites"][1].update(vpc_domains=[111, 122]), "vPC domain 111")

    def test_duplicate_asn(self):
        self.rejects(lambda d: d["sites"][1]["asn"].update(fw=65217), "BGP AS 65217")

    def test_asn_collides_with_cloud(self):
        self.rejects(lambda d: d["sites"][0]["asn"].update(core=64512), "BGP AS 64512")

    def test_vni_collision_between_sites(self):
        # DC2 VLAN 20 -> 120020; make DC1 produce the same VNI
        self.rejects(lambda d: d["sites"][0].update(vni_base=120000), "VNI 120010")

    def test_vni_collides_with_l3vni(self):
        self.rejects(lambda d: d["sites"][0].update(vni_base=50000), "L3VNI")

    def test_cloud_prefix_overlaps_site(self):
        self.rejects(lambda d: d["cloud"]["aws_prefixes"].append("10.120.8.0/22"), "overlaps DC2")

    def test_legacy_core_ip_outside_transit(self):
        self.rejects(lambda d: d["sites"][1].update(legacy_core_ip="10.120.98.2"), "outside 10.120.99.0/24")

    def test_legacy_core_ip_on_border_leaf_svi(self):
        self.rejects(lambda d: d["sites"][1].update(legacy_core_ip="10.120.99.11"), "border-leaf SVI")

    def test_unknown_dci_mode(self):
        self.rejects(lambda d: d.update(dci={"mode": "ring"}), "dci mode 'ring'")

    def test_dci_mode_defaults_to_pair(self):
        data = copy.deepcopy(self.data)
        data.pop("dci", None)
        build.validate(data)
        build.load(data)
        self.assertEqual(build.DCI_MODE, "pair")
        self.assertEqual(len(build.dci_links()), 2)

    def test_all_errors_reported_together(self):
        def two(d):
            d["sites"][1]["asn"]["fw"] = 65217
            d["sites"][0]["host_vlans"].append([242, "X"])
        self.rejects(two, "BGP AS 65217", "host VLAN 242")

    def test_cli_exits_2_without_writing(self):
        bad = copy.deepcopy(self.data)
        bad["sites"][1]["octet"] = 110
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp, "bad.json")
            src.write_text(json.dumps(bad))
            out = Path(tmp, "out")
            self.assertEqual(build.main([str(src), "--out", str(out)]), 2)
            self.assertFalse(out.exists())


class CommittedDemoTest(unittest.TestCase):
    """examples/demo/ must be what the current generator produces from examples/demo-fabric.json."""

    def test_examples_demo_is_current(self):
        committed = ROOT / "examples" / "demo"
        with tempfile.TemporaryDirectory() as tmp:
            build.main([str(DEMO), "--out", tmp])
            fresh = sorted(p.relative_to(tmp) for p in Path(tmp).rglob("*") if p.is_file())
            have = sorted(p.relative_to(committed) for p in committed.rglob("*") if p.is_file())
            self.assertEqual(fresh, have)
            for rel in fresh:
                self.assertEqual(Path(tmp, rel).read_text(), (committed / rel).read_text(),
                                 f"{rel} is stale: rebuild with "
                                 "python3 -m fabric_design.build examples/demo-fabric.json --out examples/demo")


if __name__ == "__main__":
    unittest.main()
