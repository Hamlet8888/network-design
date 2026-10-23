"""Consistency checks on generated output, run against the fictional demo fabric.

    python3 -m unittest discover -s tests -t .
"""

import collections
import json
import re
import tempfile
import unittest
from pathlib import Path

from fabric_design import build

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demo-fabric.json"


class DemoFabricTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name)
        cls.assert_ok = build.main([str(DEMO), "--out", str(cls.out)])
        cls.configs = {f.stem: f.read_text() for f in sorted((cls.out / "configs").glob("*.cfg"))}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_build_succeeds_and_writes_everything(self):
        self.assertEqual(self.assert_ok, 0)
        self.assertEqual(len(self.configs), 2 * len(build.DEVICES))
        self.assertEqual(len(list((self.out / "configs").glob("*.panos.txt"))), 2)
        self.assertTrue((self.out / "demo-fabric-design.html").is_file())
        self.assertEqual(len(list((self.out / "checks").glob("*.txt"))), 2 * len(build.DEVICES))
        self.assertTrue((self.out / "checks" / "checks.json").is_file())

    def test_no_ospf_configured(self):
        for name, txt in self.configs.items():
            lines = [l for l in txt.splitlines() if "ospf" in l.lower() and not l.lstrip().startswith("!")]
            self.assertEqual(lines, [], name)

    def _owners_and_neighbors(self):
        owner, asn, nbrs = collections.defaultdict(set), {}, collections.defaultdict(list)
        for d, txt in self.configs.items():
            asn[d] = int(re.search(r"^router bgp (\d+)", txt, re.M).group(1))
            for m in re.finditer(r"^\s+ip address (\d+\.\d+\.\d+\.\d+)/\d+", txt, re.M):
                owner[m.group(1)].add(d)
            cur = None
            for line in txt.splitlines():
                m = re.match(r"^\s+neighbor (\S+)$", line)
                if m:
                    cur = m.group(1)
                    continue
                m = re.match(r"^\s+remote-as (\d+)", line)
                if m and cur:
                    nbrs[d].append((cur, int(m.group(1))))
                    cur = None
        return owner, asn, nbrs

    def test_every_fabric_bgp_session_is_symmetric(self):
        data = json.loads(DEMO.read_text())
        external = {data["cloud"]["aws_asn"], data["cloud"]["azure_asn"]}
        for s in data["sites"]:
            external |= {s["asn"]["fw"], s["asn"]["core"]}
        owner, asn, nbrs = self._owners_and_neighbors()
        mine = collections.defaultdict(set)
        for ip, devs in owner.items():
            for d in devs:
                mine[d].add(ip)
        checked = 0
        for d, peers in nbrs.items():
            for ip, ras in peers:
                if ras in external:
                    continue
                checked += 1
                self.assertEqual(len(owner[ip]), 1, f"{d}: neighbor {ip} owned by {owner[ip]}")
                (p,) = owner[ip]
                self.assertEqual(asn[p], ras, f"{d}: {ip} is AS {asn[p]}, configured {ras}")
                self.assertTrue(any(r == asn[d] and i in mine[d] for i, r in nbrs[p]), f"{p} has no session back to {d}")
        self.assertGreater(checked, 100)

    def test_point_to_point_links_have_two_ends(self):
        owner, _, _ = self._owners_and_neighbors()
        links = collections.defaultdict(set)
        for ip, devs in owner.items():
            a = ip.split(".")
            if a[2] in ("242", "246"):
                links[(a[1], a[2], int(a[3]) // 2)] |= devs
        self.assertEqual(len(links), 2 * len(build.spines()) * len(build.DOWNSTREAM) + len(build.dci_links()))
        for key, devs in links.items():
            self.assertEqual(len(devs), 2, key)

    def test_dci_option_diagrams(self):
        for mode, circuits in (("pair", len(build.bgws())), ("full-mesh", 2 * len(build.bgws()))):
            svg = (self.out / "diagrams" / f"topology-{mode}.svg").read_text()
            self.assertTrue(svg.startswith('<svg xmlns="http://www.w3.org/2000/svg"'), mode)
            self.assertIn("<style>", svg)
            # DCI circuits are the dci-class lines outside the legend
            body = svg.split('<g class="legend">')[0]
            self.assertEqual(body.count('class="dci"'), circuits, mode)
            self.assertIn(f"{circuits} circuits", svg)

    def test_output_is_deterministic(self):
        with tempfile.TemporaryDirectory() as again:
            build.main([str(DEMO), "--out", again])
            for name, txt in self.configs.items():
                self.assertEqual(Path(again, "configs", f"{name}.cfg").read_text(), txt, name)


if __name__ == "__main__":
    unittest.main()
