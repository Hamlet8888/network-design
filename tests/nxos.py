"""A small, forgiving reader for the NX-OS configs the generator writes.

It understands only what the tests need: indentation-based stanzas, trailing "!" comments,
interfaces, VLANs, VRFs, prefix-lists, route-maps, the NVE interface, EVPN VNIs and BGP neighbors.
"""

import ipaddress
import re


class Node:
    def __init__(self, line, depth):
        self.line, self.depth, self.children = line, depth, []

    def find(self, prefix):
        return [c for c in self.children if c.line == prefix or c.line.startswith(prefix + " ")]

    def values(self, prefix):
        """The rest of each child line that starts with prefix."""
        return [c.line[len(prefix):].strip() for c in self.find(prefix)]

    def __repr__(self):
        return f"Node({self.line!r})"


def strip_comment(line):
    i = line.find(" !")
    if i >= 0 and '"' not in line[:i]:
        line = line[:i]
    return line.rstrip()


def parse(text):
    """Parse config text into a root Node whose children are the top-level stanzas."""
    root = Node("", -1)
    stack = [root]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        line = strip_comment(raw)
        if not line.strip():
            continue
        depth = len(line) - len(line.lstrip(" "))
        while stack[-1].depth >= depth:
            stack.pop()
        node = Node(line.strip(), depth)
        stack[-1].children.append(node)
        stack.append(node)
    return root


class Config:
    """Parsed view of one generated switch config."""

    def __init__(self, name, text):
        self.name, self.text = name, text
        self.root = parse(text)
        self.interfaces = {n.line.split(None, 1)[1]: n for n in self.root.find("interface")}
        # A config may open "router bgp" more than once (the border-leaf block adds to it); merge them.
        blocks = self.root.find("router bgp")
        self.bgp = blocks[0] if blocks else None
        for extra in blocks[1:]:
            if extra.line != self.bgp.line:
                raise ValueError(f"{name}: {extra.line!r} conflicts with {self.bgp.line!r}")
            for child in extra.children:
                same = [c for c in self.bgp.children if c.line == child.line and c.line.startswith("vrf ")]
                if same:
                    same[0].children += child.children
                else:
                    self.bgp.children.append(child)
        self.asn = int(self.bgp.line.split()[2]) if self.bgp else None

    def top(self, prefix):
        return self.root.find(prefix)

    # -- addressing ---------------------------------------------------------
    def addresses(self):
        """(interface, ip_interface, secondary, vrf) for every configured IPv4 address."""
        out = []
        for ifname, node in self.interfaces.items():
            vrf = (node.values("vrf member") or ["default"])[0]
            for v in node.values("ip address"):
                parts = v.split()
                if "/" not in parts[0]:
                    continue
                out.append((ifname, ipaddress.ip_interface(parts[0]), "secondary" in parts[1:], vrf))
        return out

    def owns(self, ip):
        ip = ipaddress.ip_address(ip)
        return any(a.ip == ip for _, a, _, _ in self.addresses())

    def loopback(self, n):
        node = self.interfaces.get(f"loopback{n}")
        if not node:
            return None
        return ipaddress.ip_interface(node.values("ip address")[0].split()[0]).ip

    # -- VLANs / VNIs -------------------------------------------------------
    def vlan_segments(self):
        out = {}
        for node in self.top("vlan"):
            seg = node.values("vn-segment")
            for vid in expand(node.line.split(None, 1)[1]):
                out[vid] = int(seg[0]) if seg else None
        return out

    def vrfs(self):
        """name -> {'vni': int|None, 'rts': set of (direction, rt, evpn?)}"""
        out = {}
        for node in self.top("vrf context"):
            name = node.line.split()[2]
            vni = node.values("vni")
            rts = set()
            for af in node.find("address-family"):
                for v in af.values("route-target"):
                    p = v.split()
                    rts.add((p[0], p[1], len(p) > 2 and p[2] == "evpn"))
            out[name] = {"vni": int(vni[0]) if vni else None, "rts": rts}
        return out

    def evpn_l2vnis(self):
        """vni -> {'import': set, 'export': set}"""
        out = {}
        for evpn in self.top("evpn"):
            for v in evpn.find("vni"):
                p = v.line.split()
                if p[-1] != "l2":
                    continue
                rts = {"import": set(), "export": set()}
                for line in v.values("route-target"):
                    d, rt = line.split()[:2]
                    if d == "both":
                        rts["import"].add(rt)
                        rts["export"].add(rt)
                    else:
                        rts[d].add(rt)
                out[int(p[1])] = rts
        return out

    def nve(self):
        node = self.interfaces.get("nve1")
        l2, l3 = set(), set()
        if node:
            for v in node.values("member vni"):
                p = v.split()
                (l3 if "associate-vrf" in p else l2).add(int(p[0]))
        return node, l2, l3

    # -- policy ---------------------------------------------------------------
    def prefix_lists(self):
        out = {}
        for n in self.top("ip prefix-list"):
            p = n.line.split()
            out.setdefault(p[2], []).append(n.line)
        return out

    def route_maps(self):
        return {n.line.split()[1]: True for n in self.top("route-map")}

    def route_map_matches(self):
        """(route-map, kind, name) for every prefix-list / as-path reference inside a route-map."""
        out = []
        for n in self.top("route-map"):
            rm = n.line.split()[1]
            for v in n.values("match ip address prefix-list"):
                out += [(rm, "prefix-list", x) for x in v.split()]
            for v in n.values("match as-path"):
                out += [(rm, "as-path", x) for x in v.split()]
        return out

    def as_path_lists(self):
        return {n.line.split()[3] for n in self.top("ip as-path access-list")}

    # -- BGP ------------------------------------------------------------------
    def neighbors(self):
        """(vrf, neighbor ip, Node) for every BGP neighbor, including VRF neighbors."""
        out = []
        if not self.bgp:
            return out
        for n in self.bgp.find("neighbor"):
            out.append(("default", n.line.split()[1], n))
        for v in self.bgp.find("vrf"):
            for n in v.find("neighbor"):
                out.append((v.line.split()[1], n.line.split()[1], n))
        return out

    def neighbor_route_maps(self):
        """(neighbor, route-map, direction) for every route-map applied to a neighbor."""
        out = []
        for _, ip, n in self.neighbors():
            for af in n.find("address-family"):
                for v in af.values("route-map"):
                    rm, d = v.split()[:2]
                    out.append((ip, rm, d))
        return out


def expand(spec):
    """'10,20-22' -> [10, 20, 21, 22]"""
    out = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        elif part.strip().isdigit():
            out.append(int(part))
    return out


def ifname_short(desc_port):
    """'Eth1/5' -> 'Ethernet1/5'"""
    m = re.fullmatch(r"Eth(\d+/\d+)", desc_port)
    return f"Ethernet{m.group(1)}" if m else desc_port
