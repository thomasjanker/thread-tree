import ipaddress
import unittest

from fixture import Fixture
from thread_tree.otdiag import (Netdata, parse_childip6, parse_childtable, parse_conn_time, parse_keyvalues,
                                parse_netdata, parse_router_neighbors, parse_router_table, parse_topology, _fields)

F = Fixture()
BASIC = "meshdiag topology"
FULL = "meshdiag topology ip6-addrs children"


class TopologyTests(unittest.TestCase):
    def test_plain_topology(self):
        routers = parse_topology(F.lines(BASIC))
        self.assertEqual([r.router_id for r in routers], [42, 5, 39, 53, 47])
        self.assertEqual([hex(r.rloc16) for r in routers], ["0xa800", "0x1400", "0x9c00", "0xd400", "0xbc00"])
        self.assertEqual([r.version for r in routers], [5, 4, 5, 5, 4])
        by_id = {r.router_id: r for r in routers}
        self.assertTrue(by_id[42].border_router and by_id[42].parent and not by_id[42].leader)
        self.assertTrue(by_id[53].leader and not by_id[53].border_router)
        self.assertEqual(by_id[42].links, {3: [53], 2: [39], 1: [5, 47]})
        self.assertEqual(by_id[39].links, {3: [5, 42, 47, 53]})
        self.assertEqual(by_id[42].ext, "0200000000000003")
        self.assertTrue(all(r.children is None and r.ip6 == [] for r in routers))   # not requested

    def test_topology_with_addresses_and_children(self):
        by_id = {r.router_id: r for r in parse_topology(F.lines(FULL))}
        br = by_id[42]
        self.assertEqual(len(br.ip6), 8)
        self.assertIn("fdca:fe00:1:1:0:ff:fe00:fc38", br.ip6)                       # an ALOC, written out in full
        self.assertEqual([c.rloc16 for c in br.children], [0xA801, 0xA802, 0xA803, 0xA804])
        self.assertEqual([c.lq for c in br.children], [2, 1, 1, 3])
        self.assertEqual([c.mode for c in br.children], ["", "", "", "rdn"])        # '-' means no flags
        self.assertEqual([c.me for c in br.children], [False, False, False, True])
        self.assertEqual(by_id[47].children, [])                                    # "children: none"
        self.assertEqual(by_id[5].children, [])
        self.assertEqual([c.rloc16 for c in by_id[39].children], [0x9C0C])
        omr = [a for a in by_id[5].ip6 if a.startswith("fdca:fe00:2:1:")]
        self.assertEqual(len(omr), 1)                                               # the address Home Assistant shows
        for r in by_id.values():                                                    # every address is a valid, canonical IPv6
            for a in r.ip6:
                self.assertEqual(str(ipaddress.IPv6Address(a)), a)

    def test_every_router_has_a_link_quality_view(self):
        for r in parse_topology(F.lines(BASIC)):
            self.assertTrue(r.links, r.router_id)
            self.assertTrue(all(q in (1, 2, 3) for q in r.links))

    def test_garbage_and_truncation_are_survived(self):
        self.assertEqual(parse_topology([]), [])
        self.assertEqual(parse_topology(["nonsense", "3-links:{ 1 }", "children:", "rloc16:0x1 lq:x"]), [])
        part = F.lines(FULL)[:7]                                                    # cut in the middle of a router
        routers = parse_topology(part)
        self.assertEqual(len(routers), 1)
        self.assertEqual(routers[0].links, {3: [53], 2: [39], 1: [5, 47]})
        extra = parse_topology(["id:1 rloc16:0x0400 ext-addr:aabbccddeeff0011 ver:5 - leader - future-flag",
                                "    9-links:{ 2 }", "    new-field: whatever"])  # unknown flags and lines are ignored
        self.assertEqual((extra[0].leader, extra[0].links), (True, {9: [2]}))


class ChildTableTests(unittest.TestCase):
    def test_one_sleepy_child(self):
        (child,) = parse_childtable(F.lines("meshdiag childtable 0x9c00"))
        self.assertEqual((child.rloc16, child.ext, child.version), (0x9C0C, "0200000000000008", 4))
        self.assertEqual((child.timeout, child.age, child.supervision, child.queued), (240, 3, 129, 0))
        self.assertEqual((child.rx_on_idle, child.device_type, child.full_net), (False, "mtd", False))
        self.assertEqual((child.rss_ave, child.rss_last, child.margin), (-79, -80, 41))
        self.assertEqual((child.frame_err, child.msg_err), (3.29, 0.0))
        self.assertEqual(child.conn_time, 16 * 3600 + 22 * 60 + 50)

    def test_several_children_with_days_of_uptime_and_a_full_thread_device(self):
        children = parse_childtable(F.lines("meshdiag childtable 0xa800"))
        self.assertEqual([c.rloc16 for c in children], [0xA801, 0xA802, 0xA803, 0xA804])
        self.assertEqual(children[0].conn_time, 9 * 86400 + 6 * 3600 + 31 * 60 + 4)
        last = children[3]
        self.assertEqual((last.rx_on_idle, last.device_type, last.full_net, last.supervision), (True, "ftd", True, 0))
        self.assertEqual((last.rss_ave, last.margin, last.frame_err), (-53, 47, 0.0))

    def test_child_addresses(self):
        out = parse_childip6(F.lines("meshdiag childip6 0xa800"))
        self.assertEqual(sorted(out), [0xA801, 0xA802, 0xA803])
        for addresses in out.values():
            self.assertEqual(len(addresses), 2)
            self.assertTrue(addresses[0].startswith("fdca:fe00:1:1:"))               # mesh-local
            self.assertTrue(addresses[1].startswith("fdca:fe00:2:1:"))               # off-mesh routable

    def test_a_router_that_did_not_answer(self):
        self.assertEqual(F.error("meshdiag childtable 0x1400"), "ResponseTimeout (error 28)")
        self.assertEqual((parse_childtable([]), parse_childip6([])), ([], {}))


class RouterNeighborTests(unittest.TestCase):
    def test_neighbor_table(self):
        neighbors = {n.rloc16: n for n in parse_router_neighbors(F.lines("meshdiag routerneighbortable 0x9c00"))}
        self.assertEqual(sorted(hex(r) for r in neighbors), ["0x1400", "0xa800", "0xbc00", "0xd400"])
        n = neighbors[0x1400]
        self.assertEqual((n.ext, n.version, n.rss_ave, n.rss_last, n.margin), ("0200000000000004", 4, -93, -93, 27))
        self.assertEqual((n.frame_err, n.msg_err, n.conn_time), (17.78, 0.0, 16 * 3600 + 23 * 60 + 1))
        self.assertEqual(neighbors[0xBC00].conn_time, 42 * 60 + 27)                  # a young link
        self.assertEqual(neighbors[0xD400].frame_err, 52.14)

    def test_long_uptime_with_days(self):
        n = {x.rloc16: x for x in parse_router_neighbors(F.lines("meshdiag routerneighbortable 0xa800"))}
        self.assertEqual(n[0xD400].conn_time, 11 * 86400 + 15 * 3600 + 24 * 60 + 17)
        self.assertEqual((n[0xBC00].rss_ave, n[0xBC00].margin), (-96, 4))

    def test_strong_link_between_close_routers(self):
        n = {x.rloc16: x for x in parse_router_neighbors(F.lines("meshdiag routerneighbortable 0xd400"))}
        self.assertEqual((n[0xBC00].rss_ave, n[0xBC00].margin), (-41, 79))

    def test_conn_time(self):
        self.assertEqual([parse_conn_time(t) for t in ("00:00:17", "9d.06:31:04", "11d.15:24:17", "1:02:03", "x", "", None)],
                         [17, 801064, 11 * 86400 + 55457, 3723, None, None, None])


class NetdataAndKeyValueTests(unittest.TestCase):
    def test_netdata(self):
        nd = parse_netdata(F.lines("netdata show"))
        self.assertEqual(nd.prefixes, [{"prefix": "fdca:fe00:2:1::/64", "flags": "paos", "pref": "low", "rloc16": 0xA800}])
        self.assertEqual([r["prefix"] for r in nd.routes], ["fc00::/7", "fdca:fe00:2:2:0:0::/96"])
        self.assertEqual(len(nd.services), 2)
        self.assertEqual((nd.services[0]["enterprise"], nd.services[0]["data"], nd.services[0]["rloc16"]), (44970, "01", 0xA800))
        self.assertEqual(nd.contexts, {1: "fdca:fe00:2:1::/64"})
        self.assertEqual(nd.border_router_rloc16s(), {0xA800})

    def test_context_prefixes_for_compressed_addresses(self):
        nd = parse_netdata(F.lines("netdata show"))
        self.assertEqual(nd.context_prefixes64(), {1: int(ipaddress.IPv6Address("fdca:fe00:2:1::")) >> 64})
        only_long = Netdata(contexts={2: "fdca:fe00:2:2::/96", 3: "garbage"})
        self.assertEqual(only_long.context_prefixes64(), {})

    def test_key_value_commands(self):
        leader = parse_keyvalues(F.lines("leaderdata"))
        self.assertEqual((leader["Partition ID"], leader["Leader Router ID"]), ("123456789", "53"))
        parent = parse_keyvalues(F.lines("parent"))
        self.assertEqual((parent["Rloc"], parent["Link Quality In"], parent["Version"]), ("a800", "3", "5"))
        self.assertEqual(parse_keyvalues(["no separator", ""]), {})

    def test_router_table(self):
        self.assertEqual(parse_router_table(F.lines("router table")),
                         [(5, 0x1400), (39, 0x9C00), (42, 0xA800), (47, 0xBC00), (53, 0xD400)])
        self.assertEqual(parse_router_table(["| ID | RLOC16 |", "+---+"]), [])

    def test_field_helper_keeps_colons_in_values(self):
        self.assertEqual(_fields("conn-time:16:22:50"), {"conn-time": "16:22:50"})
        self.assertEqual(_fields("rss - ave:-79 last:-80 margin:41"), {"rss.ave": "-79", "rss.last": "-80", "rss.margin": "41"})
        self.assertEqual(_fields("err-rate - frame:3.29% msg:0.00%"), {"err-rate.frame": "3.29%", "err-rate.msg": "0.00%"})


if __name__ == "__main__":
    unittest.main()
