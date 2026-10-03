"""Active diagnostics: one collection round against the recorded output of a real network."""
import tempfile
import unittest
from pathlib import Path

from fixture import Fixture
from thread_tree.collector import NO_DETAIL_BACKOFF, CollectorError, collect_round, parse_vendor
from thread_tree.engine import Engine
from thread_tree.otcli import OtCliError
from thread_tree.store import Store
from thread_tree.topology import snapshot

F = Fixture()
NOW = 1_790_000_000.0
ML_PREFIX = 0xFDCAFE0000010001          # fdca:fe00:1:1 (the anonymized mesh-local prefix)
OWN_EXT = F.lines("extaddr")[0]         # the node that ran the diagnostics
BR, LEADER, WEAK1, ROUTER39, WEAK2 = "0200000000000003", "0200000000000006", "0200000000000004", "0200000000000005", "0200000000000007"


def recorded_run(vendor=None, calls=None):
    """`run` that answers from the transcript: recorded errors as OtCliError, unknown commands as InvalidCommand."""
    def run(command, timeout=None, secret=False):
        if calls is not None:
            calls.append(command)
        if command.startswith("networkdiagnostic get"):
            if vendor is None:
                raise OtCliError(command, 28, "ResponseTimeout")
            return vendor
        if command not in F.runs:
            raise OtCliError(command, 35, "InvalidCommand")
        if F.error(command):
            raise OtCliError(command, 28, "ResponseTimeout")
        return F.lines(command)
    return run


def collected(vendor=None, calls=None, now=NOW):
    e = Engine(ml_prefix=ML_PREFIX)
    e.set_diag_self(OWN_EXT)
    no_detail: dict = {}
    summary = collect_round(recorded_run(vendor, calls), e, now, no_detail)
    return e, summary, no_detail


class RoundTests(unittest.TestCase):
    def setUp(self):
        self.e, self.summary, self.no_detail = collected()

    def test_nodes_with_mac_addresses_and_roles(self):
        e = self.e
        self.assertEqual(len(e.nodes), 11)       # 5 routers + 6 children, nobody left without a MAC address
        self.assertEqual([n.id for n in e.nodes.values() if n.ext is None], [])
        self.assertEqual(e.nodes[BR].rloc16, 0xA800)
        self.assertEqual(e.nodes[LEADER].rloc16, 0xD400)
        snap = snapshot(e, NOW + 5)["nodes"]
        self.assertEqual({n["role"] for n in snap.values() if n["rloc16"] in ("0xa801", "0xa802", "0xa803", "0x9c0c", "0xd401")}, {"sed"})
        self.assertEqual(snap[OWN_EXT]["role"], "fed")                # the diagnostic node: rdn = full thread device
        self.assertTrue(snap[OWN_EXT]["diag_self"])
        self.assertEqual(sum(1 for n in snap.values() if n["diag_self"]), 1)
        self.assertEqual(snap[LEADER]["role"], "leader")
        self.assertEqual([n["id"] for n in snap.values() if n["border_router"]], [BR])

    def test_versions(self):
        v = {e.rloc16: e.version for e in self.e.nodes.values()}
        self.assertEqual((v[0xA800], v[0x1400], v[0x9C00], v[0xD400], v[0xBC00]), (5, 4, 5, 5, 4))
        self.assertEqual(v[0x9C0C], 4)                                # a child that is a Thread 1.3 device

    def test_both_directions_of_every_link(self):
        links = self.e.links
        self.assertEqual({k: (v["lq_in"], v["lq_out"]) for k, v in links.items() if k[0] == 42},
                         {(42, 53): (3, 3), (42, 39): (2, 3), (42, 5): (1, 1), (42, 47): (1, 1)})
        self.assertEqual((links[(5, 39)]["lq_in"], links[(5, 39)]["lq_out"], links[(5, 39)]["cost"]), (2, 3, None))
        self.assertEqual(len(links), 18)             # 4 + 3 + 4 + 4 + 3 neighbours listed by the five routers
        self.assertTrue(all(v["last_seen"] == NOW for v in links.values()))

    def test_children_get_mac_addresses_links_and_addresses(self):
        child = next(n for n in self.e.nodes.values() if n.rloc16 == 0x9C0C)
        self.assertEqual(child.ext, "0200000000000008")
        self.assertEqual((child.link["rss_ave"], child.link["margin"], child.link["frame_err"]), (-79, 41, 3.29))
        self.assertEqual(child.link["conn_time"], 58970)
        self.assertEqual((child.ftd, child.rx_on_idle), (False, False))
        self.assertEqual(child.last_diag, NOW - 3)                    # the parent heard it 3 seconds ago
        self.assertEqual(len(child.addresses), 2)                     # its ML-EID (prefix 1:1) and its OMR address (2:1)
        self.assertEqual(sorted(a.rsplit(":", 4)[0] for a in child.addresses), ["fdca:fe00:1:1", "fdca:fe00:2:1"])

    def test_router_addresses_include_the_omr_address_home_assistant_shows(self):
        omr = [a for a in self.e.nodes[WEAK1].addresses if a.startswith("fdca:fe00:2:1:")]
        self.assertEqual(len(omr), 1)
        leader = self.e.nodes[LEADER].addresses
        self.assertIn("fdca:fe00:1:1:0:ff:fe00:fc00", leader)         # the leader's anycast address
        for node in self.e.nodes.values():                            # link-local and RLOC are derived, not stored
            self.assertFalse([a for a in node.addresses if a.startswith("fe80") or a.endswith(f"fe00:{node.rloc16:x}")])

    def test_neighbor_measurements_between_routers(self):
        m = self.e.link_metrics
        self.assertEqual(len(m), 12)                                   # three routers answered, 4 neighbours each
        self.assertEqual((m[(39, 5)]["rss_ave"], m[(39, 5)]["margin"], m[(39, 5)]["frame_err"]), (-93, 27, 17.78))
        self.assertEqual(m[(39, 47)]["conn_time"], 42 * 60 + 27)      # a young link
        self.assertEqual(m[(53, 5)]["frame_err"], 53.93)
        self.assertEqual((m[(53, 47)]["rss_ave"], m[(53, 47)]["margin"]), (-41, 79))
        self.assertNotIn((5, 39), m)                                   # router 5 never answered

    def test_contexts_and_border_router_from_network_data(self):
        self.assertEqual(self.e.contexts, {1: 0xFDCAFE0000020001})
        self.assertTrue(self.e.nodes[BR].border_router)

    def test_partition_and_leader(self):
        self.assertEqual(self.e.leaders, {123456789: 53})
        self.assertEqual(self.e.primary_partition, 123456789)

    def test_summary_and_failures(self):
        s = self.summary
        self.assertEqual((s["routers"], s["children"], s["partition"]), (5, 6, 123456789))
        self.assertEqual(s["failures"], {0x1400: "ResponseTimeout", 0xBC00: "ResponseTimeout"})
        self.assertEqual(self.no_detail, {0x1400: NOW + NO_DETAIL_BACKOFF, 0xBC00: NOW + NO_DETAIL_BACKOFF})

    def test_routers_that_did_not_answer_are_still_alive(self):
        for ext in (WEAK1, WEAK2):
            n = self.e.nodes[ext]
            self.assertEqual(n.last_diag, NOW)
            self.assertEqual(snapshot(self.e, NOW + 60)["nodes"][ext]["online"], True)   # never heard by a sniffer
            self.assertEqual(snapshot(self.e, NOW + 60)["nodes"][ext]["heard"], False)
        self.assertEqual(snapshot(self.e, NOW + 5 * 3600)["nodes"][WEAK1]["online"], False)

    def test_a_device_the_network_vouches_for_is_online_not_just_indirectly(self):
        n = snapshot(self.e, NOW + 60)["nodes"][WEAK1]                # never heard by a sniffer, but the routers list it
        self.assertEqual((n["online"], n["online_indirect"], n["heard"]), (True, False, False))

    def test_without_new_answers_only_frames_to_the_device_keep_it_online_indirectly(self):
        self.e.on_destination(NOW + 5 * 3600 + 100, WEAK1)
        n = snapshot(self.e, NOW + 5 * 3600 + 200)["nodes"][WEAK1]    # the last answer is hours old (a router: 15 min)
        self.assertEqual((n["online"], n["online_indirect"]), (True, True))


class AskingTests(unittest.TestCase):
    def test_routers_without_children_are_not_asked_for_their_child_table(self):
        calls: list[str] = []
        collected(calls=calls)
        self.assertNotIn("meshdiag childtable 0xbc00", calls)          # "children: none" in the topology
        self.assertNotIn("meshdiag childip6 0x1400", calls)
        self.assertIn("meshdiag routerneighbortable 0xbc00", calls)
        self.assertIn("meshdiag childtable 0xa800", calls)

    def test_a_router_that_did_not_answer_is_skipped_until_the_backoff_is_over(self):
        e, _, no_detail = collected()
        calls: list[str] = []
        s = collect_round(recorded_run(calls=calls), e, NOW + 300, no_detail)
        self.assertFalse([c for c in calls if c.endswith("0x1400") or c.endswith("0xbc00")])
        self.assertEqual(s["failures"][0x1400], "no answer earlier")
        calls.clear()
        collect_round(recorded_run(calls=calls), e, NOW + NO_DETAIL_BACKOFF + 1, no_detail)
        self.assertIn("meshdiag routerneighbortable 0x1400", calls)    # tried again after the backoff

    def test_a_second_round_changes_nothing_but_the_time(self):
        e, _, no_detail = collected()
        counts = (len(e.nodes), len(e.links), len(e.link_metrics))
        addresses = {nid: sorted(n.addresses) for nid, n in e.nodes.items()}
        collect_round(recorded_run(), e, NOW + 600, no_detail)
        self.assertEqual((len(e.nodes), len(e.links), len(e.link_metrics)), counts)
        self.assertEqual({nid: sorted(n.addresses) for nid, n in e.nodes.items()}, addresses)
        self.assertTrue(all(v["last_seen"] == NOW + 600 for v in e.links.values()))

    def test_neighbours_that_vanish_are_removed_from_the_links(self):
        e, _, no_detail = collected()
        self.assertIn((5, 42), e.links)
        run = recorded_run()

        def changed(command, timeout=None, secret=False):
            lines = run(command, timeout)
            if command == "meshdiag topology ip6-addrs children":     # router 5 no longer lists router 42
                return [l.replace("1-links:{ 42 53 }", "1-links:{ 53 }") for l in lines]
            return lines

        collect_round(changed, e, NOW + 600, no_detail)
        self.assertNotIn((5, 42), e.links)
        self.assertIn((5, 53), e.links)

    def test_no_routers_is_an_error(self):
        def run(command, timeout=None, secret=False):
            return ["Partition ID: 1"] if command == "leaderdata" else []
        with self.assertRaises(CollectorError):
            collect_round(run, Engine(), NOW, {})


class VendorTests(unittest.TestCase):
    VENDOR = ["DIAG_GET.rsp/ans from fdca:fe00:1:1:0:ff:fe00:1400: 1900", "Vendor Name: Example GmbH", "Vendor Model: Plug 2",
              "Vendor SW Version: 1.2.3", "Thread Stack Version: OPENTHREAD/abc"]

    def test_parse(self):
        self.assertEqual(parse_vendor(self.VENDOR), {"name": "Example GmbH", "model": "Plug 2", "sw": "1.2.3",
                                                     "stack": "OPENTHREAD/abc"})
        self.assertEqual(parse_vendor(["Vendor Name: only a name"]), {"name": "only a name"})
        self.assertIsNone(parse_vendor(["DIAG_GET.rsp/ans from x: 00"]))
        self.assertIsNone(parse_vendor([]))

    def test_routers_are_asked_first_a_few_per_round_and_the_node_itself_never(self):
        calls: list[str] = []
        e, summary, _ = collected(vendor=self.VENDOR, calls=calls)
        asked = [c for c in calls if c.startswith("networkdiagnostic get")]
        self.assertEqual(len(asked), 3)
        self.assertEqual(summary["vendor"], 3)
        self.assertTrue(all(":0:ff:fe00:" in c and c.endswith(" 25 26 27 28") for c in asked))
        self.assertTrue(all(int(c.split(":")[-1].split()[0], 16) & 0x3FF == 0 for c in asked))   # all routers
        own = next(n for n in e.nodes.values() if n.ext == OWN_EXT)
        self.assertIsNone(own.vendor)
        self.assertEqual(own.vendor_try, 0.0)
        have = [n for n in e.nodes.values() if n.vendor]
        self.assertEqual(len(have), 3)
        self.assertEqual(have[0].vendor["name"], "Example GmbH")

    def test_devices_that_do_not_answer_are_not_asked_again_soon(self):
        calls: list[str] = []
        e, _, no_detail = collected(vendor=None, calls=calls)             # nobody answers
        first = len([c for c in calls if c.startswith("networkdiagnostic get")])
        self.assertEqual(first, 3)
        calls.clear()
        collect_round(recorded_run(calls=calls), e, NOW + 300, no_detail)
        second = [c for c in calls if c.startswith("networkdiagnostic get")]
        self.assertEqual(len(second), 2)                                    # the other two routers, not the first three again
        self.assertEqual(len({c for c in second}), 2)

    def test_everyone_is_asked_in_the_end_then_nobody_until_the_retry_time(self):
        e, _, no_detail = collected(vendor=None)
        for i in range(1, 6):
            collect_round(recorded_run(), e, NOW + 300 * i, no_detail)
        calls: list[str] = []
        collect_round(recorded_run(calls=calls), e, NOW + 3000, no_detail)
        self.assertEqual([c for c in calls if c.startswith("networkdiagnostic get")], [])


class PersistenceTests(unittest.TestCase):
    def test_everything_survives_a_restart(self):
        e, _, _ = collected(vendor=VendorTests.VENDOR)
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.sqlite")
            store.save(e.export_state(clear_dirty=True))
            e2 = Engine()
            e2.load_state(store.load())
        self.assertEqual(snapshot(e2, NOW + 60)["nodes"], snapshot(e, NOW + 60)["nodes"])
        self.assertEqual((e2.link_metrics, e2.contexts, e2.diag_self), (e.link_metrics, e.contexts, e.diag_self))
        self.assertEqual({k: (v["lq_in"], v["lq_out"], v["cost"]) for k, v in e2.links.items()},
                         {k: (v["lq_in"], v["lq_out"], v["cost"]) for k, v in e.links.items()})

    def test_reset_forgets_the_measurements(self):
        e, _, _ = collected()
        e.reset_topology()
        self.assertEqual((e.link_metrics, e.contexts), ({}, {}))
        self.assertEqual(e.diag_self, OWN_EXT)                              # which node we are does not depend on the network


class ActiveAndPassiveTests(unittest.TestCase):
    def test_diagnostics_do_not_pretend_the_sniffer_heard_the_device(self):
        e, _, _ = collected()
        self.assertTrue(all(n.last_heard == 0 for n in e.nodes.values()))
        e.on_frame(NOW + 10, BR, 0xA800)
        self.assertEqual(e.nodes[BR].last_heard, NOW + 10)

    def test_a_node_known_only_by_short_address_gets_its_mac_from_the_child_table(self):
        e = Engine(ml_prefix=ML_PREFIX)
        e.node_for(NOW - 100, rloc16=0x9C0C, touch=False)                 # seen in traffic, MAC unknown
        e.set_diag_self(OWN_EXT)
        collect_round(recorded_run(), e, NOW, {})
        self.assertNotIn("rloc16:9c0c", e.nodes)
        self.assertEqual(e.nodes["0200000000000008"].rloc16, 0x9C0C)


if __name__ == "__main__":
    unittest.main()
