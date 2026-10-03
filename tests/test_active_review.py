"""Corner cases of the active diagnostics found in review: freshness between rounds, retiring a replaced diagnostic
node, missing answers, long intervals."""
import tempfile
import unittest
from pathlib import Path

from test_active import BR, LEADER, NOW, OWN_EXT, WEAK1, collected, recorded_run
from test_collector import RecordedStick, Stick, wait_for
from thread_tree.collector import DiagThread, collect_round
from thread_tree.diagnose import report
from thread_tree.engine import DIAG_TTL, LINK_TTL, Engine
from thread_tree.otdiag import Router
from thread_tree.presence import presence
from thread_tree.store import Store
from thread_tree.topology import snapshot

CAPTURE = {"running": False, "stats": {}}


class FreshnessTests(unittest.TestCase):
    def test_links_of_the_latest_round_stay_current_between_rounds(self):
        e, _, _ = collected()
        link = e.links[(42, 53)]
        self.assertTrue(e.link_is_fresh(link))
        e.clock = NOW + 4 * 60                      # 4 minutes later, the next round is due in a minute
        self.assertGreater(e.clock - link["last_seen"], LINK_TTL)
        self.assertTrue(e.link_is_fresh(link))
        e.clock = NOW + DIAG_TTL + 1                # the rounds stopped
        self.assertFalse(e.link_is_fresh(link))

    def test_the_tree_does_not_lose_its_links_between_rounds(self):
        e, _, _ = collected()
        e.clock = NOW + 4 * 60
        snap = snapshot(e, NOW + 4 * 60)
        self.assertFalse([l for l in snap["links"] if l["stale"]])
        edges = [c["edge"]["kind"] for p in snap["partitions"] for c in _walk(p["root"])]
        self.assertNotIn("unknown", edges)

    def test_a_link_from_an_earlier_round_is_not_rescued_by_a_later_one(self):
        e, _, _ = collected()
        e.links[(1, 2)] = {"lq_in": 3, "lq_out": 3, "cost": 1, "last_seen": NOW - 600}   # heard passively long ago
        e.clock = NOW + 60
        self.assertFalse(e.link_is_fresh(e.links[(1, 2)]))

    def test_passive_links_keep_their_short_lifetime(self):
        e = Engine()
        e.on_route64(1000.0, 0x0400, [(0, 3, 3, 1)])
        e.clock = 1000.0 + LINK_TTL + 1
        self.assertFalse(e.link_is_fresh(e.links[(1, 0)]))

    def test_rebuilding_forgets_the_round(self):
        e, _, _ = collected()
        e.reset_topology()
        self.assertEqual(e.diag_ts, 0.0)

    def test_presence_with_rounds_further_apart_than_the_limit(self):
        # a router that nobody heard, vouched for 20 minutes ago; rounds every 30 minutes
        self.assertEqual(presence(0, 0, 0, "router", 1200.0, 0.1, 0.0), (False, False))
        self.assertEqual(presence(0, 0, 0, "router", 1200.0, 0.1, 5400.0), (True, False))

    def test_the_collector_widens_the_window_for_a_long_interval(self):
        e = Engine()
        DiagThread(e, "/dev/null", None, interval=1200.0)
        self.assertEqual(e.diag_ttl, 3600.0)
        DiagThread(e, "/dev/null", None, interval=300.0)
        self.assertEqual(e.diag_ttl, DIAG_TTL)
        slow = DiagThread(e, "/dev/null", None, interval=10 ** 6)
        self.assertEqual((slow.interval, e.diag_ttl), (3600.0, 10800.0))
        self.assertEqual(DiagThread(e, "/dev/null", None, interval=1.0).interval, 10.0)

    def test_findings_use_the_measurements_of_a_long_interval(self):
        e, summary, _ = collected()
        e.diag_ttl = 3 * 3600.0
        e.diag_info = {"enabled": True, "state": "idle", "ts": NOW, "failures": summary["failures"]}
        _, later = report(e, NOW + 2 * 3600, CAPTURE)      # two hours: older than an hour, but only two thirds of the window
        self.assertIn("link_lossy", {f["code"] for f in later["nodes"][LEADER]["findings"]})


def _walk(node):
    for c in node["children"]:
        yield c
        yield from _walk(c)


class KeptAliveTests(unittest.TestCase):
    def test_a_device_the_network_keeps_confirming_is_not_pruned(self):
        e, _, _ = collected()
        day = 86400.0
        e.diag_info = {}
        n = e.nodes[WEAK1]                           # never heard, never addressed: only the routers know it
        n.last_seen = n.last_addressed = NOW - 31 * day
        e.on_diag_topology(NOW, [Router(router_id=5, rloc16=0x1400, ext=WEAK1, version=4)], 123456789)
        self.assertEqual(e.prune(NOW + 60, 30 * day), 0)
        self.assertIn(WEAK1, e.nodes)
        n.last_diag = NOW - 31 * day                 # but not when it stopped being confirmed
        self.assertEqual(e.prune(NOW + 60, 30 * day), 1)

    def test_last_seen_includes_the_networks_own_confirmation(self):
        e, _, _ = collected()
        e.nodes[BR].last_seen = NOW - 7 * 86400
        shown = snapshot(e, NOW + 5)["nodes"][BR]["last_seen"]
        self.assertEqual(shown, NOW)                 # confirmed by the routers a moment ago


class MissingAnswerTests(unittest.TestCase):
    def test_leader_from_leaderdata_when_the_list_does_not_name_it(self):
        e = Engine(ml_prefix=0xFDCAFE0000010001)
        routers = [Router(router_id=5, rloc16=0x1400, ext="aa" * 8, version=5),
                   Router(router_id=9, rloc16=0x2400, ext="bb" * 8, version=5)]   # nobody flagged as leader
        e.on_diag_topology(NOW, routers, 77, leader_router_id=9)
        self.assertEqual(e.leaders, {77: 9})
        self.assertEqual(snapshot(e, NOW)["nodes"]["bb" * 8]["role"], "leader")

    def test_the_collector_passes_the_leader_of_leaderdata(self):
        def run(command, timeout=None, secret=False):
            lines = recorded_run()(command, timeout, secret)
            return [l for l in lines if "- leader" not in l] if command.startswith("meshdiag topology") else lines
        e = Engine(ml_prefix=0xFDCAFE0000010001)
        collect_round(run, e, NOW, {})
        self.assertEqual(e.leaders, {123456789: 53})

    def test_a_router_that_did_not_answer_keeps_what_its_advertisements_said(self):
        e = Engine()
        e.on_route64(NOW - 30, 0x1400, [(9, 2, 3, 1)])                 # router 5 heard router 9 and told us its quality
        old = e.links[(5, 9)]
        self.assertEqual((old["lq_in"], old["lq_out"]), (2, 3))
        # router 5 answers the topology query and lists router 9; router 9 does not answer at all
        e.on_diag_topology(NOW, [Router(router_id=5, rloc16=0x1400, ext="aa" * 8, version=5, links={1: [9]})], 7)
        link = e.links[(5, 9)]
        self.assertEqual((link["lq_in"], link["lq_out"], link["cost"]), (1, 3, 1))   # in: measured now, out: as before

    def test_a_router_that_answered_without_listing_the_other_one_means_no_link_back(self):
        e = Engine()
        routers = [Router(router_id=5, rloc16=0x1400, ext="aa" * 8, version=5, links={3: [9]}),
                   Router(router_id=9, rloc16=0x2400, ext="bb" * 8, version=5)]
        e.on_diag_topology(NOW, routers, 7)
        self.assertEqual(e.links[(5, 9)]["lq_out"], 0)

    def test_the_child_count_includes_children_of_routers_that_did_not_answer(self):
        e, summary, _ = collected()
        listed = sum(1 for n in e.nodes.values() if n.rloc16 is not None and n.rloc16 % 1024 != 0)
        self.assertEqual(summary["children"], listed)


class ReplacedDiagnosticNodeTests(unittest.TestCase):
    OLD, NEW = "aa" * 8, "bb" * 8

    def engine_with_old(self):
        e = Engine()
        e.set_diag_self(self.OLD)
        e.on_frame(100.0, self.OLD, 0x1403)
        e.set_name(self.OLD, "Diagnostic stick")
        return e

    def test_a_new_identity_replaces_the_old_one(self):
        e = self.engine_with_old()
        self.assertTrue(e.pending_events)
        e.set_diag_self(self.NEW)
        self.assertNotIn(self.OLD, e.nodes)
        self.assertNotIn(0x1403, e.rloc_index)
        self.assertEqual(e.pending_events, [])               # nothing of the old node is saved any more
        self.assertEqual(e.names, {self.NEW: "Diagnostic stick"})
        self.assertEqual(e.diag_self, self.NEW)

    def test_the_same_identity_or_none_changes_nothing(self):
        e = self.engine_with_old()
        e.set_diag_self(self.OLD)
        e.set_diag_self(None)
        self.assertIn(self.OLD, e.nodes)
        self.assertEqual(e.names, {self.OLD: "Diagnostic stick"})

    def test_a_name_already_given_to_the_new_identity_wins(self):
        e = self.engine_with_old()
        e.on_frame(100.0, self.NEW, 0x1404)
        e.set_name(self.NEW, "Mine")
        e.set_diag_self(self.NEW)
        self.assertEqual(e.names, {self.NEW: "Mine"})

    def test_it_survives_a_restart_of_the_program(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.sqlite")
            e = self.engine_with_old()
            store.save(e.export_state(clear_dirty=True))
            e2 = Engine()
            e2.load_state(store.load())
            self.assertEqual(e2.diag_self, self.OLD)          # remembered, so a changed address is noticed ...
            e2.set_diag_self(self.NEW)                         # ... when the collector reads it after the restart
            store.save(e2.export_state(clear_dirty=True))
            e3 = Engine()
            e3.load_state(store.load())
            self.assertNotIn(self.OLD, e3.nodes)
            self.assertEqual(e3.names, {self.NEW: "Diagnostic stick"})

    def test_a_stick_that_comes_back_with_another_address_through_the_collector(self):
        e = Engine(ml_prefix=0xFDCAFE0000010001)
        with Stick(RecordedStick, state="child", eligible=False) as stick:
            e.set_diag_self("cc" * 8)                           # what the previous session of the stick had
            e.on_frame(50.0, "cc" * 8, 0x1403)
            thread = DiagThread(e, stick.port, "0e08" + "00" * 8 + "0510" + "11" * 16 + "0708fdcafe0000010001",
                                interval=30.0, join_timeout=5.0, poll=0.01, retry_delay=0.05)
            thread.start()
            self.assertTrue(wait_for(lambda: e.diag_info.get("ts")))
            thread.stop()
            thread.join(timeout=5)
        self.assertEqual(e.diag_self, OWN_EXT)
        self.assertNotIn("cc" * 8, e.nodes)


if __name__ == "__main__":
    unittest.main()
