import csv
import io
import unittest

from thread_tree.diagnose import (ADV_MIN_OBSERVED, REPARENT_WARN, analyze, node_diagnostics, nodes_csv, report)
from thread_tree.engine import Engine
from thread_tree.topology import snapshot

NOW = 10 * 86400.0 + 5000
LEADER, B, C = "aa" * 8, "bb" * 8, "cc" * 8   # routers with router ids 0, 9, 17


def codes(analysis, nid):
    return {f["code"] for f in analysis["nodes"][nid]["findings"]}


def net(now=NOW, extra_routers=()):
    e = Engine(ml_prefix=0xFD123456789A0001)
    for ext, rloc in ((LEADER, 0x0000), (B, 0x2400), (C, 0x4400), *extra_routers):
        node = e.on_frame(now, ext, rloc)
        e.on_leader_data(now, node, 7, 0)
    return e


def link(e, links, ts=NOW):
    """links: {(src router id, dst router id): (lq_in, lq_out)} as reported in MLE advertisements."""
    by_src = {}
    for (a, b), (lq_in, lq_out) in links.items():
        by_src.setdefault(a, []).append((b, lq_in, lq_out, 1))
    for src, entries in by_src.items():
        e.on_route64(ts, src << 10, entries)


def run(e, now=NOW, capture=None):
    snap = snapshot(e, now)
    return snap, analyze(e, snap, now, capture)


class OfflineTests(unittest.TestCase):
    def test_offline_router_with_children_is_critical_without_children_a_warning(self):
        e = net()
        e.on_frame(NOW, "dd" * 8, (9 << 10) | 1)           # a child of router B
        e.nodes[B].last_seen = NOW - 100_000
        e.nodes[C].last_seen = NOW - 100_000
        _, a = run(e)
        sev = {f["code"]: f["severity"] for f in a["nodes"][B]["findings"]}
        self.assertEqual(sev["offline"], "crit")
        self.assertEqual({f["code"]: f["severity"] for f in a["nodes"][C]["findings"]}["offline"], "warn")
        self.assertEqual(a["nodes"][B]["status"], "crit")

    def test_offline_leader_is_critical_and_online_nodes_have_no_offline_finding(self):
        e = net()
        e.nodes[LEADER].last_seen = NOW - 100_000
        _, a = run(e)
        self.assertEqual({f["code"]: f["severity"] for f in a["nodes"][LEADER]["findings"]}["offline"], "crit")
        self.assertNotIn("offline", codes(a, B))

    def test_end_device_offline_and_parent_offline(self):
        e = net()
        e.on_frame(NOW, "dd" * 8, (9 << 10) | 1)
        e.nodes[B].last_seen = NOW - 100_000
        e.nodes["dd" * 8].last_seen = NOW - 100_000 - 6 * 3600
        _, a = run(e)
        self.assertIn("offline", codes(a, "dd" * 8))
        e.nodes["dd" * 8].last_seen = NOW
        _, a = run(e)
        self.assertEqual(codes(a, "dd" * 8) & {"offline", "parent_offline"}, {"parent_offline"})


class GraphTests(unittest.TestCase):
    def test_chain_has_a_critical_router_and_single_links(self):
        e = net()
        e.on_frame(NOW, "dd" * 8, (17 << 10) | 1)           # a child of C, behind B
        link(e, {(0, 9): (3, 3), (9, 17): (3, 3)})
        _, a = run(e)
        self.assertIn("critical_router", codes(a, B))
        f = [x for x in a["nodes"][B]["findings"] if x["code"] == "critical_router"][0]
        self.assertEqual((f["params"]["cuts_routers"], f["params"]["cut_children"]), (1, 1))
        self.assertIn("single_link", codes(a, C))
        self.assertEqual(a["summary"]["critical_routers"][0]["id"], B)

    def test_triangle_has_no_weak_point(self):
        e = net()
        link(e, {(0, 9): (3, 3), (9, 17): (3, 3), (0, 17): (3, 3)})
        _, a = run(e)
        for nid in (LEADER, B, C):
            self.assertFalse(codes(a, nid) & {"critical_router", "single_link"}, nid)
        self.assertEqual(a["summary"]["critical_routers"], [])

    def test_two_routers_are_too_few_to_judge(self):
        e = Engine()
        for ext, rloc in ((LEADER, 0), (B, 0x2400)):
            e.on_leader_data(NOW, e.on_frame(NOW, ext, rloc), 7, 0)
        link(e, {(0, 9): (3, 3)})
        _, a = run(e)
        self.assertFalse(codes(a, B) & {"critical_router", "single_link"})

    def test_weak_and_asymmetric_links(self):
        e = net()
        link(e, {(0, 9): (1, 1), (9, 17): (3, 1), (0, 17): (3, 3)})
        _, a = run(e)
        self.assertIn("weak_links", codes(a, B))         # both links of B are weak (1 and min(3, 1))
        self.assertNotIn("weak_links", codes(a, C))      # C has a good link to the leader
        self.assertIn("asymmetric_link", codes(a, C))
        f = [x for x in a["nodes"][C]["findings"] if x["code"] == "asymmetric_link"][0]
        self.assertEqual((f["params"]["lq_in"], f["params"]["lq_out"]), (3, 1))

    def test_all_links_weak(self):
        e = net()
        link(e, {(0, 9): (1, 1), (9, 17): (1, 1), (0, 17): (1, 1)})
        _, a = run(e)
        self.assertIn("weak_links", codes(a, B))

    def test_stale_links_are_not_used(self):
        e = net()
        link(e, {(0, 9): (3, 3), (9, 17): (3, 3)}, ts=NOW - 1000)  # reported long ago, the clock is at NOW
        _, a = run(e)
        self.assertNotIn("critical_router", codes(a, B))
        self.assertEqual(a["summary"]["links"]["fresh"], 0)
        self.assertEqual(a["summary"]["links"]["stale"], 2)

    def test_link_quality_distribution(self):
        e = net()
        link(e, {(0, 9): (3, 3), (9, 17): (2, 3), (0, 17): (1, 3)})
        _, a = run(e)
        self.assertEqual(a["summary"]["links"]["lq"], {"3": 1, "2": 1, "1": 1})


class HistoryRuleTests(unittest.TestCase):
    def child_with_moves(self, moves, age=0.0):
        e = net()
        child = e.on_frame(NOW, "dd" * 8, (9 << 10) | 1)
        for i in range(moves):
            e._log(child, NOW - age - i * 60, "parent", **{"from": 5, "to": 9})
        return e

    def test_reparenting_needs_the_threshold_and_a_recent_window(self):
        _, a = run(self.child_with_moves(REPARENT_WARN))
        self.assertIn("reparenting", codes(a, "dd" * 8))
        _, a = run(self.child_with_moves(REPARENT_WARN - 1))
        self.assertNotIn("reparenting", codes(a, "dd" * 8))
        _, a = run(self.child_with_moves(REPARENT_WARN + 5, age=2 * 86400))   # too old
        self.assertNotIn("reparenting", codes(a, "dd" * 8))

    def test_learning_the_parent_is_not_a_move(self):
        e = net()
        child = e.on_frame(NOW, "dd" * 8, None)
        for i in range(5):
            e._log(child, NOW - i, "parent", **{"from": None, "to": 9})
        _, a = run(e)
        self.assertNotIn("reparenting", codes(a, "dd" * 8))

    def test_router_that_keeps_changing_its_short_address(self):
        e = net()
        for i in range(3):
            e._log(e.nodes[B], NOW - i, "rloc16", **{"from": "0x2400", "to": "0x2800"})
        _, a = run(e)
        self.assertIn("role_flap", codes(a, B))


class StatisticsRuleTests(unittest.TestCase):
    def record(self, e, nid, frames, retries=0, rssi=None, start=NOW - 3600):
        node = e.nodes[nid]
        for i in range(frames):
            ts = start + i
            node.stats.record_frame(ts, "data", length=10, rssi=rssi, seq=i % 250, dst="x")
            if i < retries:
                node.stats.record_frame(ts + 0.01, "data", length=10, rssi=rssi, seq=i % 250, dst="x")
        return node

    def test_high_retry_rate(self):
        e = net()
        self.record(e, B, frames=100, retries=40)       # 40 of 140 frames repeated
        self.record(e, C, frames=100, retries=5)
        _, a = run(e)
        self.assertIn("retry_high", codes(a, B))
        self.assertNotIn("retry_high", codes(a, C))

    def test_retry_rate_needs_enough_frames(self):
        e = net()
        self.record(e, B, frames=10, retries=9)
        _, a = run(e)
        self.assertNotIn("retry_high", codes(a, B))

    def test_weak_signal_at_the_sniffer(self):
        e = net()
        self.record(e, B, frames=30, rssi=-92)
        self.record(e, C, frames=10, rssi=-92)           # too few measurements
        self.record(e, LEADER, frames=30, rssi=-60)
        _, a = run(e)
        self.assertIn("signal_weak", codes(a, B))
        self.assertNotIn("signal_weak", codes(a, C))
        self.assertNotIn("signal_weak", codes(a, LEADER))
        self.assertEqual({f["code"]: f["severity"] for f in a["nodes"][B]["findings"]}["signal_weak"], "info")

    def test_advertisements_far_too_often(self):
        e = net()
        node = e.nodes[B]
        node.stats.first = NOW - 2 * 3600
        for i in range(400):                                        # 400 advertisements within the last hour
            node.stats.record_frame(NOW - 3000 + i * 7, "adv")
        _, a = run(e)
        f = [x for x in a["nodes"][B]["findings"] if x["code"] == "adv_fast"][0]
        self.assertAlmostEqual(f["params"]["mean"], 3600 / f["params"]["per_hour"])

    def test_advertisement_rule_waits_for_enough_observation(self):
        e = net()
        node = e.nodes[B]
        node.stats.first = NOW - ADV_MIN_OBSERVED + 600
        for i in range(400):
            node.stats.record_frame(NOW - 3000 + i * 7, "adv")
        node.stats.first = NOW - ADV_MIN_OBSERVED + 600
        _, a = run(e)
        self.assertNotIn("adv_fast", codes(a, B))

    def test_normal_advertisement_rate_is_fine(self):
        e = net()
        node = e.nodes[B]
        for i in range(110):                                        # one every 32 s
            node.stats.record_frame(NOW - 3500 + i * 32, "adv")
        node.stats.first = NOW - 7200
        _, a = run(e)
        self.assertNotIn("adv_fast", codes(a, B))


class IdentityRuleTests(unittest.TestCase):
    def test_unknown_parent_indirect_and_missing_mac(self):
        e = net()
        e.node_for(NOW, rloc16=0x2401, touch=False)       # known by short address only, never heard
        e.on_destination(NOW, "ee" * 8)                   # MAC only, no parent hint, never heard
        _, a = run(e)
        self.assertTrue({"no_mac", "indirect_only"} <= codes(a, "rloc16:2401"))
        self.assertTrue({"unknown_parent", "indirect_only"} <= codes(a, "ee" * 8))
        self.assertNotIn("no_mac", codes(a, "ee" * 8))
        self.assertEqual(a["nodes"]["ee" * 8]["status"], "info")

    def test_a_healthy_node_has_no_findings(self):
        e = net()
        link(e, {(0, 9): (3, 3), (9, 17): (3, 3), (0, 17): (3, 3)})
        _, a = run(e)
        self.assertEqual((a["nodes"][LEADER]["findings"], a["nodes"][LEADER]["status"]), ([], "ok"))
        self.assertEqual(a["nodes"][LEADER]["brief"]["children"], 0)


class NetworkRuleTests(unittest.TestCase):
    def test_partitions_border_routers_and_router_count(self):
        e = net()
        _, a = run(e)
        self.assertEqual({f["code"] for f in a["summary"]["findings"]}, {"no_border_router"})
        e.on_network_data(NOW, {0x2400})
        _, a = run(e)
        self.assertEqual({f["code"]: f["params"] for f in a["summary"]["findings"]}["single_border_router"], {"br_node": B})
        e.on_network_data(NOW, {0x2400, 0x4400})
        _, a = run(e)
        self.assertEqual(a["summary"]["findings"], [])
        # a second partition
        e.on_leader_data(NOW, e.on_frame(NOW, "ff" * 8, 0x8000), 99, 32)
        _, a = run(e)
        self.assertIn("partitions", {f["code"] for f in a["summary"]["findings"]})

    def test_router_limit(self):
        for count, expected in ((27, None), (28, "router_near_limit"), (32, "router_limit")):
            extra = [(f"{i:016x}", (i + 20) << 10) for i in range(1, count - 2)]
            e = net(extra_routers=extra)
            _, a = run(e)
            found = {f["code"] for f in a["summary"]["findings"]} & {"router_near_limit", "router_limit"}
            self.assertEqual(found, {expected} if expected else set(), count)

    def test_many_offline(self):
        e = net(extra_routers=[("dd" * 8, 0x6400), ("ee" * 8, 0x8400)])
        for nid in ("dd" * 8, "ee" * 8):
            e.nodes[nid].last_seen = NOW - 100_000
        _, a = run(e)
        self.assertIn("many_offline", {f["code"] for f in a["summary"]["findings"]})

    def test_sniffer_silent_and_decrypt_failures(self):
        e = net()
        node = e.nodes[B]
        e.record_frame(NOW - 600, node, "data")
        _, a = run(e, capture={"running": True, "stats": {"mle_ok": 2, "mle_failed": 50}})
        found = {f["code"]: f["severity"] for f in a["summary"]["findings"]}
        self.assertEqual((found["sniffer_silent"], found["decrypt_failing"]), ("crit", "crit"))
        self.assertEqual(a["summary"]["status"], "crit")
        _, a = run(e, capture={"running": False, "stats": {"mle_ok": 50, "mle_failed": 0}})
        self.assertNotIn("sniffer_silent", {f["code"] for f in a["summary"]["findings"]})  # not running: no claim

    def test_repeated_leader_changes(self):
        e = net()
        for i in range(2):
            e._log(e.nodes[B], NOW - i * 100, "role", **{"from": "router", "to": "leader"})
        _, a = run(e)
        self.assertIn("leader_changes", {f["code"] for f in a["summary"]["findings"]})

    def test_summary_numbers(self):
        e = net()
        e.on_frame(NOW, "dd" * 8, (9 << 10) | 1)
        e.nodes[C].last_seen = NOW - 100_000
        e.record_frame(NOW - 5, None, "ack")
        _, a = run(e)
        s = a["summary"]
        self.assertEqual((s["nodes"]["total"], s["nodes"]["online"], s["nodes"]["offline"]), (4, 3, 1))
        self.assertEqual(s["nodes"]["by_role"], {"leader": 1, "router": 2, "child": 1})
        self.assertEqual((s["routers"]["count"], s["routers"]["limit"]), (3, 32))
        self.assertEqual([p["id"] for p in s["partitions"]], [7])
        self.assertEqual((s["capture"]["acks"], s["capture"]["frames"]), (1, 1))
        self.assertAlmostEqual(s["capture"]["last_frame_age"], 5.0)


class DetailAndExportTests(unittest.TestCase):
    def setUp(self):
        self.e = net()
        self.child = self.e.on_frame(NOW, "dd" * 8, (9 << 10) | 1)
        link(self.e, {(0, 9): (3, 3), (9, 17): (2, 1)})
        self.e.set_name(B, "=Kueche, Router")
        self.e.record_frame(NOW - 100, self.e.nodes[B], "data", length=10, rssi=-70.5)
        self.snap, self.analysis = run(self.e)

    def test_router_detail(self):
        d = node_diagnostics(self.e, self.snap, self.analysis, B, NOW)
        self.assertEqual((d["role"], d["name"], d["router_id"]), ("router", "=Kueche, Router", 9))
        self.assertEqual({l["neighbor_router_id"] for l in d["links"]}, {0, 17})
        self.assertEqual([c["id"] for c in d["children"]], ["dd" * 8])
        self.assertEqual(len(d["series"]["frames"]), 144)
        self.assertEqual(d["stats"]["rssi"]["last"], -70.5)
        self.assertEqual(d["events"][0]["ts"] >= d["events"][-1]["ts"], True)  # newest first
        self.assertIn("critical_router", {f["code"] for f in d["findings"]})
        neighbour = [l for l in d["links"] if l["neighbor_router_id"] == 17][0]
        self.assertEqual((neighbour["neighbor"]["id"], neighbour["lq_in"], neighbour["lq_out"]), (C, 2, 1))

    def test_child_detail_names_its_parent(self):
        d = node_diagnostics(self.e, self.snap, self.analysis, "dd" * 8, NOW)
        self.assertEqual((d["parent"]["id"], d["children"], d["links"]), (B, [], []))

    def test_unknown_and_placeholder_nodes_have_no_detail(self):
        self.assertIsNone(node_diagnostics(self.e, self.snap, self.analysis, "00" * 8, NOW))
        placeholders = [nid for nid, n in self.snap["nodes"].items() if n.get("placeholder")]
        for nid in placeholders:
            self.assertIsNone(node_diagnostics(self.e, self.snap, self.analysis, nid, NOW))

    def test_report_adds_health_to_every_node(self):
        snap, analysis = report(self.e, NOW)
        for nid, n in snap["nodes"].items():
            if not n.get("placeholder"):
                self.assertEqual(n["health"], analysis["nodes"][nid]["status"])

    def test_csv(self):
        text = nodes_csv(self.e, self.snap, self.analysis, NOW)
        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(len(rows), 4)
        row = {r["id"]: r for r in rows}[B]
        self.assertEqual(row["name"], "'=Kueche, Router")            # spreadsheet formula defused, comma kept
        self.assertEqual(row["mac"], "bb:bb:bb:bb:bb:bb:bb:bb")
        self.assertEqual((row["frames"], row["rssi_avg"], row["rssi_min"]), ("1", "-70.5", "-70.5"))  # numbers intact
        self.assertIn("critical_router", row["findings"])
        self.assertEqual(row["status"], "warn")


if __name__ == "__main__":
    unittest.main()
