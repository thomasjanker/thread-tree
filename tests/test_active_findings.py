"""Findings and exports that use the measurements of the active diagnostics (real recorded network)."""
import csv
import io
import unittest

from test_active import BR, LEADER, NOW, OWN_EXT, ROUTER39, WEAK1, WEAK2, collected
from thread_tree.diagnose import ACTIVE_STALE, FINDING_CODES, nodes_csv, node_diagnostics, report
from thread_tree.engine import Engine

CHILD_OF_39, CHILD_OF_LEADER = "0200000000000008", "020000000000000c"          # healthy sleepy children
POOR_CHILDREN = ("0200000000000009", "020000000000000a", "020000000000000b")  # the border router's sleepy children
CAPTURE = {"running": False, "stats": {}}


def active_state(summary, **extra):
    """What the collector thread writes into engine.diag_info after a round."""
    return {"enabled": True, "state": "idle", "ts": NOW, "routers": summary["routers"], "children": summary["children"],
            "failures": summary["failures"], "vendor": 0, "next": NOW + 300, **extra}


def analysed(now=NOW + 5, **extra):
    e, summary, _ = collected()
    e.diag_info = active_state(summary, **extra)
    snap, analysis = report(e, now, CAPTURE)
    return e, snap, analysis


def codes(analysis, nid):
    return {f["code"]: f for f in analysis["nodes"][nid]["findings"]}


class RouterFindingTests(unittest.TestCase):
    def setUp(self):
        self.e, self.snap, self.analysis = analysed()

    def test_the_leader_loses_frames_to_the_weak_router(self):
        f = codes(self.analysis, LEADER)["link_lossy"]
        self.assertEqual(f["severity"], "warn")
        p = f["params"]
        self.assertEqual(p["neighbor_node"], WEAK1)               # router ID 5 = the router with the weak links
        self.assertAlmostEqual(p["rate"], 0.5393)                  # its worst link: 54 % of the frames not acknowledged
        self.assertAlmostEqual(p["msg_rate"], 0.0069)
        self.assertEqual((p["rssi"], p["links"]), (-101, 2))       # it hears that neighbour at the edge of the radio's range

    def test_the_other_end_of_a_lossy_link_reports_its_own_measurement(self):
        f = codes(self.analysis, ROUTER39)["link_lossy"]
        self.assertEqual((f["params"]["neighbor_node"], f["params"]["links"]), (LEADER, 2))
        self.assertAlmostEqual(f["params"]["rate"], 0.5214)

    def test_a_router_with_clean_links_has_no_such_finding(self):
        self.assertNotIn("link_lossy", codes(self.analysis, BR))   # the border router measured 3 % at most

    def test_routers_that_do_not_answer_the_detail_queries(self):
        for nid in (WEAK1, WEAK2):
            self.assertIn("router_no_detail", codes(self.analysis, nid))
        for nid in (BR, LEADER, ROUTER39):
            self.assertNotIn("router_no_detail", codes(self.analysis, nid))

    def test_old_measurements_are_not_used(self):
        _, _, later = analysed(now=NOW + ACTIVE_STALE + 60)
        self.assertNotIn("link_lossy", codes(later, LEADER))
        self.assertNotIn("router_no_detail", codes(later, WEAK1))

    def test_a_link_that_is_only_lossy_in_messages_counts(self):
        e, summary, _ = collected()
        e.diag_info = active_state(summary)
        e.link_metrics[(42, 53)] = {"rss_ave": -60, "rss_last": -60, "margin": 40, "frame_err": 3.0, "msg_err": 9.0, "conn_time": 1, "ts": NOW}
        _, analysis = report(e, NOW + 5, CAPTURE)
        f = codes(analysis, BR)["link_lossy"]
        self.assertEqual(f["params"]["neighbor_node"], LEADER)
        self.assertAlmostEqual(f["params"]["msg_rate"], 0.09)

    def test_a_neighbour_without_a_node_is_named_by_its_short_address(self):
        e, summary, _ = collected()
        e.diag_info = active_state(summary)
        e.link_metrics[(42, 20)] = {"rss_ave": -80, "rss_last": -80, "margin": 20, "frame_err": 80.0, "msg_err": 1.0, "conn_time": 1, "ts": NOW}
        _, analysis = report(e, NOW + 5, CAPTURE)
        self.assertEqual(codes(analysis, BR)["link_lossy"]["params"]["neighbor_node"], "0x5000")


class ChildFindingTests(unittest.TestCase):
    def setUp(self):
        self.e, self.snap, self.analysis = analysed()

    def test_children_of_the_border_router_have_a_poor_link(self):
        for nid in POOR_CHILDREN:
            f = codes(self.analysis, nid)["child_link_poor"]
            self.assertEqual(f["severity"], "info")                # frames are lost, but no message
            self.assertGreaterEqual(f["params"]["rate"], 0.25)
        self.assertEqual(codes(self.analysis, "020000000000000b")["child_link_poor"]["params"]["rssi"], -96)

    def test_healthy_children_and_the_diagnostic_node_have_none(self):
        for nid in (CHILD_OF_39, CHILD_OF_LEADER, OWN_EXT):
            self.assertNotIn("child_link_poor", codes(self.analysis, nid))

    def test_lost_messages_make_it_a_warning(self):
        self.e.nodes[CHILD_OF_39].link.update(frame_err=30.0, msg_err=7.0)
        _, analysis = report(self.e, NOW + 5, CAPTURE)
        f = codes(analysis, CHILD_OF_39)["child_link_poor"]
        self.assertEqual(f["severity"], "warn")
        self.assertEqual(analysis["nodes"][CHILD_OF_39]["status"], "warn")

    def test_a_weak_signal_alone_is_a_note(self):
        self.e.nodes[CHILD_OF_39].link.update(frame_err=1.0, msg_err=0.0, rss_ave=-93)
        _, analysis = report(self.e, NOW + 5, CAPTURE)
        self.assertEqual(codes(analysis, CHILD_OF_39)["child_link_poor"]["severity"], "info")

    def test_the_noise_floor_dependent_margin_is_not_a_criterion(self):
        self.e.nodes[CHILD_OF_39].link.update(frame_err=1.0, msg_err=0.0, rss_ave=-70, margin=2)
        _, analysis = report(self.e, NOW + 5, CAPTURE)
        self.assertNotIn("child_link_poor", codes(analysis, CHILD_OF_39))

    def test_a_parent_that_has_not_heard_the_child_for_most_of_the_timeout(self):
        self.assertNotIn("child_age_high", codes(self.analysis, CHILD_OF_39))
        self.e.nodes[CHILD_OF_39].link.update(age=200, timeout=240)
        _, analysis = report(self.e, NOW + 5, CAPTURE)
        f = codes(analysis, CHILD_OF_39)["child_age_high"]
        self.assertEqual((f["severity"], f["params"]), ("info", {"age": 200, "timeout": 240}))
        self.e.nodes[CHILD_OF_39].link.update(age=100)
        self.assertNotIn("child_age_high", codes(report(self.e, NOW + 5, CAPTURE)[1], CHILD_OF_39))

    def test_a_child_without_measurements_has_no_active_findings(self):
        self.e.nodes[CHILD_OF_39].link = None
        _, analysis = report(self.e, NOW + 5, CAPTURE)
        self.assertEqual({"child_link_poor", "child_age_high"} & set(codes(analysis, CHILD_OF_39)), set())


class IndirectTests(unittest.TestCase):
    def test_confirmed_by_the_diagnostics_instead_of_just_not_heard(self):
        _, _, analysis = analysed()
        for nid in (BR, WEAK1, CHILD_OF_39):
            c = codes(analysis, nid)
            self.assertIn("indirect_confirmed", c)
            self.assertNotIn("indirect_only", c)
        self.assertEqual(codes(analysis, BR)["indirect_confirmed"]["params"]["since"], NOW)

    def test_without_recent_diagnostics_it_is_just_not_heard(self):
        _, _, analysis = analysed(now=NOW + ACTIVE_STALE + 60)
        c = codes(analysis, BR)
        self.assertIn("indirect_only", c)
        self.assertNotIn("indirect_confirmed", c)

    def test_passive_only_networks_are_unchanged(self):
        e = Engine()
        e.on_frame(NOW, "aa" * 8, 0x0400)
        e.on_frame(NOW, "bb" * 8, None)
        snap, analysis = report(e, NOW + 1, CAPTURE)
        self.assertEqual(analysis["summary"]["active"], {"enabled": False})
        for nid in analysis["nodes"]:
            self.assertFalse({"indirect_confirmed", "link_lossy", "child_link_poor", "router_no_detail"} & set(codes(analysis, nid)))


class NetworkTests(unittest.TestCase):
    def test_the_collector_failing_is_a_warning(self):
        _, _, analysis = analysed(state="error", error="the node did not attach to the network")
        f = [f for f in analysis["summary"]["findings"] if f["code"] == "diag_failing"]
        self.assertEqual([(x["severity"], x["params"]) for x in f], [("warn", {"message": "the node did not attach to the network"})])
        self.assertEqual(analysis["summary"]["status"], "warn")

    def test_a_working_collector_has_no_such_finding(self):
        _, _, analysis = analysed()
        self.assertNotIn("diag_failing", {f["code"] for f in analysis["summary"]["findings"]})

    def test_summary_of_the_collector_names_the_devices(self):
        e, _, analysis = analysed(own_rloc16=0xA804)
        a = analysis["summary"]["active"]
        self.assertEqual((a["enabled"], a["state"], a["routers"], a["children"]), (True, "idle", 5, 6))
        self.assertEqual({(x["rloc16"], x["node"]) for x in a["failures"]}, {("0x1400", WEAK1), ("0xbc00", WEAK2)})
        self.assertEqual((a["own_rloc16"], a["own_node"]), ("0xa804", OWN_EXT))
        self.assertEqual(a["next"], NOW + 300)

    def test_every_code_is_known(self):
        _, _, analysis = analysed(state="error", error="x")
        seen = {f["code"] for v in analysis["nodes"].values() for f in v["findings"]} | {f["code"] for f in analysis["summary"]["findings"]}
        self.assertLessEqual(seen, set(FINDING_CODES))


class DetailAndExportTests(unittest.TestCase):
    def setUp(self):
        self.e, self.snap, self.analysis = analysed()

    def test_router_page_has_the_measurements_of_every_link(self):
        d = node_diagnostics(self.e, self.snap, self.analysis, LEADER, NOW + 5)
        self.assertEqual(d["version"], 5)
        self.assertEqual(d["diag_self"], False)
        by_neighbor = {(l["neighbor"]["id"] if l["neighbor"] else None, l["reported_by"]): l for l in d["links"]}
        measured = by_neighbor[(WEAK1, "self")]["metrics"]
        self.assertEqual((measured["rss_ave"], measured["frame_err"]), (-101, 53.93))
        self.assertIsNone(by_neighbor[(WEAK1, "neighbor")]["metrics"])    # router 5 never answered: nothing measured by it

    def test_router_page_lists_children_with_their_link(self):
        d = node_diagnostics(self.e, self.snap, self.analysis, BR, NOW + 5)
        kids = {c["id"]: c for c in d["children"]}
        self.assertEqual(set(kids), {*POOR_CHILDREN, OWN_EXT})
        self.assertEqual(kids["020000000000000b"]["link"]["rss_ave"], -96)
        self.assertEqual((kids[OWN_EXT]["version"], kids[OWN_EXT]["ftd"], kids[OWN_EXT]["diag_self"]), (5, True, True))
        self.assertFalse(kids["0200000000000009"]["diag_self"])

    def test_child_page_has_the_parents_view(self):
        d = node_diagnostics(self.e, self.snap, self.analysis, "020000000000000b", NOW + 5)
        self.assertEqual((d["link"]["margin"], d["link"]["queued"], d["link"]["timeout"]), (4, 0, 240))
        self.assertEqual(d["parent"]["id"], BR)
        self.assertEqual(d["last_diag"], NOW - 6)

    def test_the_diagnostic_node_is_marked(self):
        d = node_diagnostics(self.e, self.snap, self.analysis, OWN_EXT, NOW + 5)
        self.assertTrue(d["diag_self"])

    def test_csv_has_version_vendor_and_the_parents_measurements(self):
        self.e.on_diag_vendor(NOW, 0xA800, {"name": "=IKEA", "model": "DIRIGERA", "sw": "2.8"})
        text = nodes_csv(self.e, *report(self.e, NOW + 5, CAPTURE), NOW + 5)
        rows = list(csv.DictReader(io.StringIO(text)))
        by_mac = {r["mac"].replace(":", ""): r for r in rows}
        br = by_mac[BR]
        self.assertEqual((br["thread_version"], br["vendor"], br["model"], br["firmware"]), ("1.4", "'=IKEA", "DIRIGERA", "2.8"))
        child = by_mac["020000000000000b"]
        self.assertEqual((child["parent_rssi"], child["parent_margin"], child["parent_frame_err"]), ("-96", "4", "25.45"))
        self.assertEqual(by_mac[WEAK1]["thread_version"], "1.3")
        self.assertEqual(by_mac[WEAK1]["parent_rssi"], "")


class LinkMetricsTests(unittest.TestCase):
    def test_a_neighbour_that_vanished_from_the_table_loses_its_measurement(self):
        from thread_tree.otdiag import RouterNeighbor
        e, _, _ = collected()
        self.assertIn((39, 5), e.link_metrics)
        keep = [RouterNeighbor(rloc16=0xD400, ext="0200000000000006", version=5, rss_ave=-70, rss_last=-70, margin=30,
                               frame_err=1.0, msg_err=0.0, conn_time=5)]
        e.on_diag_neighbors(NOW + 300, 0x9C00, keep)
        self.assertEqual({k for k in e.link_metrics if k[0] == 39}, {(39, 53)})
        self.assertEqual(e.link_metrics[(39, 53)]["rss_ave"], -70)
        self.assertIn((53, 5), e.link_metrics)                             # other routers' measurements stay


if __name__ == "__main__":
    unittest.main()
