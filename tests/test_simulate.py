import unittest

from thread_tree.diagnose import report
from thread_tree.engine import Engine
from thread_tree.simulate import (FLAPPER, NO_DETAIL, OLD_CHILD, PROFILES, STICK, VENDORS, Simulator, populate, refresh_active,
                                  seed_history)

NOW = 10 * 86400.0 + 5000
BR, WEAK, CRIT = "c8d1d1fffe000005", "c8d1d1fffe000011", "c8d1d1fffe000009"


def seeded(hours=6):
    e = Engine()
    populate(e, now=NOW)
    seed_history(e, NOW, hours=hours)
    e.tick(NOW)
    return e


class SeedTests(unittest.TestCase):
    def test_history_gives_the_demo_its_findings(self):
        e = seeded()
        snap, a = report(e, NOW)
        found = {nid: {f["code"] for f in v["findings"]} for nid, v in a["nodes"].items()}
        self.assertTrue({"retry_high", "signal_weak"} <= found[WEAK])
        self.assertTrue({"reparenting", "signal_weak"} <= found[FLAPPER])
        self.assertIn("critical_router", found[CRIT])
        self.assertEqual(found["c8d1d1fffe000001"], set())          # the leader is fine
        self.assertEqual({f["code"] for f in a["summary"]["findings"]}, {"single_border_router"})
        self.assertEqual(snap["nodes"][WEAK]["health"], "warn")

    def test_statistics_are_filled_for_heard_nodes_only(self):
        e = seeded()
        for ext in PROFILES:
            self.assertGreater(e.nodes[ext].stats.frames, 100, ext)
        for ext in ("c8d1d1fffe000016", "a4c138fffe100007"):        # never heard directly
            self.assertEqual(e.nodes[ext].stats.frames, 0)
        self.assertGreater(e.capture.frames, 1000)
        series = e.nodes[BR].stats.series(NOW, 24)
        self.assertEqual(len(series["frames"]), 144)
        self.assertGreater(sum(series["frames"][-36:]), 0)         # the last 6 hours
        self.assertEqual(sum(series["frames"][:100]), 0)           # earlier than the seeded window

    def test_sleepy_devices_poll_and_routers_advertise(self):
        e = seeded()
        self.assertGreater(e.nodes["a4c138fffe100002"].stats.kinds["poll"], 500)
        self.assertGreater(e.nodes[BR].stats.kinds["adv"], 100)
        self.assertNotIn("adv", e.nodes["a4c138fffe100002"].stats.kinds)
        poll = e.nodes["a4c138fffe100002"].stats.summary(NOW)["poll"]
        self.assertAlmostEqual(poll["mean"], 4.0, delta=0.5)

    def test_events_are_seeded_in_order(self):
        e = seeded()
        kinds = [ev["kind"] for ev in e.nodes[WEAK].events]
        self.assertEqual(kinds[0], "first_seen")
        self.assertEqual(kinds[-2:], ["offline", "online"])
        flapper = e.nodes[FLAPPER].events
        self.assertEqual(sum(1 for ev in flapper if ev["kind"] == "parent"), 5)
        self.assertEqual([ev["ts"] for ev in flapper], sorted(ev["ts"] for ev in flapper))

    def test_retransmissions_follow_the_profile(self):
        e = seeded()
        weak = e.nodes[WEAK].stats.summary(NOW)["retry_rate"]
        good = e.nodes["c8d1d1fffe000001"].stats.summary(NOW)["retry_rate"]
        self.assertGreater(weak, 0.15)
        self.assertLess(good, 0.05)

    def test_the_moving_child_never_takes_another_childs_short_address(self):
        e = seeded()
        sim = Simulator(e, interval=5.0)
        sim.rng.random = lambda: 0.0           # the child moves in every step
        for i in range(10):
            sim.step(NOW + 5 * (i + 1))
        self.assertEqual([n.id for n in e.nodes.values() if n.rloc16 is None], [])

    def test_a_live_step_adds_traffic_and_keeps_indirect_nodes_addressed(self):
        e = seeded()
        before = e.nodes[BR].stats.frames
        before_addressed = e.nodes["c8d1d1fffe000016"].last_addressed
        sim = Simulator(e, interval=5.0)
        for i in range(20):
            sim.step(NOW + 5 * (i + 1))
        self.assertGreater(e.nodes[BR].stats.frames, before)
        self.assertGreater(e.nodes["c8d1d1fffe000016"].last_addressed, before_addressed)
        self.assertEqual(e.nodes["c8d1d1fffe000016"].last_heard, 0)  # still never heard


def demo(now=NOW):
    e = Engine()
    populate(e, now=now, history=True, active=True)
    e.tick(now)
    return e


def codes(analysis, nid):
    return {f["code"]: f for f in analysis["nodes"][nid]["findings"]}


class ActiveSeedTests(unittest.TestCase):
    def test_plain_populate_has_no_active_data(self):
        e = Engine()
        populate(e, now=NOW, history=True)
        self.assertEqual(e.diag_info, {})
        self.assertEqual(e.link_metrics, {})
        self.assertNotIn(STICK, e.nodes)
        self.assertTrue(all(n.version is None and n.vendor is None and n.link is None for n in e.nodes.values()))

    def test_versions_vendors_and_links(self):
        e = demo()
        self.assertEqual({n.version for n in e.nodes.values() if n.rloc16 is not None and n.rloc16 % 1024 == 0}, {4, 5})
        self.assertEqual(e.nodes[BR].vendor["model"], "Border Router 2")
        self.assertEqual(e.nodes["c8d1d1fffe000009"].vendor, {"name": "Sample Lighting", "model": "Bulb A60", "sw": "1.0.7", "stack": "1.4.0"})
        self.assertIsNone(e.nodes[WEAK].vendor)                       # the old router answers nothing
        self.assertEqual(len([n for n in e.nodes.values() if n.vendor]), len(VENDORS))
        self.assertFalse([k for k in e.link_metrics if k[0] == 17])   # and measures nothing
        self.assertTrue([k for k in e.link_metrics if k[1] == 17])    # but the others measure their links to it

    def test_the_diagnostic_node_is_a_full_end_device_next_to_the_sniffer(self):
        e = demo()
        n = e.nodes[STICK]
        self.assertEqual((e.diag_self, n.rloc16 >> 10, e.role_of(n), n.last_heard > 0), (STICK, 5, "fed", True))
        self.assertEqual(sum(1 for x in e.nodes.values() if x.rloc16 is None), 0)

    def test_the_findings_that_need_the_active_data(self):
        e = demo()
        _, a = report(e, NOW + 1, {"running": True, "stats": {"mle_ok": 10, "mle_failed": 0}})
        self.assertEqual(codes(a, CRIT)["link_lossy"]["params"]["neighbor_node"], WEAK)   # router 9 loses frames to router 17
        self.assertIn("router_no_detail", codes(a, WEAK))
        self.assertTrue({"child_link_poor", "child_age_high"} <= set(codes(a, OLD_CHILD)))
        self.assertEqual(a["summary"]["active"]["state"], "idle")
        self.assertEqual({f["node"] for f in a["summary"]["active"]["failures"]}, {WEAK})
        self.assertEqual(a["summary"]["active"]["own_node"], STICK)
        self.assertEqual({f["code"] for f in a["summary"]["findings"]}, {"single_border_router"})

    def test_a_demo_round_refreshes_everything_and_never_makes_nodes_up_twice(self):
        e = demo()
        count = len(e.nodes)
        refresh_active(e, NOW + 300)
        self.assertEqual((len(e.nodes), e.diag_info["ts"]), (count, NOW + 300))
        self.assertTrue(all(m["ts"] == NOW + 300 for m in e.link_metrics.values()))

    def test_the_simulator_runs_a_round_every_minute(self):
        e = demo()
        sim = Simulator(e, interval=5.0)
        for i in range(1, 12):                                          # up to a minute after the first step
            sim.step(NOW + 5 * i)
        self.assertEqual(e.diag_info["ts"], NOW)                         # the round of populate()
        sim.step(NOW + 65)
        self.assertEqual(e.diag_info["ts"], NOW + 65)

    def test_the_simulator_stays_passive_without_the_seeding(self):
        e = seeded()
        sim = Simulator(e, interval=5.0)
        for i in range(1, 14):
            sim.step(NOW + 5 * i)
        self.assertEqual((e.diag_info, e.link_metrics), ({}, {}))


if __name__ == "__main__":
    unittest.main()
