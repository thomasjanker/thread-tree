import unittest

from thread_tree.diagnose import report
from thread_tree.engine import Engine
from thread_tree.simulate import FLAPPER, PROFILES, Simulator, populate, seed_history

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


if __name__ == "__main__":
    unittest.main()
