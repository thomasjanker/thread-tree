"""Guided test "router outage", played through with the demo network (whose simulator switches the router off)."""
import json
import tempfile
import time
import unittest
from pathlib import Path

from test_config import ApiFixture
from thread_tree.engine import Engine
from thread_tree.runtime import Controller, TestBusy
from thread_tree.scenario import MAX_DURATION, RouterOutageTest
from thread_tree.simulate import Simulator, populate

ROUTER9, ROUTER17, LEADER = "c8d1d1fffe000009", "c8d1d1fffe000011", "c8d1d1fffe000001"
WINDOW = "a4c138fffe100004"                       # the sleepy child of router 9


class DemoOutageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.engine = Engine()
        self.t0 = time.time()
        populate(self.engine, now=self.t0, history=True)
        self.c = Controller(self.engine, "demo", editable=False, locked_reason="demo",
                            settings_path=Path(self.tmp.name) / "s.json")
        self.sim = Simulator(self.engine)

    def run_for(self, seconds, start):
        t = start
        while t < start + seconds:
            t += 5.0
            self.sim.step(t)
            self.engine.tick(t)
        return t

    def test_the_children_move_and_the_report_says_when(self):
        report = self.c.start_router_test(ROUTER9)["running"]
        self.assertEqual((report["target_rloc16"], report["summary"]["children"]), ("0x2400", 1))
        start = self.c.test.start
        self.run_for(120, start)
        report = self.c.test.report(self.engine, start + 120)
        child = report["children"][0]
        self.assertEqual((child["id"], child["status"], child["new_parent"]), (WINDOW, "moved", 0))
        self.assertGreaterEqual(child["attached_after"], 60)          # a sleepy device notices late
        self.assertLess(child["searched_after"], child["attached_after"])
        self.assertEqual(report["router_silent_after"], 0.0)          # nothing heard from it since the start
        self.assertEqual(report["links_left"], 0)                     # the mesh dropped it
        self.assertEqual(report["summary"]["moved"], 1)

    def test_stopping_keeps_the_report_and_switches_the_router_on(self):
        self.c.start_router_test(ROUTER17)
        self.run_for(30, self.c.test.start)
        result = self.c.stop_test()
        self.assertIsNone(result["running"])
        self.assertEqual(result["past"][0]["target"], ROUTER17)
        self.assertIsNone(self.engine.demo_outage)
        stored = json.loads((Path(self.tmp.name) / "s.json").read_text())["tests"]
        self.assertEqual(stored[0]["target_rloc16"], "0x4400")
        again = Controller(Engine(), "demo", editable=False, settings_path=Path(self.tmp.name) / "s.json")
        self.assertEqual(again.tests()["past"][0]["target"], ROUTER17)  # kept across restarts

    def test_one_test_at_a_time_and_only_routers(self):
        self.c.start_router_test(ROUTER9)
        with self.assertRaises(TestBusy):
            self.c.start_router_test(ROUTER17)
        self.c.stop_test()
        with self.assertRaises(TestBusy):
            self.c.stop_test()
        with self.assertRaises(ValueError):
            self.c.start_router_test(WINDOW)

    def test_a_forgotten_test_ends_by_itself(self):
        test = RouterOutageTest(self.engine, LEADER, self.t0)
        report = test.report(self.engine, self.t0 + MAX_DURATION + 60)
        self.assertFalse(report["running"])
        self.assertEqual(report["duration"], MAX_DURATION)


class TestApiTests(ApiFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.engine.on_frame(1000.0, "aa" * 8, 0x0400)

    def post(self, path, body="{}", **headers):
        return self.call("POST", path, body, {"Content-Type": "application/json", **headers})

    def test_start_report_stop(self):
        status, data = self.post("/api/tests/router-outage", json.dumps({"router": "aa" * 8}))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["running"]["target_rloc16"], "0x0400")
        self.assertEqual(self.post("/api/tests/router-outage", json.dumps({"router": "aa" * 8}))[0], 409)
        self.assertEqual(json.loads(self.call("GET", "/api/tests")[1])["running"]["target"], "aa" * 8)
        status, data = self.post("/api/tests/stop")
        self.assertEqual((status, json.loads(data)["running"]), (200, None))

    def test_bad_requests_and_guards(self):
        self.assertEqual(self.post("/api/tests/router-outage", "{}")[0], 400)
        self.assertEqual(self.post("/api/tests/router-outage", json.dumps({"router": "nope"}))[0], 400)
        self.assertEqual(self.post("/api/tests/router-outage", json.dumps({"router": "aa" * 8}), Origin="http://evil.example")[0], 403)
        self.assertEqual(self.post("/api/tests/stop")[0], 409)


if __name__ == "__main__":
    unittest.main()


class AllGuidedTests(unittest.TestCase):
    """Every guided test, with the demo simulator playing the user's part."""

    def setUp(self):
        from thread_tree.scenario import make_test
        self.make_test = make_test
        self.engine = Engine()
        self.t0 = time.time()
        populate(self.engine, now=self.t0, history=True)
        self.engine.tick(self.t0)
        self.sim = Simulator(self.engine)

    def run_test(self, kind, target, seconds):
        test = self.make_test(kind, self.engine, target, self.t0)
        self.engine.demo_outage = (target, self.t0, kind)
        t = self.t0
        while t < self.t0 + seconds:
            t += 5.0
            self.sim.step(t)
            self.engine.tick(t)
            test.observe(self.engine, t)
        return test.report(self.engine, t)

    def test_leader_outage(self):
        r = self.run_test("leader_outage", LEADER, 120)
        self.assertEqual((r["leader_before"], r["leader_now"]), (0, 5))
        self.assertGreaterEqual(r["leader_changed_after"], 30)
        self.assertEqual((r["partition_before"], r["partition_now"]), (0x1A2B3C4D, 0x1A2B3C4E))
        self.assertEqual(r["version_now"], 8)
        self.assertEqual(r["children"][0]["status"], "moved")

    def test_only_the_leader_for_the_leader_test(self):
        with self.assertRaises(ValueError):
            self.make_test("leader_outage", self.engine, ROUTER9, self.t0)
        with self.assertRaises(ValueError):
            self.make_test("br_outage", self.engine, ROUTER9, self.t0)
        with self.assertRaises(ValueError):
            self.make_test("router_outage", self.engine, None, self.t0)
        with self.assertRaises(ValueError):
            self.make_test("nonsense", self.engine, ROUTER9, self.t0)

    def test_border_router_outage(self):
        r = self.run_test("br_outage", "c8d1d1fffe000005", 60)
        self.assertEqual(r["br_before"], ["c8d1d1fffe000005"])
        self.assertEqual(r["br_now"], [])
        self.assertGreaterEqual(r["br_lost_after"], 20)

    def test_partition_and_merge(self):
        r = self.run_test("partition", ROUTER9, 330)               # router 22 hangs on router 9 alone
        self.assertEqual(r["partitions_max"], 2)
        self.assertGreaterEqual(r["split_after"], 30)
        self.assertGreater(r["merged_after"], r["split_after"])  # after the router came back
        self.assertEqual(r["partitions_now"], 1)

    def test_router_upgrade(self):
        r = self.run_test("router_upgrade", ROUTER17, 70)
        self.assertEqual([(x["id"], x["rloc16"]) for x in r["new_routers"]], [("a4c138fffe100003", "0x7800")])
        self.assertGreaterEqual(r["new_routers"][0]["after"], 45)

    def test_router_comes_back(self):
        r = self.run_test("router_return", ROUTER17, 150)
        self.assertTrue(r["on_at_start"])
        self.assertIsNotNone(r["silent_after"])
        self.assertGreaterEqual(r["back_after"], 90)
        self.assertIsNotNone(r["adv_after"])
        self.assertTrue(r["same_id"])

    def test_device_rejoin(self):
        r = self.run_test("device_rejoin", WINDOW, 60)
        self.assertEqual(r["status"], "back")
        self.assertLess(r["searched_after"], r["attached_after"])
        self.assertEqual((r["requests"], r["parent_before"], r["parent_now"]), (2, 9, 9))
        with self.assertRaises(ValueError):
            self.make_test("device_rejoin", self.engine, ROUTER9, self.t0)

    def test_commissioning(self):
        r = self.run_test("commissioning", None, 60)
        d = r["devices"]
        self.assertEqual([x["id"] for x in d], ["a4c138fffe1000aa"])
        self.assertEqual((d[0]["discovery_after"], d[0]["searched_after"], d[0]["attached_after"], d[0]["parent"]), (15.0, 20.0, 25.0, 0))
        self.assertEqual(r["discoveries"], 1)

    def test_the_api_starts_any_kind(self):
        c = Controller(self.engine, "run", "nrf:/dev/null", tshark="definitely-not-installed")
        self.addCleanup(c.stop_capture)
        self.assertEqual(c.start_test("commissioning", None)["running"]["kind"], "commissioning")
        c.stop_test()
        self.assertEqual(c.tests()["past"][0]["kind"], "commissioning")
