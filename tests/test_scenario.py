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
        self.assertEqual((report["router_rloc16"], report["summary"]["children"]), ("0x2400", 1))
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
        self.assertEqual(result["past"][0]["router"], ROUTER17)
        self.assertIsNone(self.engine.demo_outage)
        stored = json.loads((Path(self.tmp.name) / "s.json").read_text())["tests"]
        self.assertEqual(stored[0]["router_rloc16"], "0x4400")
        again = Controller(Engine(), "demo", editable=False, settings_path=Path(self.tmp.name) / "s.json")
        self.assertEqual(again.tests()["past"][0]["router"], ROUTER17)  # kept across restarts

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
        self.assertEqual(json.loads(data)["running"]["router_rloc16"], "0x0400")
        self.assertEqual(self.post("/api/tests/router-outage", json.dumps({"router": "aa" * 8}))[0], 409)
        self.assertEqual(json.loads(self.call("GET", "/api/tests")[1])["running"]["router"], "aa" * 8)
        status, data = self.post("/api/tests/stop")
        self.assertEqual((status, json.loads(data)["running"]), (200, None))

    def test_bad_requests_and_guards(self):
        self.assertEqual(self.post("/api/tests/router-outage", "{}")[0], 400)
        self.assertEqual(self.post("/api/tests/router-outage", json.dumps({"router": "nope"}))[0], 400)
        self.assertEqual(self.post("/api/tests/router-outage", json.dumps({"router": "aa" * 8}), Origin="http://evil.example")[0], 403)
        self.assertEqual(self.post("/api/tests/stop")[0], 409)


if __name__ == "__main__":
    unittest.main()
