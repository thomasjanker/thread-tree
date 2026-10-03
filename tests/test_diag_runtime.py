"""Active diagnostics wired into the application: Controller, the 'query now' endpoint, cancelling a running query."""
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from test_collector import ML_PREFIX, RecordedStick, Stick, wait_for
from test_config import KEY, ApiFixture, dataset_hex
from thread_tree.dataset import normalize_hex
from thread_tree.engine import Engine
from thread_tree.otcli import OtCli, OtCliCancelled
from thread_tree.runtime import Controller, DiagUnavailable
from thread_tree.simulate import populate

FAST = {"join_timeout": 5.0, "poll": 0.01, "retry_delay": 0.05}   # the stick of these tests joins at once


class HangingStick(RecordedStick):
    """Never answers the topology query (until released), like a network that does not respond."""

    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self.release = threading.Event()

    def reply(self, cmd):
        if cmd.startswith("meshdiag topology"):
            self.release.wait(30)
        return super().reply(cmd)


class ControllerDiagTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.engine = Engine()

    def make(self, stick, **kw):
        c = Controller(self.engine, "run", "nrf:/dev/null", dataset_path=Path(self.tmp.name) / "t.sqlite.dataset",
                       tshark="definitely-not-installed", diag_port=stick.port, diag_interval=30.0, diag_options=FAST, **kw)
        self.addCleanup(c.stop_capture)
        self.addCleanup(c.stop_diagnostics)
        return c

    def rounds(self):
        return self.engine.diag_info.get("ts")

    def test_joins_with_the_dataset_entered_in_the_ui_and_never_reveals_it(self):
        text = dataset_hex(channel=17)
        with Stick() as stick:
            c = self.make(stick)
            c.set_dataset(text.upper())                    # the form may deliver capitals
            c.start_diagnostics()
            self.assertTrue(wait_for(self.rounds))
            sent = [r for r in stick.fake.received if r.startswith("dataset set active")]
            everything = json.dumps(c.config()) + json.dumps(c.status()) + repr(self.engine.diag_info)
            enabled = c.status()["diagnostics"]
        self.assertEqual(sent, ["dataset set active " + normalize_hex(text)])
        self.assertNotIn(KEY, everything)
        self.assertNotIn(text, everything)
        self.assertTrue(enabled)

    def test_without_a_dataset_it_waits_then_joins_when_one_arrives_and_waits_again_when_it_is_removed(self):
        with Stick() as stick:
            c = self.make(stick)
            c.start_diagnostics()
            self.assertTrue(wait_for(lambda: self.engine.diag_info.get("state") == "waiting for dataset"))
            self.assertEqual(stick.fake.received, [])      # the port is not even opened for nothing
            c.set_dataset(dataset_hex())
            self.assertTrue(wait_for(self.rounds))
            c.clear_dataset()
            self.assertTrue(wait_for(lambda: self.engine.diag_info.get("state") == "waiting for dataset"))
            self.assertIsNone(self.rounds())               # the answers of the old network are not shown as current

    def test_the_dataset_of_the_command_line_is_used_too(self):
        text = dataset_hex(channel=15)
        with Stick() as stick:
            c = Controller(self.engine, "run", "nrf:/dev/null", cli_dataset=text, tshark="definitely-not-installed",
                           diag_port=stick.port, diag_interval=30.0, diag_options=FAST)
            self.addCleanup(c.stop_capture)
            self.addCleanup(c.stop_diagnostics)
            c.start_diagnostics()
            self.assertTrue(wait_for(self.rounds))
            sent = [r for r in stick.fake.received if r.startswith("dataset set active")]
        self.assertEqual(sent, ["dataset set active " + text])

    def test_a_stored_dataset_is_used_after_a_restart(self):
        text = dataset_hex()
        first = Controller(Engine(), "run", "nrf:/dev/null", dataset_path=Path(self.tmp.name) / "t.sqlite.dataset",
                           tshark="definitely-not-installed")
        self.addCleanup(first.stop_capture)
        first.set_dataset(text)
        with Stick() as stick:
            c = self.make(stick)                           # a new process reads the file
            c.start_diagnostics()
            self.assertTrue(wait_for(self.rounds))
            sent = [r for r in stick.fake.received if r.startswith("dataset set active")]
        self.assertEqual(sent, ["dataset set active " + text])

    def test_query_now_runs_another_round(self):
        with Stick() as stick:
            c = self.make(stick)
            c.set_dataset(dataset_hex())
            c.start_diagnostics()
            self.assertTrue(wait_for(self.rounds))
            first = self.rounds()
            self.assertEqual(c.run_diagnostics(), {"queued": True})
            self.assertTrue(wait_for(lambda: self.rounds() != first))   # the interval is 30 s: this was the trigger

    def test_rebuilding_the_tree_asks_again_at_once(self):
        with Stick() as stick:
            c = self.make(stick)
            c.set_dataset(dataset_hex())
            c.start_diagnostics()
            self.assertTrue(wait_for(lambda: len(self.engine.nodes) == 11))
            first = self.rounds()
            c.rebuild_topology()
            self.assertTrue(wait_for(lambda: self.rounds() != first and len(self.engine.nodes) == 11))

    def test_stopping_does_not_wait_for_a_query_in_progress(self):
        with Stick(HangingStick) as stick:
            c = self.make(stick)
            c.set_dataset(dataset_hex())
            c.start_diagnostics()
            self.assertTrue(wait_for(lambda: any(r.startswith("meshdiag topology") for r in stick.fake.received)))
            started = time.monotonic()
            c.stop_diagnostics()
            took = time.monotonic() - started
            stick.fake.release.set()
        self.assertLess(took, 3.0)                         # it was waiting for up to 90 s
        self.assertIsNone(c.diag)
        self.assertEqual(self.engine.diag_info, {})

    def test_without_a_port_there_is_nothing_to_query(self):
        c = Controller(self.engine, "run", "nrf:/dev/null", tshark="definitely-not-installed")
        self.addCleanup(c.stop_capture)
        c.start_diagnostics()
        self.assertIsNone(c.diag)
        self.assertFalse(c.status()["diagnostics"])
        with self.assertRaises(DiagUnavailable):
            c.run_diagnostics()
        c.set_dataset(dataset_hex())                       # a dataset alone does not start anything either
        self.assertIsNone(c.diag)

    def test_a_missing_stick_is_reported_and_retried(self):
        c = Controller(self.engine, "run", "nrf:/dev/null", cli_dataset=dataset_hex(), tshark="definitely-not-installed",
                       diag_port="/dev/does-not-exist", diag_interval=30.0, diag_options=FAST)
        self.addCleanup(c.stop_capture)
        self.addCleanup(c.stop_diagnostics)
        c.start_diagnostics()
        self.assertTrue(wait_for(lambda: self.engine.diag_info.get("state") == "error"))
        self.assertIn("does-not-exist", self.engine.diag_info["error"])
        self.assertIn("does-not-exist", c.status()["diagnostics_error"])        # the UI shows it as a banner

    def test_no_error_in_the_status_while_it_works(self):
        with Stick() as stick:
            c = self.make(stick)
            c.set_dataset(dataset_hex())
            c.start_diagnostics()
            self.assertTrue(wait_for(self.rounds))
            self.assertIsNone(c.status()["diagnostics_error"])


class SwitchTests(unittest.TestCase):
    """The UI switch: off = the stick stays in the network but asks nothing; kept across restarts."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.engine = Engine()
        self.settings = Path(self.tmp.name) / "t.sqlite.settings.json"

    def make(self, stick, engine=None):
        c = Controller(engine or self.engine, "run", "nrf:/dev/null", cli_dataset=dataset_hex(), tshark="definitely-not-installed",
                       diag_port=stick.port, diag_interval=30.0, diag_options=FAST, settings_path=self.settings)
        self.addCleanup(c.stop_capture)
        self.addCleanup(c.stop_diagnostics)
        return c

    def test_switched_off_it_stays_joined_and_asks_nothing_then_asks_at_once_when_switched_on(self):
        with Stick() as stick:
            c = self.make(stick)
            c.start_diagnostics()
            self.assertTrue(wait_for(lambda: self.engine.diag_info.get("ts")))
            joined = len(stick.fake.received)
            c.set_diag_enabled(False)
            self.assertTrue(wait_for(lambda: self.engine.diag_info.get("state") == "paused"))
            time.sleep(0.3)
            later = stick.fake.received[joined:]
            self.assertFalse([r for r in later if r.startswith(("meshdiag", "networkdiagnostic", "thread stop"))])
            with self.assertRaises(DiagUnavailable):
                c.run_diagnostics()
            self.assertTrue(c.status()["diagnostics_paused"])
            first = self.engine.diag_info["ts"]
            c.set_diag_enabled(True)
            self.assertTrue(wait_for(lambda: self.engine.diag_info.get("ts") != first))
            self.assertFalse(c.status()["diagnostics_paused"])

    def test_the_switch_survives_a_restart(self):
        with Stick() as stick:
            c = self.make(stick)
            c.start_diagnostics()
            c.set_diag_enabled(False)
            c.stop_diagnostics()
            engine = Engine()
            again = self.make(stick, engine)
            self.assertTrue(again.diag_paused)
            again.start_diagnostics()
            self.assertTrue(wait_for(lambda: engine.diag_info.get("state") == "paused"))
            self.assertIsNone(engine.diag_info.get("ts"))             # it joined, but did not ask
        self.assertEqual(json.loads(self.settings.read_text()), {"diag_paused": True})

    def test_without_a_stick_there_is_nothing_to_switch(self):
        c = Controller(self.engine, "run", "nrf:/dev/null", tshark="definitely-not-installed", settings_path=self.settings)
        self.addCleanup(c.stop_capture)
        with self.assertRaises(DiagUnavailable):
            c.set_diag_enabled(False)
        self.assertFalse(self.settings.exists())

    def test_the_demo_stops_its_simulated_rounds(self):
        from thread_tree.simulate import Simulator
        populate(self.engine, now=1000.0, active=True)
        c = Controller(self.engine, "demo", editable=False, locked_reason="demo", settings_path=self.settings)
        c.set_diag_enabled(False)
        self.assertEqual(self.engine.diag_info["state"], "paused")
        sim = Simulator(self.engine)
        for i in range(1, 30):
            sim.step(1000.0 + 5 * i)
        self.assertEqual(self.engine.diag_info["ts"], 1000.0)
        restarted = Controller(Engine(), "demo", editable=False, locked_reason="demo", settings_path=self.settings)
        self.assertEqual(restarted.engine.diag_info.get("state"), "paused")
        c.set_diag_enabled(True)
        self.assertAlmostEqual(self.engine.diag_info["ts"], time.time(), delta=5)


class DemoControllerTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()
        populate(self.engine, now=1000.0, history=True, active=True)
        self.controller = Controller(self.engine, "demo", editable=False, locked_reason="demo", allow_remote_config=True)

    def test_the_demo_always_has_diagnostics_and_query_now_refreshes_them(self):
        self.assertTrue(self.controller.status()["diagnostics"])
        self.assertEqual(self.engine.diag_info["ts"], 1000.0)
        self.assertEqual(self.controller.run_diagnostics(), {"queued": True})
        self.assertAlmostEqual(self.engine.diag_info["ts"], time.time(), delta=5)

    def test_rebuilding_the_demo_brings_the_active_data_back(self):
        self.controller.rebuild_topology()
        self.assertTrue(self.engine.nodes)
        self.assertTrue(self.engine.diag_info["demo"])
        self.assertTrue(self.engine.link_metrics)
        self.assertTrue(any(n.vendor for n in self.engine.nodes.values()))


class RunNowApiTests(ApiFixture, unittest.TestCase):
    class Stub:
        calls = 0

        def trigger(self):
            self.calls += 1

    def setUp(self):
        self.stub = self.Stub()

    def tearDown(self):
        self.controller.diag = None

    def run_now(self, body="{}", **headers):
        return self.call("POST", "/api/diagnostics/run", body, {"Content-Type": "application/json", **headers})

    def test_without_a_diagnostic_node_it_is_a_conflict(self):
        status, data = self.run_now()
        self.assertEqual(status, 409)
        self.assertIn("--diag-port", json.loads(data)["error"])

    def test_asks_for_a_round(self):
        self.controller.diag = self.stub
        status, data = self.run_now()
        self.assertEqual((status, json.loads(data), self.stub.calls), (200, {"queued": True}, 1))

    def test_guards(self):
        self.controller.diag = self.stub
        self.assertEqual(self.run_now(Origin="http://evil.example")[0], 403)
        self.assertEqual(self.run_now(Host="evil.example:80")[0], 403)
        self.assertEqual(self.call("POST", "/api/diagnostics/run", "{}", {"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.run_now("[]")[0], 400)
        self.assertEqual(self.stub.calls, 0)

    def test_the_switch_endpoint(self):
        calls = []
        self.stub.set_paused = calls.append
        def post(body, **headers):
            return self.call("POST", "/api/diagnostics/enabled", body, {"Content-Type": "application/json", **headers})
        self.assertEqual(post('{"enabled": false}')[0], 409)        # no stick
        self.controller.diag = self.stub
        self.addCleanup(setattr, self.controller, "diag_paused", False)
        status, data = post('{"enabled": false}')
        self.assertEqual((status, json.loads(data), calls), (200, {"enabled": False}, [True]))
        self.assertEqual(self.run_now()[0], 409)                      # switched off: no "ask now"
        self.assertEqual(post('{"enabled": "no"}')[0], 400)
        self.assertEqual(post('{"enabled": true}', Origin="http://evil.example")[0], 403)
        self.assertEqual(self.call("POST", "/api/diagnostics/enabled", '{"enabled": true}', {"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(post('{"enabled": true}')[0], 200)
        self.assertEqual(calls, [True, False])

    def test_the_status_says_whether_there_is_one(self):
        self.assertFalse(json.loads(self.call("GET", "/api/status")[1])["diagnostics"])
        self.controller.diag = self.stub
        self.assertTrue(json.loads(self.call("GET", "/api/status")[1])["diagnostics"])


class CancelTests(unittest.TestCase):
    def test_a_running_command_stops_when_cancelled(self):
        with Stick(HangingStick) as stick:
            cli = OtCli(stick.port).open()
            self.addCleanup(cli.close)
            cli.cancel = threading.Event()
            threading.Timer(0.3, cli.cancel.set).start()
            started = time.monotonic()
            with self.assertRaises(OtCliCancelled):
                cli.command("meshdiag topology ip6-addrs children", timeout=60)
            self.assertLess(time.monotonic() - started, 3.0)
            stick.fake.release.set()

    def test_cancelled_before_it_starts(self):
        with Stick() as stick:
            cli = OtCli(stick.port).open()
            self.addCleanup(cli.close)
            cli.cancel = threading.Event()
            cli.cancel.set()
            with self.assertRaises(OtCliCancelled):
                cli.command("state")
            self.assertEqual(stick.fake.received, [])      # it did not even send the command


if __name__ == "__main__":
    unittest.main()
