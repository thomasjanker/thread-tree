"""DiagThread against a simulated stick (pseudo terminal) that answers with the recorded real output."""
import logging
import os
import pty
import threading
import time
import unittest

from fixture import Fixture
from test_config import KEY as UI_KEY, dataset_hex
from test_otcli import FakeCli
from thread_tree.collector import DiagThread
from thread_tree.engine import Engine
from thread_tree.otcli import OtCli, OtCliTimeout

logging.getLogger("thread_tree.collector").setLevel(logging.CRITICAL)  # the thread reports problems; keep the test output clean
F = Fixture()
DATASET = "0e08" + "00" * 8 + "0510" + "11" * 16 + "0708fdcafe0000010001"
KEY = "11" * 16
ML_PREFIX = 0xFDCAFE0000010001


OUR_NETWORK = {"networkname": "MyThread", "channel": "17", "panid": "0x0551", "extpanid": "dead00beef00cafe",
               "networkkey": UI_KEY}      # what a node says that is attached to the network of test_config.dataset_hex()


class RecordedStick(FakeCli):
    """Answers from the transcript; keeps track of joining like a real node."""

    def __init__(self, master, state="disabled", eligible=True, help_lines=None, dataset_error=None, attach_as="child",
                 vendor=None, network=None):
        super().__init__(master, commands=["help"])
        self.state, self.eligible, self.attach_as = state, eligible, attach_as
        self.help_lines, self.dataset_error, self.vendor, self.polls = help_lines, dataset_error, vendor, 0
        self.network = network or {}                 # what the node says about the network it is attached to

    def reply(self, cmd):
        if cmd in self.network:
            return [self.network[cmd]]
        if cmd == "help":
            return self.help_lines if self.help_lines is not None else F.lines("help")
        if cmd == "state":
            if self.state == "detached":
                self.polls += 1
                if self.polls >= 2:
                    self.state = self.attach_as
            return [self.state]
        if cmd == "routereligible":
            return ["Enabled" if self.eligible else "Disabled"]
        if cmd == "routereligible disable":
            self.eligible = False
            return []
        if cmd.startswith("dataset set active"):
            return [self.dataset_error] if self.dataset_error else []
        if cmd == "thread start":
            self.state, self.polls = "detached", 0
            return []
        if cmd == "thread stop":
            self.state = "disabled"
            return []
        if cmd.startswith("networkdiagnostic get"):
            return self.vendor or ["Error 28: ResponseTimeout"]
        if cmd in F.runs and cmd not in ("version", "help", "thread stop", "ifconfig down", "ifconfig up", "thread start"):
            return ["Error 28: ResponseTimeout"] if F.error(cmd) else F.lines(cmd)
        return [] if cmd in ("ifconfig down", "ifconfig up") else ["Error 35: InvalidCommand"]


class Stick:
    def __init__(self, stick_class=RecordedStick, **kw):
        self.master, self.slave = pty.openpty()
        self.port = os.ttyname(self.slave)
        self.fake = stick_class(self.master, **kw)

    def __enter__(self):
        self.fake.start()
        return self

    def __exit__(self, *exc):
        self.fake.stop()
        self.fake.join(timeout=2)
        os.close(self.master)
        os.close(self.slave)


def wait_for(condition, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.02)
    return False


def start(engine, stick, dataset_hex=DATASET, **kw):
    opts = dict(interval=30.0, join_timeout=5.0, poll=0.01, retry_delay=0.05)
    opts.update(kw)
    thread = DiagThread(engine, stick.port, dataset_hex, **opts)
    thread.start()
    return thread


def finish(thread):
    thread.stop()
    thread.join(timeout=5)
    assert not thread.is_alive()


class JoinAndRoundTests(unittest.TestCase):
    def test_joins_as_end_device_then_collects(self):
        engine = Engine(ml_prefix=ML_PREFIX)
        with Stick() as stick:
            thread = start(engine, stick)
            self.assertTrue(wait_for(lambda: engine.diag_info.get("ts")))
            finish(thread)
            received = stick.fake.received
        order = [c for c in received if c in ("thread stop", "ifconfig down", "routereligible disable", "ifconfig up", "thread start")
                 or c.startswith("dataset set active")]
        self.assertEqual([c.split(" <")[0].split(" 0e08")[0] for c in order],
                         ["thread stop", "ifconfig down", "routereligible disable", "dataset set active", "ifconfig up", "thread start"])
        info = engine.diag_info
        self.assertEqual((info["state"], info["routers"], info["children"], info["error"]), ("idle", 5, 6, None))
        self.assertEqual(info["failures"], {0x1400: "ResponseTimeout", 0xBC00: "ResponseTimeout"})
        self.assertEqual(engine.diag_self, F.lines("extaddr")[0])
        self.assertEqual(info["own_rloc16"], 0xA804)
        self.assertEqual(len(engine.nodes), 11)
        self.assertGreater(info["next"], info["ts"])

    def test_the_dataset_is_never_in_the_status(self):
        engine = Engine(ml_prefix=ML_PREFIX)
        with Stick(dataset_error="Error 7: InvalidArgs") as stick:
            thread = start(engine, stick)
            self.assertTrue(wait_for(lambda: engine.diag_info.get("state") == "error"))
            finish(thread)
        self.assertNotIn(KEY, repr(engine.diag_info))
        self.assertNotIn(DATASET, repr(engine.diag_info))
        self.assertIn("rejected the dataset", engine.diag_info["error"])

    def test_an_already_joined_end_device_is_not_disturbed(self):
        engine = Engine(ml_prefix=ML_PREFIX)
        with Stick(state="child", eligible=False) as stick:
            thread = start(engine, stick)
            self.assertTrue(wait_for(lambda: engine.diag_info.get("ts")))
            finish(thread)
            received = stick.fake.received
        self.assertNotIn("thread stop", received)
        self.assertFalse(any(c.startswith("dataset set active") for c in received))

    def test_a_node_on_another_network_is_moved_to_ours(self):
        for differs in ("networkname", "channel", "panid", "extpanid", "networkkey"):
            with self.subTest(differs=differs):
                engine = Engine(ml_prefix=ML_PREFIX)
                network = {**OUR_NETWORK, differs: "9" * 32 if differs == "networkkey" else "other"}
                with Stick(state="child", eligible=False, network=network) as stick:
                    thread = start(engine, stick, dataset_hex=dataset_hex(channel=17))
                    self.assertTrue(wait_for(lambda: engine.diag_info.get("ts")))
                    finish(thread)
                    received = stick.fake.received
                self.assertIn("thread stop", received)
                self.assertEqual(sum(c.startswith("dataset set active") for c in received), 1)
                self.assertNotIn("9" * 32, repr(engine.diag_info))

    def test_a_node_on_our_network_is_left_alone(self):
        engine = Engine(ml_prefix=ML_PREFIX)
        with Stick(state="child", eligible=False, network=OUR_NETWORK) as stick:
            thread = start(engine, stick, dataset_hex=dataset_hex(channel=17))
            self.assertTrue(wait_for(lambda: engine.diag_info.get("ts")))
            finish(thread)
            received = stick.fake.received
        self.assertNotIn("thread stop", received)
        self.assertFalse(any(c.startswith("dataset set active") for c in received))
        self.assertTrue({"networkname", "channel", "panid", "extpanid", "networkkey"} <= set(received))   # it did look

    def test_settings_that_cannot_be_read_count_as_equal(self):
        engine = Engine(ml_prefix=ML_PREFIX)
        readable = {k: v for k, v in OUR_NETWORK.items() if k != "networkkey"}   # a build that hides the key
        with Stick(state="child", eligible=False, network=readable) as stick:
            thread = start(engine, stick, dataset_hex=dataset_hex(channel=17))
            self.assertTrue(wait_for(lambda: engine.diag_info.get("ts")))
            finish(thread)
            received = stick.fake.received
        self.assertNotIn("thread stop", received)

    def test_a_node_that_may_become_a_router_is_reconfigured(self):
        engine = Engine(ml_prefix=ML_PREFIX)
        with Stick(state="child", eligible=True) as stick:
            thread = start(engine, stick)
            self.assertTrue(wait_for(lambda: engine.diag_info.get("ts")))
            finish(thread)
            received = stick.fake.received
        self.assertIn("routereligible disable", received)
        self.assertLess(received.index("routereligible disable"), received.index("thread start"))

    def test_attaching_as_router_is_refused(self):
        engine = Engine(ml_prefix=ML_PREFIX)
        with Stick(attach_as="router") as stick:
            thread = start(engine, stick)
            self.assertTrue(wait_for(lambda: engine.diag_info.get("state") == "error"))
            finish(thread)
            received = stick.fake.received
        self.assertIn("attached as router", engine.diag_info["error"])
        self.assertIn("thread stop", received[received.index("thread start"):])        # it was stopped again
        self.assertEqual(engine.nodes, {})                                              # nothing collected

    def test_firmware_without_meshdiag_says_so(self):
        engine = Engine(ml_prefix=ML_PREFIX)
        plain = [c for c in F.lines("help") if c != "meshdiag"]
        with Stick(help_lines=plain) as stick:
            thread = start(engine, stick)
            self.assertTrue(wait_for(lambda: engine.diag_info.get("state") == "error"))
            finish(thread)
        self.assertIn("no meshdiag", engine.diag_info["error"])

    def test_vendor_data_is_collected_when_devices_answer(self):
        engine = Engine(ml_prefix=ML_PREFIX)
        vendor = ["DIAG_GET.rsp/ans from x: 00", "Vendor Name: Example", "Vendor Model: Plug"]
        with Stick(vendor=vendor) as stick:
            thread = start(engine, stick)
            self.assertTrue(wait_for(lambda: engine.diag_info.get("ts")))
            finish(thread)
        self.assertEqual(sum(1 for n in engine.nodes.values() if n.vendor == {"name": "Example", "model": "Plug"}), 3)
        self.assertEqual(engine.diag_info["vendor"], 3)

    def test_trigger_starts_a_round_at_once(self):
        engine = Engine(ml_prefix=ML_PREFIX)
        with Stick(state="child", eligible=False) as stick:
            thread = start(engine, stick, interval=3600.0)
            self.assertTrue(wait_for(lambda: engine.diag_info.get("ts")))
            first = engine.diag_info["ts"]
            time.sleep(0.05)
            thread.trigger()
            self.assertTrue(wait_for(lambda: engine.diag_info.get("ts", 0) > first))
            finish(thread)
            self.assertGreaterEqual(stick.fake.received.count("leaderdata"), 2)


class FailureTests(unittest.TestCase):
    def test_without_a_dataset_nothing_is_opened(self):
        engine = Engine()
        opened = []
        thread = DiagThread(engine, "/dev/null-does-not-matter", None, open_cli=lambda p: opened.append(p) or None,
                            retry_delay=0.05)
        thread.start()
        self.assertTrue(wait_for(lambda: engine.diag_info.get("state") == "waiting for dataset"))
        finish(thread)
        self.assertEqual(opened, [])

    def test_a_missing_stick_is_retried_and_reported(self):
        engine = Engine()
        thread = DiagThread(engine, "/dev/serial/by-id/does-not-exist", DATASET, retry_delay=0.05)
        thread.start()
        self.assertTrue(wait_for(lambda: engine.diag_info.get("state") == "error"))
        self.assertIn("No such file", engine.diag_info["error"])
        self.assertTrue(thread.is_alive())                          # keeps trying
        finish(thread)

    def test_a_stick_that_goes_silent_is_reconnected(self):
        engine = Engine(ml_prefix=ML_PREFIX)
        sessions = []
        with Stick(state="child", eligible=False) as stick:
            def open_cli(port):
                cli = OtCli(port, timeout=1.0)
                if not sessions:                                    # the first session: the stick does not answer
                    cli.command = lambda *a, **k: (_ for _ in ()).throw(OtCliTimeout("no response"))
                sessions.append(cli)
                return cli
            thread = DiagThread(engine, stick.port, DATASET, interval=30.0, open_cli=open_cli, retry_delay=0.05,
                                join_timeout=3.0, poll=0.01)
            thread.start()
            self.assertTrue(wait_for(lambda: engine.diag_info.get("ts"), timeout=15))
            finish(thread)
        self.assertGreaterEqual(len(sessions), 2)
        self.assertIsNone(engine.diag_info["error"])                # the error of the first session is gone


if __name__ == "__main__":
    unittest.main()


class ChildMacTests(unittest.TestCase):
    """Children known only by their RLOC16 (their router does not answer the child table) are asked for their MAC."""

    def setUp(self):
        self.engine = Engine(ml_prefix=ML_PREFIX)
        with self.engine.lock:
            self.engine.node_for(1000.0, ext="a604009ec59510b2", rloc16=0x1400)
            self.engine.node_for(1000.0, rloc16=0x140A)  # heard by its short address only
        self.asked = []

    def run_cli(self, answer):
        def run(cmd, timeout=None):
            self.asked.append((cmd, timeout))
            if isinstance(answer, Exception):
                raise answer
            return answer
        return run

    def test_the_answer_gives_the_device_its_mac(self):
        from thread_tree.collector import _ask_macs
        answer = ["DIAG_GET.rsp/ans from fdca:fe00:0:1:0:ff:fe00:140a: 0008...", "Ext Address: '1a2b3c4d5e6f7081'", "Timeout: 240"]
        tried = {}
        self.assertEqual(_ask_macs(self.run_cli(answer), self.engine, 2000.0, tried, 2), 1)
        cmd, timeout = self.asked[0]
        self.assertTrue(cmd.startswith("networkdiagnostic get fdca:fe00:1:1:0:ff:fe00:140a 0 3"), cmd)
        self.assertGreaterEqual(timeout, 30)  # a sleepy child answers on its next poll
        node = self.engine.nodes["1a2b3c4d5e6f7081"]
        self.assertEqual((node.rloc16, node.child_timeout), (0x140A, 240))
        self.assertNotIn("rloc16:140a", self.engine.nodes)
        self.assertEqual(_ask_macs(self.run_cli(answer), self.engine, 2100.0, tried, 2), 0)  # known now: not asked again
        self.assertEqual(len(self.asked), 1)

    def test_no_answer_is_asked_again_later(self):
        from thread_tree.collector import MAC_RETRY, _ask_macs
        tried = {}
        _ask_macs(self.run_cli(OtCliTimeout("no answer")), self.engine, 2000.0, tried, 2)
        _ask_macs(self.run_cli(OtCliTimeout("no answer")), self.engine, 2300.0, tried, 2)
        self.assertEqual(len(self.asked), 1)
        _ask_macs(self.run_cli(OtCliTimeout("no answer")), self.engine, 2000.0 + MAC_RETRY + 1, tried, 2)
        self.assertEqual(len(self.asked), 2)
        self.assertIn("rloc16:140a", self.engine.nodes)
