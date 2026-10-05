"""Finding the sticks by their USB identity, and using whichever is plugged in (also later)."""
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from test_collector import Stick, wait_for
from test_config import dataset_hex
from thread_tree import sticks
from thread_tree.collector import DiagThread
from thread_tree.engine import Engine
from thread_tree.runtime import Controller


def fake_sys(root: Path, devices: list[tuple[str, str, str, str]], by_id: dict[str, str] | None = None):
    """devices: (tty, idVendor, idProduct, product) as Linux sysfs shows them."""
    (root / "sys/class/tty").mkdir(parents=True)
    (root / "dev/serial/by-id").mkdir(parents=True)
    for i, (tty, vendor, product_id, product) in enumerate(devices):
        usb = root / f"sys/devices/usb1/1-{i}"
        iface = usb / f"1-{i}:1.0"
        (iface / "tty" / tty).mkdir(parents=True)
        for name, value in (("idVendor", vendor), ("idProduct", product_id), ("product", product)):
            (usb / name).write_text(value + "\n")
        os.symlink(iface / "tty" / tty, root / "sys/class/tty" / tty)
        os.symlink(iface, iface / "tty" / tty / "device")
        (root / "dev" / tty).touch()
    for name, tty in (by_id or {}).items():
        os.symlink(f"../../{tty}", root / "dev/serial/by-id" / name)
    return {"sys_root": root / "sys", "dev_root": root / "dev"}


class FindTests(unittest.TestCase):
    def test_both_kinds_and_a_stable_name(self):
        with tempfile.TemporaryDirectory() as d:
            roots = fake_sys(Path(d), [("ttyACM0", "1915", "cafe", "nRF528xx OpenThread Device"),
                                       ("ttyACM1", "1915", "154b", "nRF 802154 Sniffer"),
                                       ("ttyUSB0", "0403", "6001", "FT232R")],
                             by_id={"usb-Nordic_Semiconductor_nRF528xx_OpenThread_Device_C3-if00": "ttyACM0"})
            found = {s["tty"].rsplit("/", 1)[1]: s for s in sticks.find_sticks(**roots)}
            self.assertEqual((found["ttyACM0"]["kind"], found["ttyACM1"]["kind"], found["ttyUSB0"]["kind"]), ("diag", "sniffer", None))
            self.assertTrue(found["ttyACM0"]["path"].endswith("OpenThread_Device_C3-if00"))   # by-id preferred
            self.assertEqual(found["ttyACM1"]["path"], str(roots["dev_root"] / "ttyACM1"))   # the sniffer has none
            self.assertEqual(found["ttyACM1"]["usb"], "1915:154b")
            self.assertEqual(sticks.find("sniffer", **roots), str(roots["dev_root"] / "ttyACM1"))

    def test_nothing_plugged_in(self):
        with tempfile.TemporaryDirectory() as d:
            roots = fake_sys(Path(d), [])
            self.assertEqual((sticks.find_sticks(**roots), sticks.find("diag", **roots)), ([], None))
            self.assertEqual(sticks.find_sticks(sys_root=Path(d) / "nothing"), [])

    def test_by_product_name_too(self):
        self.assertEqual(sticks.classify({"idVendor": "1915", "idProduct": "9999", "product": "nRF 802154 Sniffer"}), "sniffer")
        self.assertEqual(sticks.classify({"idVendor": "2fe3", "idProduct": "0001", "product": "OpenThread CLI"}), "diag")
        self.assertIsNone(sticks.classify({"idVendor": "1915", "idProduct": "521f", "product": "Open DFU Bootloader"}))


class AutoSnifferTests(unittest.TestCase):
    def test_the_capture_starts_when_the_stick_appears(self):
        plugged = {"path": None}
        with mock.patch.object(sticks, "find", lambda kind, **_: plugged["path"] if kind == "sniffer" else None):
            c = Controller(Engine(), "run", "auto", cli_dataset=dataset_hex(channel=15), tshark="definitely-not-installed")
            self.addCleanup(c.stop_capture)
            with mock.patch.object(Controller, "_watch_sniffer", lambda self, every=10.0: None):
                c.start_capture()
            self.assertTrue(c.status()["waiting_for_sniffer"])
            self.assertFalse(c.status()["waiting_for_dataset"])
            self.assertIsNone(c.capture)
            plugged["path"] = "/dev/ttyACM1"
            c.start_capture()
            self.assertIsNotNone(c.capture)
            self.assertEqual(c.status()["sniffer"], "/dev/ttyACM1")
            self.assertIn("--extcap-interface /dev/ttyACM1", c.capture.source)
            self.assertIn("--channel 15", c.capture.source)
            self.assertFalse(c.status()["waiting_for_sniffer"])

    def test_the_watcher_restarts_after_unplugging(self):
        plugged = {"path": "/dev/ttyACM1"}
        with mock.patch.object(sticks, "find", lambda kind, **_: plugged["path"] if kind == "sniffer" else None):
            c = Controller(Engine(), "run", "auto", cli_dataset=dataset_hex(channel=15), tshark="definitely-not-installed")
            self.addCleanup(c.stop_capture)
            starts = []
            original = c.start_capture
            c.start_capture = lambda: (starts.append(1), original())
            with mock.patch.object(Controller, "_watch_sniffer", lambda self, every=10.0: None):
                original()                                   # tshark is missing here: the capture ends at once
            self.assertTrue(wait_for(lambda: c.capture.finished.is_set()))
            import threading
            threading.Thread(target=c._watch_sniffer, args=(0.05,), daemon=True).start()
            self.assertTrue(wait_for(lambda: len(starts) >= 2, 3))   # tries again while the stick is there
            plugged["path"] = None
            time.sleep(0.3)
            count = len(starts)
            time.sleep(0.3)
            self.assertEqual(len(starts), count)            # unplugged: nothing to start


class AutoDiagTests(unittest.TestCase):
    def test_nothing_shows_before_a_stick_turns_up_then_it_is_used(self):
        engine = Engine(ml_prefix=0xFDCAFE0000010001)
        with Stick() as stick:
            plugged = {"path": None}
            with mock.patch.object(sticks, "find", lambda kind, **_: plugged["path"] if kind == "diag" else None):
                thread = DiagThread(engine, "auto", "0e08" + "00" * 8 + "0510" + "11" * 16 + "0708fdcafe0000010001",
                                    interval=30.0, join_timeout=5.0, poll=0.01, retry_delay=0.05)
                thread._stop_evt.wait = lambda timeout=None: time.sleep(min(timeout or 0, 0.05)) or thread._stop_evt.is_set()
                thread.start()
                time.sleep(0.2)
                self.assertEqual((engine.diag_info, thread.found), ({}, False))
                plugged["path"] = stick.port                 # plugged in
                self.assertTrue(wait_for(lambda: engine.diag_info.get("ts")))
                self.assertEqual(thread.current_port, stick.port)
                thread.stop()
                thread.join(timeout=5)

    def test_off_means_no_active_diagnostics(self):
        from thread_tree.cli import _parser
        args = _parser().parse_args(["run"])
        self.assertEqual((args.source, args.diag_port), ("auto", "auto"))
        self.assertEqual(_parser().parse_args(["run", "--diag-port", "off"]).diag_port, "off")


class StatusTests(unittest.TestCase):
    def test_the_ui_learns_which_sticks_are_plugged_in_and_used(self):
        with tempfile.TemporaryDirectory() as d:
            roots = fake_sys(Path(d), [("ttyACM0", "1915", "cafe", "nRF528xx OpenThread Device"), ("ttyACM1", "1915", "154b", "nRF 802154 Sniffer")])
            real = sticks.find_sticks
            with mock.patch.object(sticks, "find_sticks", lambda **_: real(**roots)):
                c = Controller(Engine(), "run", "auto", tshark="definitely-not-installed")
                self.addCleanup(c.stop_capture)
                c.sniffer = str(roots["dev_root"] / "ttyACM1")
                status = c.status()
        kinds = {s["kind"]: s for s in status["sticks"]}
        self.assertTrue(kinds["sniffer"]["used"])
        self.assertFalse(kinds["diag"]["used"])              # no diagnostic node running in this test
        self.assertFalse(status["diagnostics"])


if __name__ == "__main__":
    unittest.main()
