import http.client
import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from thread_tree.engine import Engine
from thread_tree.runtime import ConfigLocked, Controller
from thread_tree.server import host_name, is_loopback, make_server, may_write

KEY = "00112233445566778899aabbccddeeff"


def tlv(t, value: bytes) -> bytes:
    return bytes([t, len(value)]) + value


def dataset_hex(channel=17, key=KEY) -> str:
    return (tlv(0, bytes([0]) + channel.to_bytes(2, "big")) + tlv(1, bytes.fromhex("0551"))
            + tlv(2, bytes.fromhex("dead00beef00cafe")) + tlv(3, b"MyThread")
            + tlv(5, bytes.fromhex(key)) + tlv(7, bytes.fromhex("fd12345678900001"))).hex()


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "t.sqlite.dataset"
        self.engine = Engine()

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, **kw):
        c = Controller(self.engine, "run", kw.pop("source", "nrf:/dev/null"), dataset_path=self.path,
                       tshark="definitely-not-installed", **kw)
        self.addCleanup(c.stop_capture)
        return c

    def test_waits_for_dataset_then_starts_with_its_channel(self):
        c = self.make()
        c.start_capture()
        self.assertTrue(c.status()["waiting_for_dataset"])
        self.assertFalse(c.status()["decrypting"])
        cfg = c.set_dataset(dataset_hex(channel=17))
        self.assertEqual(cfg["dataset"]["channel"], 17)
        self.assertEqual(cfg["dataset"]["pan_id"], "0x0551")
        self.assertTrue(cfg["key_set"])
        self.assertFalse(c.status()["waiting_for_dataset"])
        self.assertEqual(self.engine.ml_prefix, 0xFD12345678900001)

    def test_key_is_never_in_config_or_status(self):
        c = self.make()
        c.set_dataset(dataset_hex())
        blob = json.dumps(c.config()) + json.dumps(c.status())
        self.assertNotIn(KEY, blob)

    def test_stored_privately_and_reloaded(self):
        c = self.make()
        c.set_dataset(dataset_hex())
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)
        c2 = self.make()
        self.assertEqual(c2.config()["dataset"]["network_name"], "MyThread")
        self.assertEqual(c2.config()["dataset"]["origin"], "ui")

    def test_invalid_input_changes_nothing(self):
        c = self.make()
        for bad in ("zz", "0508aabb", dataset_hex(channel=30), dataset_hex()[:-4]):
            with self.assertRaises(ValueError):
                c.set_dataset(bad)
        self.assertFalse(self.path.exists())
        self.assertIsNone(c.config()["dataset"])
        with self.assertRaises(ValueError):  # valid TLVs but no network key
            c.set_dataset(tlv(0, bytes([0, 0, 17])).hex())

    def test_clear(self):
        c = self.make()
        c.set_dataset(dataset_hex())
        c.clear_dataset()
        self.assertFalse(self.path.exists())
        self.assertIsNone(c.config()["dataset"])

    def test_cli_dataset_locks_the_form(self):
        c = self.make(cli_dataset=dataset_hex())
        self.assertFalse(c.config()["editable"])
        with self.assertRaises(ConfigLocked):
            c.set_dataset(dataset_hex(channel=20))
        with self.assertRaises(ConfigLocked):
            c.clear_dataset()


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.engine = Engine()
        cls.controller = Controller(cls.engine, "run", "nrf:/dev/null",
                                    dataset_path=Path(cls.tmp.name) / "d", tshark="definitely-not-installed")
        cls.server = make_server(cls.engine, "127.0.0.1", 0, cls.controller)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.controller.stop_capture()
        cls.tmp.cleanup()

    def call(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hdrs = {"Host": f"localhost:{self.port}", **(headers or {})}
        conn.request(method, path, body=body, headers=hdrs)
        res = conn.getresponse()
        data = res.read()
        return res.status, data

    def post(self, value, **headers):
        h = {"Content-Type": "application/json", **headers}
        return self.call("POST", "/api/config/dataset", json.dumps({"dataset": value}), h)

    def test_set_and_get(self):
        status, data = self.post(dataset_hex())
        self.assertEqual(status, 200)
        self.assertNotIn(KEY.encode(), data)
        status, data = self.call("GET", "/api/config")
        self.assertEqual(json.loads(data)["dataset"]["channel"], 17)
        self.assertNotIn(KEY.encode(), data)
        status, data = self.call("GET", "/api/status")
        self.assertNotIn(KEY.encode(), data)

    def test_rejects_wrong_content_type(self):
        status, _ = self.call("POST", "/api/config/dataset", json.dumps({"dataset": dataset_hex()}),
                              {"Content-Type": "text/plain"})
        self.assertEqual(status, 415)

    def test_rejects_foreign_host_and_origin(self):
        status, _ = self.call("GET", "/api/config", headers={"Host": "evil.example:80"})
        self.assertEqual(status, 403)  # loopback-bound server: rebinding names are refused everywhere
        status, _ = self.post(dataset_hex(), Host="evil.example:80")
        self.assertEqual(status, 403)
        status, _ = self.post(dataset_hex(), Origin="http://evil.example")
        self.assertEqual(status, 403)
        status, _ = self.post(dataset_hex(), Origin=f"http://localhost:{self.port}")
        self.assertEqual(status, 200)

    def test_bad_dataset_is_400(self):
        status, data = self.post("nothex")
        self.assertEqual(status, 400)
        self.assertIn(b"error", data)

    def test_static_and_traversal(self):
        self.assertEqual(self.call("GET", "/")[0], 200)
        self.assertEqual(self.call("GET", "/../runtime.py")[0], 404)


class AccessRuleTests(unittest.TestCase):
    def test_host_name(self):
        self.assertEqual(host_name("localhost:8787"), "localhost")
        self.assertEqual(host_name("[::1]:8787"), "::1")
        self.assertEqual(host_name("192.168.1.5"), "192.168.1.5")
        self.assertEqual(host_name(None), "")

    def test_loopback_detection(self):
        for ip in ("127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"):
            self.assertTrue(is_loopback(ip), ip)
        for ip in ("0.0.0.0", "::", "192.168.1.5", "example.org"):
            self.assertFalse(is_loopback(ip), ip)

    def test_who_may_write(self):
        self.assertTrue(may_write("127.0.0.1", "localhost:8787", False))      # SSH tunnel
        self.assertTrue(may_write("::1", "[::1]:8787", False))
        self.assertFalse(may_write("192.168.1.20", "raspberrypi:8787", False))  # LAN client
        self.assertFalse(may_write("127.0.0.1", "evil.example:8787", False))    # DNS rebinding
        self.assertFalse(may_write("192.168.1.20", "localhost:8787", False))    # spoofed Host
        self.assertTrue(may_write("192.168.1.20", "raspberrypi:8787", True))    # default: remote entry allowed


if __name__ == "__main__":
    unittest.main()
