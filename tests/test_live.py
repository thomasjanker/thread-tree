"""The live view: recent frames and the state of the capture."""
import io
import json
import tempfile
import time
import unittest
from pathlib import Path

from test_collector import wait_for
from test_config import KEY, ApiFixture, dataset_hex
from thread_tree.capture import CaptureThread
from thread_tree.engine import Engine
from thread_tree.runtime import Controller

T_MS = 10 * 86400 * 1000


def ek_lines():
    pkts = [
        {"timestamp": str(T_MS), "layers": {"wpan_src64": ["aa:aa:aa:aa:aa:aa:aa:aa"], "wpan_src16": ["0x0400"], "mle_cmd": ["4"],
                                             "wpan_dst16": ["0xffff"], "wpan-tap_rss": ["-71"], "frame_len": ["60"]}},
        {"timestamp": str(T_MS + 1000), "layers": {"wpan_src64": ["bb:bb:bb:bb:bb:bb:bb:bb"], "wpan_cmd": ["4"], "wpan_dst16": ["0x0400"],
                                                    "wpan_seq_no": ["7"]}},
        {"timestamp": str(T_MS + 1001), "layers": {"wpan_src64": ["bb:bb:bb:bb:bb:bb:bb:bb"], "wpan_cmd": ["4"], "wpan_dst16": ["0x0400"],
                                                    "wpan_seq_no": ["7"]}},
        {"timestamp": str(T_MS + 2000), "layers": {"wpan_src16": ["0x0400"], "mle_decrypt_failed": []}},
    ]
    return "".join(json.dumps({"index": {}}) + "\n" + json.dumps(p) + "\n" for p in pkts)


class LiveTests(unittest.TestCase):
    def test_frames_and_capture_state(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cap.ek"
            path.write_text(ek_lines())
            c = Controller(Engine(), "run", f"ek:{path}", cli_dataset=dataset_hex(channel=17))
            self.addCleanup(c.stop_capture)
            c.start_capture()
            self.assertTrue(wait_for(lambda: c.capture.finished.is_set()))
            live = c.live()
        frames = live["frames"]
        self.assertEqual([f["seq"] for f in frames], [1, 2, 3, 4])
        first = frames[0]
        self.assertEqual((first["src"], first["kind"], first["mle"], first["rssi"], first["dst16"], first["decrypt"]),
                         ("aa" * 8, "adv", 4, -71, "0xffff", "ok"))
        self.assertEqual((frames[1]["kind"], frames[1]["retry"], frames[2]["retry"]), ("poll", False, True))
        self.assertEqual(frames[3]["decrypt"], "failed")
        self.assertEqual((live["capture"]["channel"], live["capture"]["source"], live["capture"]["per_minute"]), (17, "ek", 4))
        self.assertEqual(live["capture"]["stats"]["mle_failed"], 1)
        self.assertEqual(c.live(since=3)["frames"][0]["seq"], 4)
        self.assertNotIn(KEY, json.dumps(live))

    def test_messages_never_show_the_key(self):
        cap = CaptureThread(Engine(), "cmd:true", network_key=KEY)
        cap._collect(io.BytesIO(f"tshark: invalid option uat:ieee802154_keys:\"{KEY}\"\nSniffer device /dev/ttyACM1 was disconnected.\n".encode()), "tshark")
        texts = [m["text"] for m in cap.messages]
        self.assertEqual(len(texts), 2)
        self.assertNotIn(KEY, " ".join(texts))
        self.assertIn("disconnected", texts[1])

    def test_without_a_capture(self):
        c = Controller(Engine(), "run", "auto", tshark="definitely-not-installed")
        live = c.live()
        self.assertEqual((live["frames"], live["seq"], live["capture"]["running"]), ([], 0, False))


class LiveApiTests(ApiFixture, unittest.TestCase):
    def test_endpoint(self):
        status, data = self.call("GET", "/api/live?since=0")
        self.assertEqual(status, 200)
        self.assertIn("capture", json.loads(data))
        self.assertEqual(self.call("GET", "/api/live?since=x")[0], 400)
