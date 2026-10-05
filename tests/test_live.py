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


def handler():
    from thread_tree.ek import FIELDS, Handler
    engine = Engine()
    return engine, Handler(engine, {k: v[0] for k, v in FIELDS.items()})


def pkt(ms, **layers):
    return {"timestamp": str(T_MS + ms), "layers": {k: v if isinstance(v, list) else [v] for k, v in layers.items()}}


def lladdr(ext):
    from thread_tree import addresses as A
    return str(A.link_local_from_ext(ext.replace(":", "")))


class FrameDetailTests(unittest.TestCase):
    def test_poll_answered_with_frame_pending(self):
        engine, h = handler()
        h.handle(pkt(0, wpan_src64="bb:bb:bb:bb:bb:bb:bb:bb", wpan_cmd="4", wpan_dst16="0x0400", wpan_seq_no="9", frame_number="1"))
        h.handle(pkt(5, wpan_frame_type="2", wpan_seq_no="9", wpan_pending="1", frame_number="2"))
        h.handle(pkt(1000, wpan_src64="bb:bb:bb:bb:bb:bb:bb:bb", wpan_cmd="4", wpan_dst16="0x0400", wpan_seq_no="10"))
        h.handle(pkt(1005, wpan_frame_type="2", wpan_seq_no="10", wpan_pending="0"))
        ack = h.recent[1]
        self.assertEqual((ack["no"], ack["answers"], ack["flags"]["pending"]), (2, "bb" * 8, True))
        self.assertEqual(engine.nodes["bb" * 8].behavior["polls_acked"], [2, 1])

    def test_mesh_header_counts_forwarding(self):
        engine, h = handler()
        for ext, short in (("aa:aa:aa:aa:aa:aa:aa:aa", "0x0400"), ("cc:cc:cc:cc:cc:cc:cc:cc", "0x0800")):
            h.handle(pkt(0, wpan_src64=ext, wpan_src16=short, mle_cmd="4"))
        h.handle(pkt(100, wpan_src16="0x0400", wpan_dst16="0x0c00", **{"6lowpan_mesh_orig16": "0x0800", "6lowpan_mesh_dest16": "0x1000",
                                                                         "6lowpan_mesh_hops": "13"}))
        h.handle(pkt(200, wpan_src16="0x0800", wpan_dst16="0x0400", **{"6lowpan_mesh_orig16": "0x0800", "6lowpan_mesh_dest16": "0x1000"}))
        self.assertEqual(h.recent[-2]["mesh"], {"orig": "cc" * 8, "dest": "0x1000", "hops": 13})
        self.assertEqual(engine.nodes["aa" * 8].behavior["forwarded"], 1)
        self.assertEqual(engine.nodes["cc" * 8].behavior["multihop"], 1)

    def test_matter_router_id_and_srp(self):
        engine, h = handler()
        a, b = "aa:aa:aa:aa:aa:aa:aa:aa", "dd:dd:dd:dd:dd:dd:dd:dd"
        h.handle(pkt(0, wpan_src64=b, mle_cmd="9"))
        h.handle(pkt(10, wpan_src64=a, ipv6_src=lladdr(a), ipv6_dst=lladdr(b), udp_srcport="5540", udp_dstport="5540", udp_length="80"))
        h.handle(pkt(20, wpan_src64=a, ipv6_src=lladdr(a), ipv6_dst="fd00::fc00", udp_srcport="61631", udp_dstport="61631",
                     coap_opt_uri_path=["a", "as"], coap_code="2"))
        h.handle(pkt(30, wpan_src64=a, ipv6_src=lladdr(a), udp_srcport="49152", udp_dstport="53535",
                     dns_qry_name="default.service.arpa", dns_resp_name=["lamp.default.service.arpa", "Lamp._matter._tcp.default.service.arpa"]))
        matter = h.recent[1]
        self.assertEqual((matter["proto"], matter["udp"]), ("matter", {"src": 5540, "dst": 5540, "len": 80}))
        self.assertEqual(engine.nodes["aa" * 8].behavior["matter"]["out"], 1)
        self.assertEqual(engine.nodes["dd" * 8].behavior["matter"]["in"], 1)
        self.assertEqual((h.recent[2]["proto"], h.recent[2]["uri"], h.recent[2]["coap"]), ("tmf", "/a/as", 2))
        self.assertTrue(any(ev["kind"] == "router_id" and ev["params"]["what"] == "request" for ev in engine.nodes["aa" * 8].events))
        srp = engine.nodes["aa" * 8].behavior["srp"]
        self.assertEqual((srp["host"], srp["services"]), ("lamp", ["Lamp._matter._tcp.default.service.arpa"]))


def pcap(records):
    import struct
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 195)
    for i, data in enumerate(records):
        out += struct.pack("<IIII", i, 0, len(data), len(data)) + data
    return out


class Sink(io.BytesIO):
    def close(self):
        self.kept = self.getvalue()
        super().close()


class RawFrameTests(unittest.TestCase):
    def test_pump_passes_everything_and_keeps_frames(self):
        stream = pcap([b"\x01\x02", b"\x03\x04\x05"])
        cap, sink = CaptureThread(Engine(), "cmd:true"), Sink()
        cap._pump(io.BytesIO(stream), sink)
        self.assertEqual(sink.kept, stream)
        self.assertEqual([(n, len(r)) for n, r in cap.raw], [(1, 18), (2, 19)])
        self.assertEqual(cap.pcap_header, stream[:24])

    def test_pcapng_is_passed_through(self):
        stream = b"\x0a\x0d\x0d\x0a" + bytes(60)
        cap, sink = CaptureThread(Engine(), "cmd:true"), Sink()
        cap._pump(io.BytesIO(stream), sink)
        self.assertEqual((sink.kept, len(cap.raw)), (stream, 0))

    def test_decode_removes_the_key(self):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "tshark"
            layers = {"frame": {"frame.number": "1"}, "wpan": {"wpan.aux_sec.key_id_mode": "1", "wpan.key_number": KEY},
                      "mle": {"mle.tlv.network_key": KEY.upper(), "mle.note": f"uses {KEY}"}}
            fake.write_text("#!/bin/sh\ncat > /dev/null\necho '" + json.dumps([{"_source": {"layers": layers}}]) + "'\n")
            fake.chmod(0o755)
            cap = CaptureThread(Engine(), "cmd:true", network_key=KEY, tshark=str(fake))
            cap._pump(io.BytesIO(pcap([b"\x01\x02"])), Sink())
            decoded = cap.decode(1)
            self.assertIsNone(cap.decode(7))
        self.assertNotIn(KEY.lower(), json.dumps(decoded).lower())
        self.assertEqual(decoded["wpan"]["wpan.aux_sec.key_id_mode"], "1")
        self.assertEqual(decoded["frame"]["frame.number"], "1")

    def test_frame_endpoint_without_raw_frames(self):
        c = Controller(Engine(), "run", "auto", tshark="definitely-not-installed")
        self.assertIsNone(c.live_frame(1))
