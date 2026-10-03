import unittest

from thread_tree.ek import FIELDS, Handler, resolve_fields
from thread_tree.engine import Engine

T_MS = 10 * 86400 * 1000


def pkt(offset_ms, **layers):
    return {"timestamp": str(T_MS + offset_ms), "layers": layers}


def handler(engine=None, fields=None):
    e = engine or Engine()
    return e, Handler(e, fields or {k: v[0] for k, v in FIELDS.items()})


class FieldTests(unittest.TestCase):
    def test_fields_come_from_the_wireshark_reference(self):
        self.assertEqual(FIELDS["rssi"], ["wpan-tap.rss"])
        self.assertEqual(FIELDS["lqi"], ["wpan-tap.lqi"])
        self.assertEqual(FIELDS["seq"], ["wpan.seq_no"])
        self.assertEqual(FIELDS["frame_type"], ["wpan.frame_type"])

    def test_missing_tap_fields_only_disable_the_signal_statistics(self):
        with self.assertLogs("thread_tree.ek", level="WARNING") as logs:
            chosen = resolve_fields({"wpan.src64", "wpan.src16", "frame.len"})
        self.assertNotIn("rssi", chosen)
        self.assertIn("frame_len", chosen)
        self.assertTrue(any("'rssi'" in line for line in logs.output))  # the user is told what is missing


class FrameStatisticsTests(unittest.TestCase):
    def test_signal_and_size_from_tap_fields(self):
        e, h = handler()
        h.handle(pkt(0, wpan_src64=["aa:aa:aa:aa:aa:aa:aa:aa"], wpan_src16=["0x0400"], **{"wpan-tap_rss": ["-71"]},
                     **{"wpan-tap_lqi": ["180"], "wpan-tap_length": ["28"]}, frame_len=["88"]))
        node = e.nodes["aa" * 8]
        s = node.stats.summary(T_MS / 1000 + 1)
        self.assertEqual((s["frames"], s["bytes"]), (1, 60))  # 88 captured - 28 TAP header
        self.assertEqual((s["rssi"]["last"], s["lqi"]["last"]), (-71, 180))

    def test_size_without_tap_header_length(self):
        e, h = handler()
        h.handle(pkt(0, wpan_src16=["0x0400"], frame_len=["60"]))
        self.assertEqual(e.nodes["rloc16:0400"].stats.bytes, 60)

    def test_kinds(self):
        e, h = handler()
        src = {"wpan_src64": ["aa:aa:aa:aa:aa:aa:aa:aa"]}
        h.handle(pkt(0, mle_cmd=["4"], **src))                           # advertisement
        h.handle(pkt(1000, mle_cmd=["11"], **src))                       # other MLE
        h.handle(pkt(2000, wpan_cmd=["4"], wpan_dst16=["0x0400"], **src))  # data poll
        h.handle(pkt(3000, wpan_cmd=["7"], **src))                       # other MAC command
        h.handle(pkt(4000, **src))                                       # data
        h.handle(pkt(5000, mle_no_key=[], **src))                        # MLE that could not be decrypted
        h.handle(pkt(6000, wpan_frame_type=["0x0000"], **src))           # beacon
        self.assertEqual(e.nodes["aa" * 8].stats.kinds,
                         {"adv": 1, "mle": 2, "poll": 1, "cmd": 1, "data": 1, "beacon": 1})

    def test_acks_have_no_transmitter_and_count_for_the_capture_only(self):
        e, h = handler()
        h.handle(pkt(0, wpan_frame_type=["0x0002"], frame_len=["33"]))
        h.handle(pkt(10, frame_len=["33"]))  # no frame type field at all, no addresses: still an ACK
        self.assertEqual(e.nodes, {})
        self.assertEqual(e.capture.kinds, {"ack": 2})

    def test_retransmissions_are_detected_by_sequence_number(self):
        e, h = handler()
        base = dict(wpan_src16=["0x0400"], wpan_dst16=["0x0800"], wpan_seq_no=["17"])
        h.handle(pkt(0, **base))
        h.handle(pkt(8, **base))          # repeated after 8 ms
        h.handle(pkt(30, **base))         # and again
        h.handle(pkt(1000, **{**base, "wpan_seq_no": ["18"]}))
        s = e.nodes["rloc16:0400"].stats
        self.assertEqual((s.frames, s.retries), (4, 2))

    def test_addressed_counter_uses_frame_size(self):
        e, h = handler()
        h.handle(pkt(0, wpan_src16=["0x0400"], wpan_dst64=["bb:bb:bb:bb:bb:bb:bb:bb"], frame_len=["50"]))
        n = e.nodes["bb" * 8]
        self.assertEqual((n.stats.addressed, n.stats.addressed_bytes, n.stats.frames), (1, 50, 0))

    def test_unfiltered_ek_names_work_too(self):
        e, h = handler()
        h.handle(pkt(0, wpan_wpan_src16=["0x0400"], wpan_wpan_seq_no=["3"], frame_frame_len=["40"]))
        self.assertEqual(e.nodes["rloc16:0400"].stats.frames, 1)

    def test_garbage_values_do_not_break_the_handler(self):
        e, h = handler()
        h.handle(pkt(0, wpan_src16=["0x0400"], **{"wpan-tap_rss": ["n/a"], "wpan-tap_lqi": [""]}, frame_len=["x"],
                     wpan_seq_no=["?"]))
        s = e.nodes["rloc16:0400"].stats
        self.assertEqual((s.frames, s.rssi_n, s.bytes), (1, 0, 0))


if __name__ == "__main__":
    unittest.main()
