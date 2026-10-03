"""Behaviour of sleepy devices at the sniffer: poll rhythm, gaps, parent searches (synthetic sniffer data)."""
import csv
import io
import tempfile
import unittest
from pathlib import Path

from test_ek_stats import T_MS, handler, pkt
from thread_tree import behavior as B
from thread_tree.diagnose import nodes_csv, node_diagnostics, report
from thread_tree.engine import Engine
from thread_tree.store import Store

T0 = T_MS / 1000
SLEEPY, ROUTER, OTHER = "a4c138fffe100009", "c8d1d1fffe000009", "c8d1d1fffe000001"
CAPTURE = {"running": True, "stats": {}}


def never_down(start, end):
    return False


class RhythmTests(unittest.TestCase):
    def test_the_usual_interval_needs_a_few_polls(self):
        b = {}
        for i in range(5):
            self.assertIsNone(B.on_poll(b, 100.0 + 30 * i, never_down))
        self.assertIsNone(B.usual_interval(b))                       # 4 intervals
        B.on_poll(b, 250.0, never_down)
        self.assertEqual(B.usual_interval(b), 30.0)

    def test_a_gap_is_several_usual_intervals_and_does_not_spoil_the_rhythm(self):
        b = {}
        for i in range(8):
            B.on_poll(b, 30.0 * i, never_down)
        self.assertIsNone(B.on_poll(b, 210.0 + 100, never_down))      # 100 s: less than 4 x 30 s
        self.assertEqual(B.on_poll(b, 310.0 + 400, never_down), {"seconds": 400, "usual": 30.0})
        self.assertNotIn(400.0, b["intervals"])
        self.assertEqual(B.usual_interval(b), 30.0)

    def test_short_rhythms_need_a_real_gap_too(self):
        b = {}
        for i in range(8):
            B.on_poll(b, 4.0 * i, never_down)
        self.assertIsNone(B.on_poll(b, 28.0 + 20, never_down))        # 20 s is 5 x 4 s, but not 30 s longer
        self.assertIsNotNone(B.on_poll(b, 48.0 + 40, never_down))

    def test_bursts_do_not_define_the_rhythm(self):
        b = {}
        for i in range(8):
            B.on_poll(b, 30.0 * i, never_down)
            B.on_poll(b, 30.0 * i + 0.1, never_down)                  # fast poll right after
        self.assertEqual(B.usual_interval(b), 29.9)

    def test_no_gap_while_the_sniffer_heard_nothing(self):
        b = {}
        for i in range(8):
            B.on_poll(b, 30.0 * i, never_down)
        self.assertIsNone(B.on_poll(b, 210.0 + 600, lambda s, e: True))

    def test_a_search_is_one_episode(self):
        b = {}
        self.assertTrue(B.on_parent_request(b, 10.0))
        self.assertFalse(B.on_parent_request(b, 11.0))
        self.assertFalse(B.on_parent_request(b, 100.0))
        self.assertEqual(B.on_attach_request(b, 103.0), {"seconds": 93, "requests": 3})
        self.assertIsNone(B.on_attach_request(b, 104.0))              # nothing to end
        self.assertTrue(B.on_parent_request(b, 500.0))                # a new search


class Net:
    """A sleepy device and a router the sniffer keeps hearing."""

    def __init__(self):
        self.e = Engine()
        self.sleepy = self.e.on_frame(T0, SLEEPY, 0x2401)
        self.other = self.e.on_frame(T0, OTHER, 0x0000)

    def poll(self, ts, seq=None):
        self.e.record_frame(ts, self.sleepy, "poll", 12, -70, 150, seq, "2400")

    def chatter(self, start, end, step=20.0):
        t = start
        while t <= end:
            self.e.record_frame(t, self.other, "adv", 60, -60, 150, None, "ffff")
            t += step

    def regular(self, n=10, every=30.0, start=T0):
        for i in range(n):
            self.poll(start + every * i)
        return start + every * (n - 1)

    def gaps(self):
        return [ev["params"] for ev in self.sleepy.events if ev["kind"] == "poll_gap"]


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.t = Net()
        self.e, self.sleepy = self.t.e, self.t.sleepy
        self.poll, self.chatter, self.regular, self.gaps = self.t.poll, self.t.chatter, self.t.regular, self.t.gaps

    def test_a_gap_while_others_are_heard_is_logged(self):
        self.e.on_child_timeout(T0, self.sleepy, 240)
        last = self.regular()
        self.chatter(last, last + 300)
        self.poll(last + 300)
        self.assertEqual(self.gaps(), [{"timeout": 240, "seconds": 300, "usual": 30.0}])

    def test_no_gap_when_the_sniffer_was_deaf(self):
        last = self.regular()
        self.chatter(last - 60, last)                      # then nothing at all for 10 minutes
        self.poll(last + 600)
        self.assertEqual(self.gaps(), [])

    def test_retransmitted_polls_are_not_part_of_the_rhythm(self):
        for i in range(10):
            self.poll(T0 + 30 * i, seq=i)
            self.poll(T0 + 30 * i + 0.01, seq=i)           # repeated: same sequence number
        self.assertEqual(B.usual_interval(self.sleepy.behavior), 30.0)

    def test_parent_search_and_attach(self):
        router = self.e.on_frame(T0, ROUTER, 0x2400)
        self.e.on_parent_request(T0 + 10, self.sleepy)
        self.e.on_parent_request(T0 + 12, self.sleepy)
        self.e.on_attach_request(T0 + 15, self.sleepy, router)
        kinds = [(ev["kind"], ev["params"]) for ev in self.sleepy.events if ev["kind"] in ("parent_search", "attached")]
        self.assertEqual(kinds, [("parent_search", {"parent": 9}), ("attached", {"to": 9, "seconds": 5, "requests": 2})])

    def test_everything_survives_a_restart(self):
        self.e.on_child_timeout(T0, self.sleepy, 240)
        self.regular()
        self.e.on_parent_request(T0 + 400, self.sleepy)
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.sqlite")
            store.save(self.e.export_state(clear_dirty=True))
            e2 = Engine()
            e2.load_state(store.load())
        n = e2.nodes[SLEEPY]
        self.assertEqual((n.child_timeout, B.usual_interval(n.behavior)), (240, 30.0))
        self.assertEqual(n.behavior["search"]["count"], 1)


class SnifferInputTests(unittest.TestCase):
    """The same through the tshark EK adapter."""

    def test_parent_request_child_id_request_and_timeout(self):
        e, h = handler()
        h.handle(pkt(0, wpan_src64=[":".join([ROUTER[i:i + 2] for i in range(0, 16, 2)])], wpan_src16=["0x2400"], mle_cmd=["4"]))
        child = {"wpan_src64": [":".join([SLEEPY[i:i + 2] for i in range(0, 16, 2)])]}
        h.handle(pkt(1000, mle_cmd=["9"], wpan_dst16=["0xffff"], **child))
        h.handle(pkt(3000, mle_cmd=["9"], wpan_dst16=["0xffff"], **child))
        h.handle(pkt(6000, mle_cmd=["11"], mle_tlv_timeout=["240"], wpan_dst64=[":".join([ROUTER[i:i + 2] for i in range(0, 16, 2)])],
                     mle_tlv_mode_device_type=["0"], mle_tlv_mode_idle_rx=["0"], **child))
        n = e.nodes[SLEEPY]
        self.assertEqual(n.child_timeout, 240)
        self.assertEqual([ev["kind"] for ev in n.events if ev["kind"] in ("parent_search", "attached")], ["parent_search", "attached"])
        attached = next(ev for ev in n.events if ev["kind"] == "attached")["params"]
        self.assertEqual(attached, {"to": 9, "seconds": 5, "requests": 2})

    def test_data_requests_make_the_rhythm(self):
        e, h = handler()
        child = {"wpan_src64": [":".join([SLEEPY[i:i + 2] for i in range(0, 16, 2)])]}
        for i in range(8):
            h.handle(pkt(30000 * i, wpan_cmd=["4"], wpan_dst16=["0x2400"], wpan_seq_no=[str(i)], **child))
        self.assertEqual(B.usual_interval(e.nodes[SLEEPY].behavior), 30.0)


class FindingTests(unittest.TestCase):
    def setUp(self):
        self.t = Net()
        self.e = self.t.e

    def codes(self, now):
        snap, analysis = report(self.e, now, CAPTURE)
        return {f["code"]: f for f in analysis["nodes"][SLEEPY]["findings"]}, snap, analysis

    def test_one_short_gap_is_a_note_one_beyond_the_timeout_a_warning(self):
        self.e.on_child_timeout(T0, self.t.sleepy, 240)
        last = self.t.regular()
        self.t.chatter(last, last + 200)
        self.t.poll(last + 200)
        f = self.codes(last + 201)[0]["poll_gaps"]
        self.assertEqual((f["severity"], f["params"]["count"], f["params"]["longest"]), ("info", 1, 200))
        self.t.chatter(last + 200, last + 600)
        self.t.poll(last + 600)
        f = self.codes(last + 601)[0]["poll_gaps"]
        self.assertEqual((f["severity"], f["params"]["count"], f["params"]["longest"]), ("warn", 2, 400))

    def test_searches(self):
        for i in range(3):
            self.e.on_parent_request(T0 + 1000 * i, self.t.sleepy)
        f = self.codes(T0 + 3000)[0]["parent_searches"]
        self.assertEqual((f["severity"], f["params"]), ("warn", {"count": 3}))

    def test_polling_close_to_the_timeout_is_not_conform(self):
        self.e.on_child_timeout(T0, self.t.sleepy, 30)
        self.t.regular(every=28.0)
        f = self.codes(T0 + 300)[0]["poll_vs_timeout"]
        self.assertEqual(f["params"], {"usual": 28.0, "timeout": 30})

    def test_silent_right_now_while_the_sniffer_hears_others(self):
        last = self.t.regular()
        self.t.chatter(last, last + 500)
        codes, _, _ = self.codes(last + 500)
        self.assertEqual(codes["silent_now"]["params"]["seconds"], 500)
        codes, _, _ = self.codes(last + 5000)              # the sniffer itself stopped: no claim about the device
        self.assertNotIn("silent_now", codes)

    def test_device_page_and_csv(self):
        self.e.on_child_timeout(T0, self.t.sleepy, 240)
        last = self.t.regular()
        snap, analysis = report(self.e, last + 1, CAPTURE)
        d = node_diagnostics(self.e, snap, analysis, SLEEPY, last + 1)
        self.assertEqual((d["behavior"]["usual"], d["behavior"]["timeout"], d["behavior"]["gaps_24h"]), (30.0, 240, 0))
        self.assertEqual(d["behavior"]["last_poll"], last)
        rows = {r["mac"].replace(":", ""): r for r in csv.DictReader(io.StringIO(nodes_csv(self.e, snap, analysis, last + 1)))}
        self.assertEqual((rows[SLEEPY]["poll_usual_s"], rows[SLEEPY]["child_timeout_s"]), ("30.0", "240"))
        self.assertEqual(rows[OTHER]["poll_usual_s"], "")
        self.assertIsNone(node_diagnostics(self.e, snap, analysis, OTHER, last + 1)["behavior"])


if __name__ == "__main__":
    unittest.main()
