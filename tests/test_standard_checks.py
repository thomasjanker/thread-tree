"""Checks against the Thread standard (sniffer), the network events, and the log."""
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from test_config import ApiFixture
from test_ek_stats import T_MS, handler, pkt
from thread_tree import behavior as B
from thread_tree.diagnose import report
from thread_tree.engine import NETWORK_ID, Engine
from thread_tree.eventlog import entries, log_csv, severity
from thread_tree.simulate import populate
from thread_tree.store import Store

T0 = T_MS / 1000
CHILD, R5, R9, OTHER = "a4c138fffe100009", "c8d1d1fffe000005", "c8d1d1fffe000009", "c8d1d1fffe000001"
CAPTURE = {"running": True, "stats": {}}


def mac(ext):
    return ":".join(ext[i:i + 2] for i in range(0, 16, 2))


def never(start, end):
    return False


class RuleTests(unittest.TestCase):
    def test_parent_choice(self):
        self.assertIsNone(B.judge_choice({"offers": {"5": 20, "9": 25}}, 5))           # 5 dB: fine
        self.assertEqual(B.judge_choice({"offers": {"5": 12, "9": 28}}, 5),
                         {"chosen": 5, "best": 9, "chosen_margin": 12, "best_margin": 28})
        self.assertIsNone(B.judge_choice({"offers": {"5": 12}}, 5))                    # only one offer
        self.assertIsNone(B.judge_choice({"offers": {"5": 12, "9": 28}}, 7))           # chose one we did not see

    def test_frame_counter(self):
        b = {}
        self.assertIsNone(B.on_frame_counter(b, 0, 5000, 1))
        self.assertIsNone(B.on_frame_counter(b, 10, 5003, 1))
        self.assertEqual(B.on_frame_counter(b, 20, 3, 1), {"how": "reset", "from": 5003, "to": 3})
        self.assertIsNone(B.on_frame_counter(b, 30, 10, 2))                           # new key: counting starts again
        self.assertEqual(B.on_frame_counter(b, 60, 1100, 2)["how"], "skip")          # restart: stored counter ahead
        self.assertIsNone(B.on_frame_counter(b, 5000, 2500, 2))                      # a long silence: frames were sent

    def test_advertisement_gaps(self):
        b = {}
        B.on_advertisement(b, 0, never)
        self.assertIsNone(B.on_advertisement(b, 60, never))
        self.assertEqual(B.on_advertisement(b, 200, never), {"seconds": 140})
        self.assertIsNone(B.on_advertisement(b, 2000, never))                        # it was off: offline, not timing
        self.assertIsNone(B.on_advertisement(b, 2150, lambda s, e: True))            # the sniffer was deaf

    def test_supervision(self):
        b = {"supervision": 120}
        B.on_addressed(b, 0, never)
        self.assertIsNone(B.on_addressed(b, 170, never))
        self.assertEqual(B.on_addressed(b, 400, never), {"seconds": 230, "interval": 120})
        self.assertIsNone(B.on_addressed({}, 0, never) or B.on_addressed({}, 999, never))  # no interval known

    def test_version_wraps(self):
        self.assertTrue(B.serial_newer(1, 255))
        self.assertFalse(B.serial_newer(255, 1))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.e = Engine()
        self.r5 = self.e.on_frame(T0, R5, 0x1400)
        self.r9 = self.e.on_frame(T0, R9, 0x2400)
        self.child = self.e.on_frame(T0, CHILD, None)

    def kinds(self, node):
        return [(ev["kind"], ev["params"]) for ev in node.events if ev["kind"] not in ("first_seen", "parent_search", "attached")]

    def test_a_weaker_parent_and_an_unanswered_attach(self):
        self.e.on_parent_request(T0 + 1, self.child)
        self.e.on_parent_response(T0 + 2, self.r5, CHILD, 12)
        self.e.on_parent_response(T0 + 2, self.r9, CHILD, 30)
        self.e.on_attach_request(T0 + 3, self.child, self.r5)
        self.e.on_parent_request(T0 + 20, self.child)                 # no Child ID Response came: searching again
        self.assertEqual(self.kinds(self.child), [
            ("parent_choice", {"chosen": 5, "best": 9, "chosen_margin": 12, "best_margin": 30}),
            ("attach_unanswered", {"router": 5})])
        self.e.on_attach_request(T0 + 22, self.child, self.r9)
        self.e.on_address_assignment(T0 + 23, CHILD, 0x2401)          # answered
        self.e.on_parent_request(T0 + 400, self.child)
        self.assertEqual(len([k for k in self.kinds(self.child) if k[0] == "attach_unanswered"]), 1)

    def test_restart_from_the_frame_counter(self):
        self.e.on_frame_counter(T0, self.child, 900, 1)
        self.e.on_frame_counter(T0 + 30, self.child, 2, 1)
        self.assertEqual(self.kinds(self.child), [("reboot", {"how": "reset", "from": 900, "to": 2})])

    def test_old_network_data_and_network_events(self):
        e = self.e
        e.on_leader_data(T0, self.r5, 77, 0, 10)
        e.on_leader_data(T0, self.r9, 77, 0, 10)
        e.on_leader_data(T0 + 5, self.r5, 77, 0, 11)                  # new version
        e.on_leader_data(T0 + 60, self.r9, 77, 0, 10)                 # router 9 keeps the old one ...
        e.on_leader_data(T0 + 130, self.r9, 77, 0, 10)                # ... for more than 2 minutes
        e.on_leader_data(T0 + 140, self.r9, 77, 0, 10)                # logged once
        self.assertEqual([k for k in self.kinds(self.r9) if k[0] == "netdata_lag"],
                         [("netdata_lag", {"version": 10, "current": 11, "seconds": 125})])
        e.on_leader_data(T0 + 150, self.r5, 77, 9)                    # another leader
        e.on_leader_data(T0 + 160, self.r5, 88, 5)                    # a second partition
        net = [(ev["kind"], ev["params"]) for ev in e.net_events]
        self.assertEqual(net, [("netdata_version", {"partition": 77, "version": 11}),
                               ("leader_change", {"partition": 77, "from": 0, "to": 9}),
                               ("partition_new", {"partition": 88, "leader": 5})])

    def test_split_merge_routers_and_border_routers(self):
        e = self.e
        e.on_leader_data(T0, self.r5, 77, 5)
        e.on_network_data(T0, {0x1400}, complete=True)
        e.tick(T0)
        e.on_leader_data(T0 + 10, self.r9, 88, 9)                     # two partitions at once
        e.on_frame(T0 + 10, R5, 0x1400)
        e.tick(T0 + 11)
        e.on_network_data(T0 + 20, set(), complete=True)              # the border router is gone
        for t in range(30, 120, 10):                                  # partition 88 stops, 77 goes on
            e.on_leader_data(T0 + t, self.r5, 77, 5)
        e.tick(T0 + 120)
        kinds = [(ev["kind"], ev["params"].get("count"), ev["params"].get("removed")) for ev in e.net_events]
        self.assertIn(("partitions", 2, None), kinds)
        self.assertIn(("partitions", 1, None), kinds)
        self.assertIn(("br_change", None, [R5]), kinds)

    def test_network_events_survive_a_restart_and_a_rebuild(self):
        self.e._net_log(T0, "routers", count=3, before=2)
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.sqlite")
            store.save(self.e.export_state(clear_dirty=True))
            store.maintain(T0 + 10)
            e2 = Engine()
            e2.load_state(store.load())
        self.assertEqual([ev["kind"] for ev in e2.net_events], ["routers"])
        e2.reset_topology()
        self.assertEqual(len(e2.net_events), 1)


class SnifferInputTests(unittest.TestCase):
    def test_parent_response_frame_counter_and_supervision(self):
        e, h = handler()
        h.handle(pkt(0, wpan_src64=[mac(R5)], wpan_src16=["0x1400"], mle_cmd=["4"]))
        h.handle(pkt(0, wpan_src64=[mac(R9)], wpan_src16=["0x2400"], mle_cmd=["4"]))
        child = {"wpan_src64": [mac(CHILD)]}
        h.handle(pkt(1000, mle_cmd=["9"], wpan_dst16=["0xffff"], **child))
        h.handle(pkt(1500, wpan_src64=[mac(R5)], mle_cmd=["10"], mle_tlv_link_margin=["12"], wpan_dst64=[mac(CHILD)]))
        h.handle(pkt(1600, wpan_src64=[mac(R9)], mle_cmd=["10"], mle_tlv_link_margin=["30"], wpan_dst64=[mac(CHILD)]))
        h.handle(pkt(2000, mle_cmd=["11"], mle_tlv_supervision_interval=["129"], wpan_dst64=[mac(R5)], **child))
        h.handle(pkt(3000, wpan_aux_sec_frame_counter=["500"], wpan_aux_sec_key_index=["1"], **child))
        h.handle(pkt(4000, wpan_aux_sec_frame_counter=["3"], wpan_aux_sec_key_index=["1"], **child))
        n = e.nodes[CHILD]
        self.assertEqual(n.behavior["supervision"], 129)
        self.assertEqual([ev["kind"] for ev in n.events if ev["kind"] in ("parent_choice", "reboot")], ["parent_choice", "reboot"])


class FindingAndLogTests(unittest.TestCase):
    def setUp(self):
        self.e = Engine()
        populate(self.e, now=T0, history=True)
        self.e.tick(T0)
        _, self.a = report(self.e, T0 + 1, CAPTURE)

    def codes(self, nid):
        return {f["code"]: f for f in self.a["nodes"][nid]["findings"]}

    def test_the_demo_shows_every_check(self):
        self.assertEqual(self.codes("a4c138fffe100002")["reboots"]["params"]["count"], 1)
        self.assertEqual(self.codes("a4c138fffe100005")["parent_choice"]["params"]["best_margin"], 28)
        self.assertEqual(self.codes("a4c138fffe100004")["supervision_missed"]["params"]["interval"], 129)
        self.assertEqual(self.codes("c8d1d1fffe000011")["adv_gaps"]["severity"], "warn")
        self.assertEqual(self.codes("c8d1d1fffe000011")["attach_rejected"]["params"]["count"], 1)
        self.assertIn("netdata_lag", self.codes("c8d1d1fffe000016"))

    def test_busy_sleepy_device(self):
        node = self.e.nodes["a4c138fffe100002"]
        for i in range(3000):                                          # every 1.1 s instead of every 4 s
            self.e.record_frame(T0 - 3400 + i * 1.1, node, "poll", 12, -70, 150, None, "1400")
        _, a = report(self.e, T0 + 1, CAPTURE)
        f = {x["code"]: x for x in a["nodes"]["a4c138fffe100002"]["findings"]}["busy_sleepy"]
        self.assertGreaterEqual(f["params"]["per_hour"], 3 * f["params"]["median"])

    def test_log_entries_and_severities(self):
        rows = entries(self.e)
        self.assertEqual(rows, sorted(rows, key=lambda r: r["ts"], reverse=True))
        warn = entries(self.e, "warn")
        self.assertTrue(warn and all(r["severity"] == "warn" for r in warn))
        self.assertIn("reboot", {r["kind"] for r in warn})
        self.assertIn(None, {r["node"] for r in rows})                                # network events are in it
        self.assertEqual(severity("poll_gap", {"seconds": 420, "timeout": 240}), "warn")
        self.assertEqual(severity("poll_gap", {"seconds": 60, "timeout": 240}), "info")
        self.assertEqual(severity("partitions", {"count": 2}), "warn")
        self.assertEqual(severity("routers", {"count": 4, "before": 5}), "warn")
        self.assertEqual(severity("online", {}), "info")

    def test_csv(self):
        self.e.set_name("a4c138fffe100002", "=Door")
        rows = list(csv.DictReader(io.StringIO(log_csv(self.e, "warn"))))
        door = next(r for r in rows if r["event"] == "reboot")
        self.assertEqual((door["name"], door["severity"], json.loads(door["details"])["how"]), ("'=Door", "warn", "skip"))


class LogApiTests(ApiFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        node = cls.engine.on_frame(1000.0, "aa" * 8, 0x0400)
        cls.engine._log(node, 1001.0, "reboot", how="reset", **{"from": 9, "to": 1})
        cls.engine._net_log(1002.0, "routers", count=1, before=0)

    def test_log_and_filter(self):
        data = json.loads(self.call("GET", "/api/log")[1])["entries"]
        self.assertEqual([e["kind"] for e in data][:2], ["routers", "reboot"])
        warn = json.loads(self.call("GET", "/api/log?level=warn")[1])["entries"]
        self.assertEqual([e["kind"] for e in warn], ["reboot"])
        self.assertEqual(self.call("GET", "/api/log?limit=x")[0], 400)

    def test_csv_export(self):
        status, body = self.call("GET", "/api/export/log.csv?level=warn")
        self.assertEqual(status, 200)
        self.assertEqual(len(body.decode().strip().splitlines()), 2)
