import sqlite3
import tempfile
import unittest
from pathlib import Path

from thread_tree.engine import CAPTURE_ID, EVENTS_PER_NODE, Engine
from thread_tree.stats import BUCKET_SECONDS
from thread_tree.store import EVENT_RETENTION, Store

T = 10 * 86400.0


def kinds(node):
    return [e["kind"] for e in node.events]


class StatsInEngineTests(unittest.TestCase):
    def test_frame_and_destination_statistics(self):
        e = Engine()
        node = e.on_frame(T, "aa" * 8, 0x0400)
        e.record_frame(T, node, "adv", length=60, rssi=-70, lqi=200, seq=1, dst="ffff")
        e.record_frame(T + 1, None, "ack", length=5, rssi=-71)  # an ACK has no transmitter
        e.on_destination(T + 2, "aa" * 8, None, length=40)
        self.assertEqual((node.stats.frames, node.stats.addressed, node.stats.addressed_bytes), (1, 1, 40))
        self.assertEqual(e.capture.frames, 2)
        self.assertEqual(e.capture.kinds, {"adv": 1, "ack": 1})
        self.assertEqual(node.stats.summary(T + 3)["rssi"]["avg"], -70)

    def test_merge_adds_statistics_and_moves_the_history(self):
        e = Engine()
        prov = e.node_for(T, rloc16=0x0401)
        e.record_frame(T, prov, "poll", length=10)
        e.on_destination(T + 1, None, 0x0401, 20)
        e.on_frame(T + 5, "bb" * 8, 0x0401)  # the MAC becomes known: merge
        node = e.nodes["bb" * 8]
        self.assertEqual((node.stats.frames, node.stats.addressed), (1, 1))
        self.assertIn("first_seen", kinds(node))
        self.assertIn("mac_learned", kinds(node))
        self.assertNotIn("rloc16:0401", e.nodes)
        self.assertTrue(all(nid == "bb" * 8 for nid, _ in e.pending_events))


class EventTests(unittest.TestCase):
    def test_first_seen_says_whether_the_node_was_heard(self):
        e = Engine()
        e.on_frame(T, "aa" * 8, None)
        e.on_destination(T, "bb" * 8)
        self.assertEqual(e.nodes["aa" * 8].events[0]["params"], {"how": "heard"})
        self.assertEqual(e.nodes["bb" * 8].events[0]["params"], {"how": "mentioned"})

    def test_first_tick_is_only_a_baseline(self):
        e = Engine()
        e.on_frame(T, "aa" * 8, 0x0400)
        e.tick(T + 1)
        self.assertEqual(kinds(e.nodes["aa" * 8]), ["first_seen"])

    def test_role_change_to_leader(self):
        e = Engine()
        node = e.on_frame(T, "aa" * 8, 0x0400)
        e.tick(T + 1)
        e.on_leader_data(T + 2, node, 7, 1)  # router id 1 is the leader
        e.tick(T + 3)
        event = [ev for ev in node.events if ev["kind"] == "role"][0]
        self.assertEqual(event["params"], {"from": "router", "to": "leader"})

    def test_reparenting_logs_parent_and_rloc16(self):
        e = Engine()
        child = e.on_frame(T, "cc" * 8, (5 << 10) | 1)
        e.tick(T + 1)
        e.on_frame(T + 2, "cc" * 8, (9 << 10) | 1)
        e.tick(T + 3)
        by_kind = {ev["kind"]: ev["params"] for ev in child.events}
        self.assertEqual(by_kind["parent"], {"from": 5, "to": 9})
        self.assertEqual(by_kind["rloc16"], {"from": "0x1401", "to": "0x2401"})

    def test_online_and_offline(self):
        e = Engine()
        node = e.on_frame(T, "aa" * 8, 0x0400)
        e.tick(T + 10)
        e.tick(T + 10_000)  # routers are offline after 15 minutes of silence
        e.on_frame(T + 10_001, "aa" * 8, 0x0400)
        e.tick(T + 10_002)
        self.assertEqual(kinds(node), ["first_seen", "offline", "online"])

    def test_border_router_and_partition(self):
        e = Engine()
        node = e.on_frame(T, "aa" * 8, 0x0400)
        e.on_leader_data(T, node, 7, 0)
        e.tick(T + 1)
        e.on_network_data(T + 2, {0x0400})
        e.on_leader_data(T + 1000, node, 8, 0)  # the network re-formed: partition 7 has expired
        e.tick(T + 1001)
        self.assertIn("br_on", kinds(node))
        part = [ev for ev in node.events if ev["kind"] == "partition"][0]
        self.assertEqual(part["params"], {"from": 7, "to": 8})

    def test_history_is_capped(self):
        e = Engine()
        node = e.on_frame(T, "aa" * 8, 0x0400)
        for i in range(EVENTS_PER_NODE + 50):
            e._log(node, T + i, "online")
        self.assertEqual(len(node.events), EVENTS_PER_NODE)
        self.assertEqual(node.events[-1]["ts"], T + EVENTS_PER_NODE + 49)

    def test_reset_clears_history_but_keeps_capture_statistics(self):
        e = Engine()
        node = e.on_frame(T, "aa" * 8, 0x0400)
        e.record_frame(T, node, "data")
        e.reset_topology()
        self.assertEqual((e.nodes, e.pending_events), ({}, []))
        self.assertEqual(e.capture.frames, 1)


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "t.sqlite"
        self.store = Store(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def populated(self):
        e = Engine()
        node = e.on_frame(T, "aa" * 8, 0x0400)
        for i in range(5):
            e.record_frame(T + i * 400, node, "adv", length=60, rssi=-70 - i, seq=i, dst="ffff")
        e.tick(T + 1)
        e.on_frame(T + 2000, "aa" * 8, 0x0800)
        e.tick(T + 2001)
        return e, node

    def test_roundtrip_keeps_statistics_buckets_and_events(self):
        e, node = self.populated()
        self.store.save(e.export_state(clear_dirty=True))
        e2 = Engine()
        e2.load_state(self.store.load())
        n2 = e2.nodes["aa" * 8]
        now = T + 3000
        self.assertEqual(n2.stats.summary(now), node.stats.summary(now))
        self.assertEqual(n2.stats.series(now), node.stats.series(now))
        self.assertEqual(n2.events, node.events)
        self.assertEqual(e2.capture.summary(now), e.capture.summary(now))

    def test_only_changed_buckets_and_new_events_are_exported(self):
        e, node = self.populated()
        first = e.export_state(clear_dirty=True)
        self.assertGreaterEqual(len(first["bucket_updates"]), 2)
        self.assertTrue(first["events_new"])
        second = e.export_state(clear_dirty=True)
        self.assertEqual((second["bucket_updates"], second["events_new"]), ([], []))
        e.record_frame(T + 9000, node, "data")
        third = e.export_state(clear_dirty=True)
        self.assertEqual(sorted(nid for nid, _, _ in third["bucket_updates"]), sorted([CAPTURE_ID, "aa" * 8]))
        self.assertEqual(third["events_new"], [])

    def test_failed_save_is_retried_without_losing_buckets_or_events(self):
        e, _ = self.populated()
        state = e.export_state(clear_dirty=True)
        e.restore_unsaved(state)  # the save failed
        retry = e.export_state(clear_dirty=True)
        self.assertEqual(sorted(map(str, state["bucket_updates"])), sorted(map(str, retry["bucket_updates"])))
        self.assertEqual(len(state["events_new"]), len(retry["events_new"]))

    def test_merged_node_leaves_no_orphans_in_the_database(self):
        e = Engine()
        prov = e.node_for(T, rloc16=0x0401)
        e.record_frame(T, prov, "poll")
        self.store.save(e.export_state(clear_dirty=True))
        e.on_frame(T + 5, "bb" * 8, 0x0401)
        self.store.save(e.export_state(clear_dirty=True))
        loaded = self.store.load()
        owners = {nid for nid, _, _ in loaded["buckets"]} | {nid for nid, *_ in loaded["events"]}
        self.assertEqual(owners - {CAPTURE_ID}, {"bb" * 8})
        e2 = Engine()
        e2.load_state(loaded)
        self.assertEqual(e2.nodes["bb" * 8].stats.frames, 1)
        self.assertIn("mac_learned", kinds(e2.nodes["bb" * 8]))

    def test_maintenance_drops_old_buckets_and_events_and_caps_the_history(self):
        e, node = self.populated()
        for i in range(EVENTS_PER_NODE + 20):
            e._log(node, T + 3000 + i, "online")
        self.store.save(e.export_state(clear_dirty=True))
        self.store.maintain(T + 3000 + 2 * EVENT_RETENTION)  # everything is ancient by now
        self.assertEqual((self.store.load()["buckets"], self.store.load()["events"]), ([], []))
        # cap per node, with recent events
        self.store.save({"nodes": [], "links": [], "meta": {}, "names": {}, "events_new": []})
        e3, node3 = self.populated()
        for i in range(EVENTS_PER_NODE + 20):
            e3._log(node3, T + i, "online")
        self.store.save(e3.export_state(clear_dirty=True))
        self.store.maintain(T + 5000)
        counts = len([ev for ev in self.store.load()["events"] if ev[0] == "aa" * 8])
        self.assertEqual(counts, EVENTS_PER_NODE)

    def test_database_without_the_new_tables_and_column_is_upgraded(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "old.sqlite"
            con = sqlite3.connect(db)
            con.executescript("""CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
              CREATE TABLE nodes (id TEXT PRIMARY KEY, ext TEXT, rloc16 INTEGER, partition_id INTEGER,
                ftd INTEGER, rx_on_idle INTEGER, polls INTEGER NOT NULL, border_router INTEGER NOT NULL,
                first_seen REAL NOT NULL, last_seen REAL NOT NULL, last_role TEXT);
              INSERT INTO nodes VALUES ('aa', 'aa', 1024, NULL, NULL, NULL, 0, 0, 1, 2, 'router');""")
            con.commit(); con.close()
            state = Store(db).load()
            self.assertEqual((state["buckets"], state["events"]), ([], []))
            e = Engine()
            e.load_state(state)
            self.assertEqual(e.nodes["aa"].stats.frames, 0)
            e.record_frame(T, e.nodes["aa"], "data")
            Store(db).save(e.export_state(clear_dirty=True))
            self.assertEqual(Store(db).load()["nodes"][0]["stats"]["frames"], 1)

    def test_persister_ticks_and_saves(self):
        import time
        from thread_tree.store import Persister
        e = Engine()
        now = time.time()
        node = e.on_frame(now, "aa" * 8, 0x0400)
        e.record_frame(now, node, "data", rssi=-60)
        p = Persister(e, self.store)
        p.flush()
        self.assertIsNotNone(node.sig)  # the tick ran
        self.assertEqual(len(self.store.load()["buckets"]), 2)  # node + capture


if __name__ == "__main__":
    unittest.main()
