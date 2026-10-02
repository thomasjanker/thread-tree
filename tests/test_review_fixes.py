"""Regression tests for the node/link logic review (one class per finding)."""
import time
import unittest

from thread_tree import addresses as A
from thread_tree.engine import LINK_TTL, PARTITION_TTL, Engine
from thread_tree.store import Persister
from thread_tree.topology import snapshot


def tree_ids(snap):
    out = []

    def walk(t):
        out.append(t["id"])
        for c in t["children"]:
            walk(c)

    for p in snap["partitions"]:
        walk(p["root"])
    return out


def network(now=1.0):
    """Leader 0x0000 (aa..), router 0x2400 (bb..), router 0x4400 (cc..) in partition 7."""
    e = Engine()
    for ext, rloc in (("aa" * 8, 0x0000), ("bb" * 8, 0x2400), ("cc" * 8, 0x4400)):
        e.on_leader_data(now, e.on_frame(now, ext, rloc), 7, 0)
    return e


class RouterWithoutRlocTests(unittest.TestCase):
    def test_router_losing_its_rloc16_stays_in_the_tree_as_unknown(self):
        e = network()
        e.export_state()  # stores last_role = "router"
        e.on_frame(200.0, "dd" * 8, 0x2400)  # router id 9 reassigned to another device
        s = snapshot(e, now=201.0)
        self.assertEqual(s["nodes"]["bb" * 8]["role"], "unknown")
        self.assertIn("bb" * 8, tree_ids(s))
        self.assertEqual(s["nodes"]["dd" * 8]["role"], "router")

    def test_former_router_with_known_mode_shows_end_device_type(self):
        e = network()
        e.export_state()
        node = e.nodes["bb" * 8]
        e.on_frame(200.0, "dd" * 8, 0x2400)
        e.on_mode(201.0, node, False, False)
        self.assertEqual(snapshot(e, now=202.0)["nodes"]["bb" * 8]["role"], "sed")


class PartitionTests(unittest.TestCase):
    def test_re_formed_network_has_one_partition_and_no_ghost(self):
        e = network()
        sleepy = e.on_frame(1.0, "ee" * 8, None)
        e.on_leader_data(1.0, sleepy, 7, 0)  # sleepy device still carries the old partition id
        e.on_leader_data(1.0 + PARTITION_TTL + 60, e.nodes["aa" * 8], 8, 0)  # network re-formed
        s = snapshot(e, now=1.0 + PARTITION_TTL + 61)
        self.assertEqual([p["id"] for p in s["partitions"]], [8])
        self.assertEqual(s["nodes"]["ee" * 8]["partition_id"], 8)
        self.assertEqual(s["nodes"]["aa" * 8]["role"], "leader")

    def test_concurrent_partitions_both_shown_and_primary_does_not_flap(self):
        e = Engine()
        a = e.on_frame(1.0, "aa" * 8, 0x0000)
        b = e.on_frame(1.0, "bb" * 8, 0x2400)
        for ts in (1.0, 2.0, 3.0, 4.0):  # alternating leader data of two live partitions
            e.on_leader_data(ts, a, 7, 0)
            e.on_leader_data(ts + 0.5, b, 9, 9)
            self.assertEqual(e.primary_partition, 7)
        s = snapshot(e, now=5.0)
        self.assertEqual(sorted(p["id"] for p in s["partitions"]), [7, 9])
        self.assertEqual((s["nodes"]["aa" * 8]["role"], s["nodes"]["bb" * 8]["role"]), ("leader", "leader"))

    def test_state_without_partition_timestamps_still_works(self):
        e = network()
        state = e.export_state()
        del state["meta"]["partition_seen"]
        e2 = Engine()
        e2.load_state(state)
        s = snapshot(e2, now=2.0)
        self.assertEqual([p["id"] for p in s["partitions"]], [7])
        self.assertEqual(s["nodes"]["aa" * 8]["role"], "leader")


class StaleLinkTests(unittest.TestCase):
    def test_links_of_a_silent_router_stop_shaping_the_tree(self):
        e = network()
        e.on_route64(1.0, 0x0000, [(9, 3, 3, 1)])
        e.on_route64(1.0, 0x2400, [(0, 3, 3, 1), (17, 3, 3, 1)])
        e.on_route64(1.0, 0x4400, [(9, 3, 3, 1)])
        root = snapshot(e, now=2.0)["partitions"][0]["root"]
        self.assertEqual([c["id"] for c in root["children"]], ["bb" * 8])  # C reached through B
        # later only the leader keeps advertising; B and C went silent
        later = 1.0 + LINK_TTL + 30
        e.on_leader_data(later, e.nodes["aa" * 8], 7, 0)
        e.on_route64(later, 0x0000, [])
        s = snapshot(e, now=later)
        kinds = {c["id"]: c["edge"]["kind"] for c in s["partitions"][0]["root"]["children"]}
        self.assertEqual(kinds, {"bb" * 8: "unknown", "cc" * 8: "unknown"})
        self.assertTrue(all(l["stale"] for l in s["links"]))


class OneWayLinkTests(unittest.TestCase):
    def test_link_needs_both_directions(self):
        e = network()
        e.on_route64(1.0, 0x0000, [(9, 3, 0, 1)])  # leader hears B, B does not hear the leader
        kinds = {c["id"]: c["edge"] for c in snapshot(e, now=2.0)["partitions"][0]["root"]["children"]}
        self.assertEqual(kinds["bb" * 8]["kind"], "unknown")

    def test_weaker_direction_counts(self):
        e = network()
        e.on_route64(1.0, 0x0000, [(9, 3, 1, 1)])
        kinds = {c["id"]: c["edge"] for c in snapshot(e, now=2.0)["partitions"][0]["root"]["children"]}
        self.assertEqual(kinds["bb" * 8], {"kind": "link", "lq": 1})


class PersistRaceTests(unittest.TestCase):
    def test_change_during_save_is_saved_next_time(self):
        class Store:
            def __init__(self):
                self.saved = []

            def save(self, state):
                self.saved.append(state)

        now = time.time()
        e = Engine()
        e.on_frame(now, "aa" * 8, 0x0400)
        store = Store()
        p = Persister(e, store)
        original = e.export_state

        def racing_export(**kw):
            state = original(**kw)
            e.set_name("aa" * 8, "set during save")
            return state

        e.export_state = racing_export
        p.flush()
        e.export_state = original
        self.assertTrue(e.dirty)
        p.flush()
        self.assertEqual(store.saved[-1]["names"], {"aa" * 8: "set during save"})

    def test_failed_save_is_retried(self):
        class FailingStore:
            def save(self, state):
                raise OSError("disk full")

        e = Engine()
        e.on_frame(time.time(), "aa" * 8, 0x0400)
        with self.assertRaises(OSError):
            Persister(e, FailingStore()).flush()
        self.assertTrue(e.dirty)


class LinkLocalRlocTests(unittest.TestCase):
    def test_rloc_style_link_local_maps_to_the_short_address(self):
        e = Engine()
        e.on_ip(1.0, None, "fe80::ff:fe00:a800", None)
        self.assertEqual(list(e.nodes), ["rloc16:a800"])
        self.assertTrue(A.is_rloc_iid(A.iid(A.parse_ip("fe80::ff:fe00:a800"))))

    def test_mac_based_link_local_still_gives_the_mac(self):
        e = Engine()
        e.on_ip(1.0, None, "fe80::88b4:bd1a:4c18:8cf1", None)
        self.assertEqual(list(e.nodes), ["8ab4bd1a4c188cf1"])


if __name__ == "__main__":
    unittest.main()


class AddressedStatusTests(unittest.TestCase):
    """Design option C: 'last addressed' is tracked separately from the device's own activity."""

    def test_destination_updates_last_addressed_only(self):
        e = Engine()
        e.on_destination(10.0, "ee" * 8)
        e.on_destination(500.0, "ee" * 8)
        n = e.nodes["ee" * 8]
        self.assertEqual((n.last_addressed, n.last_seen, n.last_heard), (500.0, 10.0, 0.0))

    def test_short_destination_and_ignored_ones(self):
        e = Engine()
        router = e.on_frame(1.0, "bb" * 8, 0x2400)
        e.on_destination(50.0, None, 0x2400)
        self.assertEqual(router.last_addressed, 50.0)
        for dst in (0xFFFF, 0xFFFE, 0xFC00):
            e.on_destination(60.0, None, dst)
        e.on_destination(60.0, "ff" * 8)
        self.assertEqual(set(e.nodes), {"bb" * 8})

    def test_never_heard_device_is_online_indirect_while_addressed(self):
        e = Engine()
        e.on_destination(1.0, "ee" * 8)
        e.on_destination(30_000.0, "ee" * 8)  # still addressed 8 h later
        n = snapshot(e, now=30_001.0)["nodes"]["ee" * 8]
        self.assertEqual((n["online"], n["online_indirect"], n["last_addressed"]), (True, True, 30_000.0))
        n = snapshot(e, now=30_000.0 + 7 * 3600)["nodes"]["ee" * 8]  # not addressed any more
        self.assertEqual((n["online"], n["online_indirect"]), (False, False))

    def test_heard_device_is_judged_by_its_own_frames(self):
        e = Engine()
        e.on_frame(1.0, "ee" * 8, None)  # heard once
        e.on_destination(30_000.0, "ee" * 8)  # only addressed since then
        n = snapshot(e, now=30_001.0)["nodes"]["ee" * 8]
        self.assertEqual((n["online"], n["online_indirect"]), (False, False))
        self.assertEqual(n["last_addressed"], 30_000.0)

    def test_persisted_merged_and_protects_from_pruning(self):
        import tempfile
        from pathlib import Path
        from thread_tree.store import Store
        e = Engine()
        e.on_destination(5.0, None, 0x0401)          # provisional, addressed
        e.on_frame(6.0, "cc" * 8, 0x0401)            # MAC learned: merged
        self.assertEqual(e.nodes["cc" * 8].last_addressed, 5.0)
        e.on_destination(1_000_000.0, "cc" * 8)
        e.prune(now=1_000_001.0, max_age=3600.0)     # own activity old, but still addressed
        self.assertIn("cc" * 8, e.nodes)
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.sqlite")
            store.save(e.export_state())
            e2 = Engine()
            e2.load_state(store.load())
            self.assertEqual(e2.nodes["cc" * 8].last_addressed, 1_000_000.0)

    def test_ek_short_destination(self):
        from thread_tree.ek import FIELDS, Handler
        e = Engine()
        e.on_frame(1.0, "bb" * 8, 0x2400)
        Handler(e, {k: v[0] for k, v in FIELDS.items()}).handle(
            {"timestamp": "9000", "layers": {"wpan_src16": ["0x9c00"], "wpan_dst16": ["0x2400"]}})
        self.assertEqual(e.nodes["bb" * 8].last_addressed, 9.0)
