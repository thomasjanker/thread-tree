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


# ---------------------------------------------------------------- second review
from thread_tree.ek import FIELDS, Handler  # noqa: E402
from thread_tree.engine import BR_TTL  # noqa: E402


def handler(e):
    return Handler(e, {k: v[0] for k, v in FIELDS.items()})


def ek(ts_ms, **layers):
    return {"timestamp": str(ts_ms), "layers": layers}


class DatasetPrefixTests(unittest.TestCase):  # A
    def test_removing_the_dataset_removes_its_prefix(self):
        import tempfile
        from pathlib import Path
        from thread_tree.runtime import Controller
        from test_config import dataset_hex
        with tempfile.TemporaryDirectory() as d:
            e = Engine()
            c = Controller(e, "run", "nrf:/dev/null", dataset_path=Path(d) / "x.dataset",
                           tshark="definitely-not-installed")
            self.addCleanup(c.stop_capture)
            c.set_dataset(dataset_hex())
            self.assertEqual(e.ml_prefix, 0xFD12345678900001)
            c.clear_dataset()
            self.assertIsNone(e.ml_prefix)
            self.assertIsNone(e.export_state()["meta"]["fixed_ml_prefix"])


class RouteIsNotLinkTests(unittest.TestCase):  # B
    def test_multi_hop_route_entry_is_not_reported_as_link(self):
        e = network()
        e.on_route64(1.0, 0x0000, [(9, 3, 3, 1), (17, 0, 0, 2)])
        pairs = [(l["from_router_id"], l["to_router_id"]) for l in snapshot(e, now=2.0)["links"]]
        self.assertEqual(pairs, [(0, 9)])

    def test_one_way_link_is_still_reported(self):
        e = network()
        e.on_route64(1.0, 0x0000, [(9, 3, 0, 1)])
        self.assertEqual(len(snapshot(e, now=2.0)["links"]), 1)


class BorderRouterFlagTests(unittest.TestCase):  # C
    def test_partial_network_data_does_not_clear_the_flag_at_once(self):
        e = Engine()
        e.on_frame(1.0, "bb" * 8, 0x2400)
        e.on_network_data(10.0, {0x2400, 0x4400})
        e.on_network_data(20.0, {0x4400})  # stable-only copy without this entry
        self.assertTrue(e.nodes["bb" * 8].border_router)
        e.on_network_data(10.0 + BR_TTL + 1, {0x4400})  # still missing much later: no longer a BR
        self.assertFalse(e.nodes["bb" * 8].border_router)

    def test_br_seen_is_persisted(self):
        import tempfile
        from pathlib import Path
        from thread_tree.store import Store
        e = Engine()
        e.on_frame(1.0, "bb" * 8, 0x2400)
        e.on_network_data(10.0, {0x2400})
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.sqlite")
            store.save(e.export_state())
            e2 = Engine()
            e2.load_state(store.load())
            self.assertEqual(e2.nodes["bb" * 8].br_seen, 10.0)
            e2.on_network_data(20.0, set())
            self.assertTrue(e2.nodes["bb" * 8].border_router)


class StaleChildRlocTests(unittest.TestCase):  # F
    def test_polling_another_parent_by_mac_drops_the_old_short_address(self):
        e = network()
        child = e.on_frame(1.0, "a1" * 8, 0x0001)  # child of the leader
        e.on_data_request(5.0, child, 0x2400, None, sender_by_mac=True)  # now polls router 0x2400
        self.assertIsNone(child.rloc16)
        self.assertNotIn(0x0001, e.rloc_index)
        self.assertEqual(snapshot(e, now=6.0)["nodes"]["a1" * 8]["parent_router_id"], 9)

    def test_polling_by_short_address_never_drops_it(self):
        e = network()
        child = e.on_frame(1.0, "a1" * 8, 0x0001)
        e.on_data_request(5.0, child, 0x0000, None, sender_by_mac=False)
        self.assertEqual(child.rloc16, 0x0001)

    def test_ek_marks_mac_sourced_polls(self):
        e = network()
        e.on_frame(1.0, "a1" * 8, 0x0001)
        handler(e).handle(ek(5000, wpan_src64=["a1:a1:a1:a1:a1:a1:a1:a1"], wpan_dst16=["0x2400"], wpan_cmd=["4"]))
        self.assertIsNone(e.nodes["a1" * 8].rloc16)


class ChildUpdateResponseTests(unittest.TestCase):  # G
    def test_response_from_child_gives_mode_and_addresses(self):
        e = Engine(ml_prefix=0xFD123456789A0001)
        handler(e).handle(ek(1000, wpan_src64=["a1:a1:a1:a1:a1:a1:a1:a1"], mle_cmd=["14"], mle_tlv_source_addr=["14:03"],
                             mle_tlv_mode_device_type=["0"], mle_tlv_mode_idle_rx=["1"],
                             mle_tlv_addr_reg_iid=["0102030405060708"], mle_tlv_addr_reg_cid=["0"]))
        n = e.nodes["a1" * 8]
        self.assertEqual((n.rloc16, n.ftd, n.rx_on_idle), (0x1403, False, True))
        self.assertIn("fd12:3456:789a:1:102:304:506:708", n.addresses)

    def test_response_from_parent_is_not_taken_as_the_parents_mode(self):
        e = Engine(ml_prefix=0xFD123456789A0001)
        handler(e).handle(ek(1000, wpan_src64=["bb:bb:bb:bb:bb:bb:bb:bb"], mle_cmd=["14"], mle_tlv_source_addr=["14:00"],
                             mle_tlv_mode_device_type=["0"], mle_tlv_mode_idle_rx=["0"],
                             mle_tlv_addr_reg_iid=["0102030405060708"], mle_tlv_addr_reg_cid=["0"]))
        n = e.nodes["bb" * 8]
        self.assertEqual((n.ftd, n.rx_on_idle, n.addresses), (None, None, {}))


class AddressNotificationMlEidTests(unittest.TestCase):  # H
    def test_ml_eid_from_notification(self):
        e = Engine(ml_prefix=0xFD123456789A0001)
        handler(e).handle(ek(1000, wpan_src16=["0x2400"], thread_address_tlv_target_eid=["fdc2:f44c:29d0:1::1234"],
                             thread_address_tlv_rloc16=["0x2401"], thread_address_tlv_ml_eid=["11:22:33:44:55:66:77:88"]))
        addrs = e.nodes["rloc16:2401"].addresses
        self.assertEqual(set(addrs), {"fdc2:f44c:29d0:1::1234", "fd12:3456:789a:1:1122:3344:5566:7788"})


class LinkLocalBindingTests(unittest.TestCase):  # I
    def test_short_mac_source_with_mac_based_link_local_binds_both(self):
        e = Engine()
        e.on_frame(1.0, None, 0x2401)  # known so far by short address only
        handler(e).handle(ek(2000, wpan_src16=["0x2401"], ipv6_src=["fe80::88b4:bd1a:4c18:8cf1"], ipv6_dst=["ff02::1"]))
        self.assertEqual(set(e.nodes), {"8ab4bd1a4c188cf1"})
        self.assertEqual(e.nodes["8ab4bd1a4c188cf1"].rloc16, 0x2401)

    def test_routable_source_does_not_bind(self):
        e = Engine(ml_prefix=0xFD123456789A0001)
        handler(e).handle(ek(2000, wpan_src16=["0x2400"], ipv6_src=["fd12:3456:789a:1::99"]))
        self.assertEqual(set(e.nodes), {"rloc16:2400"})

    def test_helper(self):
        self.assertEqual(A.mac_from_link_local("fe80::88b4:bd1a:4c18:8cf1"), "8ab4bd1a4c188cf1")
        for other in ("fe80::ff:fe00:a800", "fd12::1", "ff02::1", None, "nonsense"):
            self.assertIsNone(A.mac_from_link_local(other))


class PanFilterTests(unittest.TestCase):  # J
    def test_filter_keeps_frames_without_pan_id(self):
        from thread_tree.capture import pan_filter
        self.assertEqual(pan_filter(0x0551),
                         "wpan.dst_pan == 0x0551 || wpan.src_pan == 0x0551 || (!wpan.dst_pan && !wpan.src_pan)")


class IdentityViaRlocTests(unittest.TestCase):  # E (UI hint)
    def test_only_short_address_frames_for_long_set_the_flag(self):
        e = Engine()
        e.on_frame(0.0, "a1" * 8, None)
        e.on_address_assignment(10.0, "a1" * 8, 0x1401)  # MAC tied to RLOC16 at t=10
        for ts in (100.0, 2000.0, 5000.0):
            e.on_frame(ts, None, 0x1401)  # polls by short address only
        n = snapshot(e, now=5001.0)["nodes"]["a1" * 8]
        self.assertEqual(n["mac_confirmed"], 10.0)
        self.assertTrue(n["identity_via_rloc"])
        e.on_frame(5100.0, "a1" * 8, None)  # a frame with its MAC address again
        self.assertFalse(snapshot(e, now=5101.0)["nodes"]["a1" * 8]["identity_via_rloc"])

    def test_destination_frames_do_not_confirm_the_mac(self):
        e = Engine()
        e.on_address_assignment(10.0, "a1" * 8, 0x1401)
        e.on_destination(4000.0, "a1" * 8)
        self.assertEqual(e.nodes["a1" * 8].mac_confirmed, 10.0)

    def test_not_set_shortly_after_confirmation_or_without_mac(self):
        e = Engine()
        e.on_address_assignment(10.0, "a1" * 8, 0x1401)
        e.on_frame(600.0, None, 0x1401)
        e.on_frame(5000.0, None, 0x2402)  # no MAC known at all: covered by the other hint
        s = snapshot(e, now=5001.0)["nodes"]
        self.assertFalse(s["a1" * 8]["identity_via_rloc"])
        self.assertFalse(s["rloc16:2402"]["identity_via_rloc"])
