import json
import tempfile
import unittest
from pathlib import Path

from thread_tree import addresses as A
from thread_tree.dataset import parse_dataset
from thread_tree.ek import Handler, FIELDS
from thread_tree.engine import Engine
from thread_tree.simulate import ML_PREFIX, populate
from thread_tree.store import Store
from thread_tree.topology import snapshot


class AddressTests(unittest.TestCase):
    def test_link_local_roundtrip(self):
        ext = "c8d1d1fffe000001"
        ll = A.link_local_from_ext(ext)
        self.assertEqual(str(ll), "fe80::cad1:d1ff:fe00:1")  # c8 ^ 02 = ca
        self.assertEqual(A.ext_from_link_local(ll), ext)

    def test_rloc16_math(self):
        self.assertEqual(A.router_id(0x1C01), 7)
        self.assertEqual(A.child_id(0x1C01), 1)
        self.assertEqual(A.parent_rloc16(0x1C01), 0x1C00)
        self.assertTrue(A.is_router_rloc(0x1C00))

    def test_classify(self):
        p = ML_PREFIX
        self.assertEqual(A.classify(A.rloc_address(p, 0x1400), p), A.RLOC)
        self.assertEqual(A.classify(A.rloc_address(p, 0xFC00), p), A.ALOC)
        self.assertEqual(A.classify(A.parse_ip("fd12:3456:789a:1::1234"), p), A.ML_EID)
        self.assertEqual(A.classify(A.parse_ip("2a02::1"), p), A.OMR)
        self.assertEqual(A.classify(A.parse_ip("fe80::1"), p), A.LINK_LOCAL)
        self.assertEqual(A.classify(A.parse_ip("fd12:3456:789a:1::1234"), None), A.UNCLASSIFIED)

    def test_ext_normalize(self):
        self.assertEqual(A.normalize_ext("C8:D1:D1:FF:FE:00:00:01"), "c8d1d1fffe000001")
        self.assertIsNone(A.normalize_ext("zz"))


class DatasetTests(unittest.TestCase):
    def test_parse(self):
        tlvs = ("0e080000000000010000" "000300000f" "35060004001fffe0" "0208dead00beef00cafe"
                "0708fd00000000000001" "0510" + "11" * 16 + "030c" + "MyThread".encode().hex().ljust(24, "0")
                + "0102abcd")
        # channel TLV: type 0 len 3 page 0 channel 15
        tlvs = "000300000f" + tlvs
        ds = parse_dataset(tlvs)
        self.assertEqual(ds.channel, 15)
        self.assertEqual(ds.pan_id, 0xABCD)
        self.assertEqual(ds.network_key, "11" * 16)
        self.assertEqual(ds.mesh_local_prefix_str, "fd00:0:0:1::/64")
        self.assertEqual(ds.ext_pan_id, "dead00beef00cafe")

    def test_truncated(self):
        with self.assertRaises(ValueError):
            parse_dataset("0508aabb")


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.e = Engine()
        populate(self.e, now=1000.0)

    def test_roles_and_tree(self):
        snap = snapshot(self.e, now=1001.0)
        roles = {n["ext"]: n["role"] for n in snap["nodes"].values() if n["ext"]}
        self.assertEqual(roles["c8d1d1fffe000001"], "leader")
        self.assertEqual(roles["c8d1d1fffe000005"], "router")
        self.assertEqual(roles["a4c138fffe100001"], "med")
        self.assertEqual(roles["a4c138fffe100002"], "sed")
        self.assertEqual(roles["a4c138fffe100003"], "fed")
        part = snap["partitions"][0]
        self.assertEqual(part["root"]["id"], "c8d1d1fffe000001")
        ids = []
        def walk(t):
            ids.append(t["id"]); [walk(c) for c in t["children"]]
        walk(part["root"])
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len([i for i in ids if i in snap["nodes"]]), len(ids))
        self.assertEqual(len(ids), 5 + 7)

    def test_border_router_has_multiple_addresses(self):
        snap = snapshot(self.e, now=1001.0)
        br = snap["nodes"]["c8d1d1fffe000005"]
        self.assertTrue(br["border_router"])
        types = [a["type"] for a in br["addresses"]]
        for t in ("ml-eid", "omr", "rloc", "link-local"):
            self.assertIn(t, types)
        self.assertGreaterEqual(types.count("omr"), 2)  # ULA OMR + GUA
        leader = snap["nodes"]["c8d1d1fffe000001"]
        self.assertIn("aloc", [a["type"] for a in leader["addresses"]])

    def test_reparent_changes_tree_not_identity(self):
        self.e.on_frame(1002.0, "a4c138fffe100001", (9 << 10) | 7)
        snap = snapshot(self.e, now=1003.0)
        self.assertEqual(snap["nodes"]["a4c138fffe100001"]["rloc16"], f"0x{(9 << 10) | 7:04x}")
        self.assertEqual(len(snap["nodes"]), 12)

    def test_provisional_node_merges_when_ext_learned(self):
        e = Engine()
        e.on_frame(1.0, None, 0x0400)
        self.assertIn("rloc16:0400", e.nodes)
        e.on_frame(2.0, "aabbccddeeff0011", 0x0400)
        self.assertNotIn("rloc16:0400", e.nodes)
        self.assertEqual(e.nodes["aabbccddeeff0011"].rloc16, 0x0400)

    def test_reassigned_rloc_unbinds_old_node(self):
        e = Engine()
        e.on_frame(1.0, "aa" * 8, 0x0400)
        e.on_frame(2.0, "bb" * 8, 0x0400)
        self.assertIsNone(e.nodes["aa" * 8].rloc16)
        self.assertEqual(e.rloc_index[0x0400], "bb" * 8)

    def test_offline_detection(self):
        snap = snapshot(self.e, now=1000.0 + 100000)
        self.assertFalse(any(n["online"] for n in snap["nodes"].values()))

    def test_forwarded_ml_eid_not_attributed_to_router(self):
        e = Engine(ml_prefix=ML_PREFIX)
        router = e.on_frame(1.0, "aa" * 8, 0x0400)
        e.on_ip(1.0, router, "fd12:3456:789a:1::99", "fd12:3456:789a:1::98")
        self.assertEqual(router.addresses, {})
        child = e.on_frame(1.0, "bb" * 8, 0x0401)
        e.on_ip(1.0, child, "fd12:3456:789a:1::99", None)
        self.assertIn("fd12:3456:789a:1::99", child.addresses)

    def test_unknown_parent_becomes_placeholder(self):
        e = Engine(ml_prefix=ML_PREFIX)
        e.on_frame(1.0, "cc" * 8, (30 << 10) | 3)
        snap = snapshot(e, now=2.0)
        self.assertTrue(any(n.get("placeholder") for n in snap["nodes"].values()))


class NameTests(unittest.TestCase):
    def setUp(self):
        self.e = Engine()
        populate(self.e, now=1000.0)
        self.ext = "a4c138fffe100002"

    def test_name_appears_in_snapshot(self):
        self.e.set_name(self.ext, "  Bad Sensor ")
        self.assertEqual(snapshot(self.e, now=1001.0)["nodes"][self.ext]["name"], "Bad Sensor")
        self.assertIsNone(snapshot(self.e, now=1001.0)["nodes"]["a4c138fffe100003"]["name"])

    def test_empty_name_removes_it(self):
        self.e.set_name(self.ext, "x")
        self.assertIsNone(self.e.set_name(self.ext, "   "))
        self.assertIsNone(self.e.set_name(self.ext, None))
        self.assertNotIn(self.ext, self.e.names)

    def test_validation(self):
        with self.assertRaises(KeyError):
            self.e.set_name("00" * 8, "nobody")
        with self.assertRaises(ValueError):
            self.e.set_name(self.ext, "x" * 65)
        with self.assertRaises(ValueError):
            self.e.set_name(self.ext, "bad\x00name")
        with self.assertRaises(ValueError):
            self.e.set_name(self.ext, "line\nbreak")
        self.assertEqual(self.e.set_name(self.ext, "Küche – Lämpchen 💡"), "Küche – Lämpchen 💡")

    def test_name_follows_device_when_it_re_parents(self):
        self.e.set_name(self.ext, "Sensor")
        self.e.on_frame(1002.0, self.ext, (9 << 10) | 9)
        snap = snapshot(self.e, now=1003.0)
        self.assertEqual(snap["nodes"][self.ext]["name"], "Sensor")
        self.assertEqual(snap["nodes"][self.ext]["rloc16"], f"0x{(9 << 10) | 9:04x}")

    def test_name_of_provisional_node_moves_to_the_ext_id_on_merge(self):
        e = Engine()
        e.on_frame(1.0, None, 0x0400)
        e.set_name("rloc16:0400", "Mystery")
        e.on_frame(2.0, "aabbccddeeff0011", 0x0400)
        self.assertEqual(e.names, {"aabbccddeeff0011": "Mystery"})

    def test_names_survive_pruning_of_ext_nodes_but_not_of_provisional_ones(self):
        e = Engine()
        e.on_frame(1.0, "aa" * 8, 0x0400)
        e.on_frame(1.0, None, 0x0800)
        e.set_name("aa" * 8, "Keep")
        e.set_name("rloc16:0800", "Drop")
        e.prune(now=10_000_000.0, max_age=60.0)
        self.assertEqual(e.names, {"aa" * 8: "Keep"})
        e.on_frame(10_000_001.0, "aa" * 8, 0x0400)  # device comes back
        self.assertEqual(snapshot(e, now=10_000_002.0)["nodes"]["aa" * 8]["name"], "Keep")

    def test_names_persist(self):
        self.e.set_name(self.ext, "Persistent")
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.sqlite")
            store.save(self.e.export_state())
            e2 = Engine()
            e2.load_state(Store(Path(d) / "t.sqlite").load())
            self.assertEqual(snapshot(e2, now=1001.0)["nodes"][self.ext]["name"], "Persistent")

    def test_old_database_without_names_table_still_loads(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "old.sqlite"
            Store(db)  # creates the schema
            con = sqlite3.connect(db)
            con.execute("DROP TABLE names")
            con.commit(); con.close()
            self.assertEqual(Store(db).load()["names"], {})  # table is re-created on open


class SourceTests(unittest.TestCase):
    def test_nrf_command(self):
        from thread_tree.capture import nrf_command
        cmd = nrf_command("/dev/ttyACM0", 17, "/opt/s.py")
        self.assertEqual(cmd, "python3 /opt/s.py --capture --extcap-interface /dev/ttyACM0 --channel 17 "
                              "--metadata ieee802154-tap --fifo /dev/stdout")
        for bad in (10, 27):
            with self.assertRaises(ValueError):
                nrf_command("/dev/ttyACM0", bad)

    def test_decrypt_stats(self):
        e = Engine()
        h = Handler(e, {**{k: v[0] for k, v in FIELDS.items()}})
        h.handle(ek(1000, wpan_src64=["aa:aa:aa:aa:aa:aa:aa:aa"], mle_no_key=[]))
        h.handle(ek(2000, wpan_src64=["aa:aa:aa:aa:aa:aa:aa:aa"], mle_cmd=["4"]))
        h.handle(ek(3000, wpan_src64=["aa:aa:aa:aa:aa:aa:aa:aa"]))
        self.assertEqual(h.stats, {"frames": 3, "mle_ok": 1, "mle_failed": 1})


class ReceptionTests(unittest.TestCase):
    def test_only_own_transmissions_count_as_heard(self):
        e = Engine(ml_prefix=ML_PREFIX)
        direct = e.on_frame(10.0, "aa" * 8, 0x0400)
        # another node's frames mention the RLOC / link-local address / notification of the others
        e.on_ip(11.0, direct, str(A.rloc_address(ML_PREFIX, 0x0800)), str(A.link_local_from_ext("bb" * 8)))
        e.on_address_notification(12.0, "fd12:3456:789a:1::5", 0x0C00)
        e.on_route64(13.0, 0x0400, [(2, 3, 3, 1)])
        snap = snapshot(e, now=14.0)
        heard = {n["rloc16"] or n["ext"]: n["heard"] for n in snap["nodes"].values()}
        self.assertTrue(heard["0x0400"])
        self.assertFalse(heard["0x0800"])
        self.assertFalse(heard["bbbbbbbbbbbbbbbb"])
        self.assertFalse(heard["0x0c00"])
        self.assertEqual(snap["nodes"]["aa" * 8]["last_heard"], 10.0)

    def test_demo_has_indirect_nodes_and_heard_survives_restart(self):
        e1 = Engine()
        populate(e1, now=1000.0)
        snap = snapshot(e1, now=1001.0)
        indirect = {n["ext"] for n in snap["nodes"].values() if not n["heard"] and not n.get("placeholder")}
        self.assertEqual(indirect, {"c8d1d1fffe000016", "a4c138fffe100007"})
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "t.sqlite")
            store.save(e1.export_state())
            e2 = Engine()
            e2.load_state(store.load())
            self.assertEqual({n["id"]: n["heard"] for n in snapshot(e2, now=1001.0)["nodes"].values()},
                             {n["id"]: n["heard"] for n in snap["nodes"].values()})

    def test_old_database_is_migrated(self):
        import sqlite3
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
            self.assertEqual(state["nodes"][0]["last_heard"], 0)
            Store(db).save(state)  # writing after migration works


class PersistenceTests(unittest.TestCase):
    def test_roundtrip_survives_restart(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "t.sqlite"
            e1 = Engine()
            populate(e1, now=1000.0)
            Store(db).save(e1.export_state())

            e2 = Engine()
            e2.load_state(Store(db).load())
            s1, s2 = snapshot(e1, now=1001.0), snapshot(e2, now=1001.0)
            self.assertEqual(s1["nodes"], s2["nodes"])
            self.assertEqual(s1["partitions"], s2["partitions"])
            self.assertEqual(s1["links"], s2["links"])
            self.assertEqual(e2.ml_prefix, e1.ml_prefix)


def ek(ts_ms, **fields):
    return {"timestamp": str(ts_ms), "layers": fields}


class EkAdapterTests(unittest.TestCase):
    def setUp(self):
        self.e = Engine()
        self.h = Handler(self.e, {k: v[0] for k, v in FIELDS.items()})

    def test_advertisement_yields_router_leader_and_links(self):
        self.h.handle(ek(
            1_000_000,
            wpan_src64=["c8:d1:d1:ff:fe:00:00:01"], wpan_src16=["0x0000"],
            ipv6_src=["fe80::c8d1:d1ff:fe00:1"],
            mle_cmd=["4"], mle_tlv_source_addr=["0000"],
            mle_tlv_leader_data_partition_id=["439041101"], mle_tlv_leader_data_router_id=["0"],
            mle_tlv_route64_id_mask=["84:40:00:00:00:00:00:00"],  # router ids 0, 5, 9
            mle_tlv_route64_nbr_in=["0", "3", "2"], mle_tlv_route64_nbr_out=["0", "3", "2"],
            mle_tlv_route64_cost=["0", "1", "1"],
        ))
        self.assertEqual(self.e.leaders, {439041101: 0})
        self.assertEqual(set(self.e.links), {(0, 5), (0, 9)})
        snap = snapshot(self.e, now=1001.0)
        self.assertEqual(snap["nodes"]["c8d1d1fffe000001"]["role"], "leader")

    def test_child_id_request_gives_mode_and_addresses(self):
        self.e.fixed_ml_prefix = ML_PREFIX
        self.h.handle(ek(
            2_000_000, wpan_src64=["a4:c1:38:ff:fe:10:00:01"],
            ipv6_src=["fe80::a6c1:38ff:fe10:1"], mle_cmd=["11"],
            mle_tlv_mode_device_type=["0"], mle_tlv_mode_idle_rx=["0"],
            mle_tlv_addr_reg_iid=["1122334455667788"], mle_tlv_addr_reg_cid=["0"],
        ))
        node = self.e.nodes["a4c138fffe100001"]
        self.assertEqual((node.ftd, node.rx_on_idle), (False, False))
        self.assertIn("fd12:3456:789a:1:1122:3344:5566:7788", node.addresses)

    def test_unaligned_route64_is_ignored(self):
        self.h.handle(ek(1, wpan_src64=["c8:d1:d1:ff:fe:00:00:01"], wpan_src16=["0x0000"], mle_cmd=["4"],
                         mle_tlv_route64_id_mask=["c0:00:00:00:00:00:00:00"], mle_tlv_route64_nbr_in=["1"],
                         mle_tlv_route64_nbr_out=["1", "1"], mle_tlv_route64_cost=["1"]))
        self.assertEqual(self.e.links, {})

    def test_data_poll_marks_sleepy_and_unfiltered_ek_names_work(self):
        self.h.handle(ek(1, wpan_wpan_src64=["a4:c1:38:ff:fe:10:00:09"], wpan_wpan_cmd=["4"]))
        self.assertTrue(self.e.nodes["a4c138fffe100009"].polls)

    def test_child_id_response_binds_mac_to_short_address(self):
        # parent 0xd400 answers the child's attach request: dst = child's MAC, Address16 = assigned RLOC16
        self.e.node_for(1.0, rloc16=0xD436, touch=False)  # known so far only by short address, never heard
        self.h.handle(ek(5_000, wpan_src64=["aa:aa:aa:aa:aa:aa:aa:aa"], wpan_src16=["0xd400"],
                         wpan_dst64=["a4:c1:38:ff:fe:10:00:77"], mle_cmd=["12"], mle_tlv_addr16=["d4:36"]))
        node = self.e.nodes["a4c138fffe100077"]
        self.assertEqual(node.rloc16, 0xD436)
        self.assertNotIn("rloc16:d436", self.e.nodes)  # provisional node merged into the MAC-identified one
        self.assertEqual(node.last_heard, 0.0)  # learned from someone else's frame: not heard directly

    def test_other_mle_commands_do_not_bind_address16(self):
        self.h.handle(ek(5_000, wpan_src64=["aa:aa:aa:aa:aa:aa:aa:aa"], wpan_dst64=["a4:c1:38:ff:fe:10:00:77"],
                         mle_cmd=["14"], mle_tlv_addr16=["d4:36"]))
        self.assertIsNone(self.e.nodes["a4c138fffe100077"].rloc16)  # exists as destination only

    def test_broadcast_destination_is_ignored(self):
        self.h.handle(ek(5_000, wpan_src64=["aa:aa:aa:aa:aa:aa:aa:aa"], wpan_dst64=["ff:ff:ff:ff:ff:ff:ff:ff"]))
        self.assertNotIn("ffffffffffffffff", self.e.nodes)

    def test_network_data_marks_border_router(self):
        self.e.on_frame(1.0, "aa" * 8, 0x1400)
        self.h.handle(ek(3, wpan_src64=["aa:aa:aa:aa:aa:aa:aa:aa"], mle_cmd=["8"],
                         thread_nwd_tlv_prefix=["fd00::"], thread_nwd_tlv_border_router_16=["0x1400", "5120"]))
        self.assertTrue(self.e.nodes["aa" * 8].border_router)


if __name__ == "__main__":
    unittest.main()
