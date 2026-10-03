"""Thread review, third round: long poll period, CSL, routers-only checks, offline limits, exact times,
contexts, service anycast addresses, route cost."""
import unittest

from test_active import BR, NOW, collected
from test_ek_stats import T_MS, handler, pkt
from thread_tree import addresses as A
from thread_tree import behavior as B
from thread_tree.diagnose import report
from thread_tree.engine import Engine
from thread_tree.topology import snapshot

T0 = T_MS / 1000
SLEEPY, ROUTER, OTHER = "a4c138fffe100009", "c8d1d1fffe000009", "c8d1d1fffe000001"


def mac(ext):
    return ":".join(ext[i:i + 2] for i in range(0, 16, 2))


def never(start, end):
    return False


class PollPeriodTests(unittest.TestCase):
    def test_the_long_period_not_the_fast_bursts(self):
        b, t = {}, 0.0
        for _ in range(6):               # every minute a long poll, after it a burst of fast polls
            t += 60.0
            B.on_poll(b, t, never)
            for _ in range(3):
                t += 1.0
                B.on_poll(b, t, never)
        self.assertGreaterEqual(B.usual_interval(b), 57.0)    # the median would be 1 s: every slow poll a "gap"
        self.assertIsNone(B.on_poll(b, t + 60.0, never))

    def test_a_gap_never_needs_more_than_the_child_timeout(self):
        self.assertEqual(B.gap_threshold(100.0), 400.0)
        self.assertEqual(B.gap_threshold(100.0, timeout=240), 240.0)
        self.assertEqual(B.gap_threshold(100.0, timeout=60), 400.0)  # a timeout below the rhythm is not plausible

    def test_csl_devices_are_not_judged_by_polls(self):
        b = {"csl": 500}
        for i in range(8):
            B.on_poll(b, 30.0 * i, never)
        self.assertIsNone(B.on_poll(b, 210.0 + 900, never))
        self.assertIsNone(B.silence(b, 5000.0))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.e = Engine()
        self.router = self.e.on_frame(T0, ROUTER, 0x2400)
        self.other = self.e.on_frame(T0, OTHER, 0x0000)
        self.sleepy = self.e.on_frame(T0, SLEEPY, 0x2401)

    def test_old_network_data_is_judged_for_routers_only(self):
        e = self.e
        e.on_leader_data(T0, self.other, 7, 0, 10)
        e.on_leader_data(T0 + 5, self.other, 7, 0, 11)
        for t in (60, 200):
            e.on_leader_data(T0 + t, self.sleepy, 7, 0, 10)      # a sleepy child with only the stable data
        self.assertNotIn("netdata_lag", [ev["kind"] for ev in self.sleepy.events])

    def test_an_attach_answered_unseen_is_not_reported_hours_later(self):
        e = self.e
        e.on_attach_request(T0, self.sleepy, self.router)
        e.on_parent_request(T0 + 3 * 3600, self.sleepy)
        self.assertNotIn("attach_unanswered", [ev["kind"] for ev in self.sleepy.events])

    def test_offline_limits_from_the_devices_rhythm(self):
        e = self.e
        self.assertEqual(e.offline_limit(self.router, "router"), 900.0)          # rhythm not known yet
        for i in range(12):
            e.record_frame(T0 + 32 * i, self.router, "adv", 60, -60, 150, None, "ffff")
        self.assertEqual(e.offline_limit(self.router, "router"), 320.0)          # ten advertisements
        self.assertEqual(e.offline_limit(self.sleepy, "sed"), 6 * 3600.0)
        e.on_child_timeout(T0, self.sleepy, 240)
        self.assertEqual(e.offline_limit(self.sleepy, "sed"), 480.0)             # twice its child timeout
        quiet = e.on_frame(T0, None, 0x2402)
        quiet.last_heard = 0
        self.assertEqual(e.offline_limit(quiet, "sed"), 6 * 3600.0)              # never heard: no own rhythm

    def test_a_deaf_sniffer_sends_nobody_offline(self):
        e = self.e
        e.on_child_timeout(T0, self.sleepy, 240)
        e.record_frame(T0, self.other, "adv", 60, -60, 150, None, "ffff")
        self.assertTrue(e.presence_of(self.sleepy, "sed", T0 + 600)[0])         # nothing heard at all: time stands still
        self.assertEqual(e.presence_now(T0 + 600), T0 + 60)
        for t in range(20, 620, 20):                                             # the sniffer hears the leader, not it
            e.record_frame(T0 + t, self.other, "adv", 60, -60, 150, None, "ffff")
        self.assertFalse(e.presence_of(self.sleepy, "sed", T0 + 600)[0])        # silent for longer than 2 x 240 s

    def test_events_are_dated_to_when_they_happened(self):
        e = self.e
        e.tick(T0 + 1)
        e.on_frame(T0 + 7, SLEEPY, 0x0001)                                       # moved to the leader
        e.tick(T0 + 30)
        parent = next(ev for ev in self.sleepy.events if ev["kind"] == "parent")
        self.assertEqual(parent["ts"], T0 + 7)
        e.on_child_timeout(T0, self.router, None or 0)
        for t in range(40, 2000, 20):                                            # the sniffer keeps hearing the leader
            e.record_frame(T0 + t, self.other, "adv", 60, -60, 150, None, "ffff")
            e.on_frame(T0 + t, OTHER, 0x0000)
        e.tick(T0 + 2000)
        offline = next(ev for ev in self.router.events if ev["kind"] == "offline")
        self.assertEqual(offline["ts"], T0 + 900)                                # silent since T0, limit 15 min
        self.assertEqual([x["ts"] for x in self.router.events], sorted(x["ts"] for x in self.router.events))

    def test_a_restarted_router_calls_all_routers(self):
        e, h = handler(self.e)
        for t in (0, 10_000, 90_000):
            h.handle(pkt(t, wpan_src64=[mac(ROUTER)], wpan_src16=["0x2400"], mle_cmd=["0"], ipv6_dst=["ff02::2"]))
        h.handle(pkt(100_000, wpan_src64=[mac(ROUTER)], wpan_src16=["0x2400"], mle_cmd=["0"], ipv6_dst=["fe80::1"]))
        reboots = [ev["params"] for ev in self.router.events if ev["kind"] == "reboot"]
        self.assertEqual(reboots, [{"how": "link_request"}, {"how": "link_request"}])   # one per minute; unicast is no restart

    def test_csl_from_the_sniffer(self):
        e, h = handler(self.e)
        h.handle(pkt(0, wpan_src64=[mac(SLEEPY)], **{"wpan_header_ie_csl_period": ["500"]}))
        self.assertEqual(self.sleepy.behavior["csl"], 500)
        h.handle(pkt(0, wpan_src64=[mac(ROUTER)], wpan_src16=["0x2400"], **{"wpan_header_ie_csl_period": ["500"]}))
        self.assertNotIn("csl", self.router.behavior)                            # a parent sends CSL IEs too


class ContextTests(unittest.TestCase):
    def test_omr_addresses_from_compressed_registrations(self):
        e, h = handler(Engine(ml_prefix=0xFD00000000000001))
        h.handle(pkt(0, wpan_src64=[mac(ROUTER)], wpan_src16=["0x2400"], thread_nwd_tlv_prefix=["fdc2:f44c:29d0:1::", "::"],
                     **{"thread_nwd_tlv_prefix_length": ["64", "0"], "thread_nwd_tlv_6co_context_id": ["1"]}))
        self.assertEqual(e.contexts, {1: 0xFDC2F44C29D00001})
        h.handle(pkt(1000, wpan_src64=[mac(SLEEPY)], wpan_src16=["0x2401"], mle_cmd=["13"],
                     mle_tlv_addr_reg_iid=["0000:0000:0000:0042", "0000:0000:0000:0043"], mle_tlv_addr_reg_cid=["0", "1"]))
        self.assertEqual(sorted(e.nodes[SLEEPY].addresses), ["fd00:0:0:1::42", "fdc2:f44c:29d0:1::43"])

    def test_contexts_that_do_not_line_up_are_ignored(self):
        e, h = handler()
        h.handle(pkt(0, wpan_src64=[mac(ROUTER)], wpan_src16=["0x2400"], thread_nwd_tlv_prefix=["fd01:1:1:1::", "fd02:2:2:2::"],
                     **{"thread_nwd_tlv_prefix_length": ["64", "64"], "thread_nwd_tlv_6co_context_id": ["1"]}))
        self.assertEqual(e.contexts, {})


class TopologyTests(unittest.TestCase):
    def test_service_anycast_addresses_of_the_border_router(self):
        e, _, _ = collected()                      # the real network: DIRIGERA is backbone router and SRP server
        addrs = {a["addr"] for a in snapshot(e, NOW + 5)["nodes"][BR]["addresses"] if a["type"] == "aloc"}
        self.assertEqual(addrs, {"fdca:fe00:1:1:0:ff:fe00:fc10", "fdca:fe00:1:1:0:ff:fe00:fc11", "fdca:fe00:1:1:0:ff:fe00:fc38"})

    def test_the_tree_follows_thread_route_costs(self):
        e = Engine()
        for rid, ext in ((0, "aa" * 8), (1, "bb" * 8), (2, "cc" * 8)):
            node = e.on_frame(T0, ext, rid << 10)
            e.on_leader_data(T0, node, 7, 0)
        e.on_route64(T0, 0x0000, [(1, 3, 3, 1), (2, 1, 1, 4)])   # leader - router 2 directly, but weak (cost 4)
        e.on_route64(T0, 0x0400, [(0, 3, 3, 1), (2, 3, 3, 1)])   # via router 1: two good links (cost 2)
        e.on_route64(T0, 0x0800, [(0, 1, 1, 4), (1, 3, 3, 1)])
        root = snapshot(e, T0)["partitions"][0]["root"]
        via = next(c for c in root["children"] if c["id"] == "bb" * 8)
        self.assertEqual([c["id"] for c in via["children"]], ["cc" * 8])

    def test_child_id_has_nine_bits(self):
        self.assertEqual(A.child_id(0x2601), 0x001 | 0x200 & 0x1FF)
        self.assertEqual(A.child_id(0x05FF), 0x1FF)


if __name__ == "__main__":
    unittest.main()
