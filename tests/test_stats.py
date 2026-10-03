import unittest

from thread_tree.stats import (BUCKET_KEEP, BUCKET_SECONDS, RETRY_WINDOW, Interval, NodeStats, rssi_bin)

T0 = 10 * 86400.0  # a bucket boundary far from the epoch


class RecordTests(unittest.TestCase):
    def test_counters_kinds_bytes(self):
        s = NodeStats()
        s.record_frame(T0, "data", length=100)
        s.record_frame(T0 + 1, "adv", length=60)
        s.record_frame(T0 + 2, "adv", length=60)
        self.assertEqual((s.frames, s.bytes), (3, 220))
        self.assertEqual(s.kinds, {"data": 1, "adv": 2})
        self.assertEqual((s.first, s.last), (T0, T0 + 2))

    def test_retransmission_needs_same_sequence_destination_and_closeness(self):
        s = NodeStats()
        self.assertFalse(s.record_frame(T0, "data", seq=7, dst="bb"))
        self.assertTrue(s.record_frame(T0 + 0.01, "data", seq=7, dst="bb"))         # repeated at once
        self.assertTrue(s.record_frame(T0 + 0.05, "data", seq=7, dst="bb"))         # and again
        self.assertFalse(s.record_frame(T0 + 1.0, "data", seq=8, dst="bb"))         # next frame
        self.assertFalse(s.record_frame(T0 + 1.01, "data", seq=8, dst="cc"))        # other destination
        self.assertFalse(s.record_frame(T0 + 10, "data", seq=8, dst="cc"))          # sequence wrapped much later
        self.assertFalse(s.record_frame(T0 + 11, "data", seq=None))                 # no sequence number
        self.assertEqual((s.frames, s.retries), (7, 2))
        self.assertAlmostEqual(s.summary(T0 + 20)["retry_rate"], 2 / 7)
        self.assertGreater(RETRY_WINDOW, 0.05)

    def test_repeated_advertisement_is_not_a_new_advertisement(self):
        s = NodeStats()
        s.record_frame(T0, "adv", seq=1, dst="ffff")
        s.record_frame(T0 + 0.02, "adv", seq=1, dst="ffff")  # retransmission
        s.record_frame(T0 + 30, "adv", seq=2, dst="ffff")
        iv = s.summary(T0 + 40)["adv"]
        self.assertEqual((iv["n"], iv["mean"], iv["min"], iv["max"]), (1, 30.0, 30.0, 30.0))
        self.assertEqual(s.window(T0 + 40, 1)["adv"], 2)  # two distinct advertisements

    def test_intervals_ignore_gaps_that_mean_missed_frames(self):
        s = NodeStats()
        for ts in (T0, T0 + 20, T0 + 40, T0 + 500, T0 + 520):  # one long gap
            s.record_frame(ts, "adv")
        iv = s.summary(T0 + 600)["adv"]
        self.assertEqual((iv["n"], iv["min"], iv["max"]), (3, 20.0, 20.0))

    def test_poll_interval(self):
        s = NodeStats()
        for ts in (T0, T0 + 4, T0 + 8, T0 + 12):
            s.record_frame(ts, "poll")
        iv = s.summary(T0 + 20)["poll"]
        self.assertEqual((iv["n"], iv["mean"]), (3, 4.0))
        self.assertEqual(s.window(T0 + 20, 1)["polls"], 4)

    def test_addressed(self):
        s = NodeStats()
        s.record_addressed(T0, 50)
        s.record_addressed(T0 + 1, None)
        self.assertEqual((s.addressed, s.addressed_bytes, s.frames), (2, 50, 0))


class RssiTests(unittest.TestCase):
    def test_bins(self):
        self.assertEqual([rssi_bin(v) for v in (-73, -75, -76, -100, -120, -20, -1)], [-75, -75, -80, -100, -100, -25, -25])

    def test_aggregates_and_histogram(self):
        s = NodeStats()
        for v in (-60, -70, -80):
            s.record_frame(T0, "data", rssi=v, lqi=200)
        r = s.summary(T0)["rssi"]
        self.assertEqual((r["n"], r["avg"], r["min"], r["max"], r["last"]), (3, -70.0, -80, -60, -80))
        hist = dict((b, n) for b, n in r["hist"])
        self.assertEqual((hist[-60], hist[-70], hist[-80]), (1, 1, 1))
        self.assertEqual(len(r["hist"]), 16)
        self.assertEqual(s.summary(T0)["lqi"], {"n": 3, "avg": 200.0, "last": 200})

    def test_no_rssi_means_none(self):
        s = NodeStats()
        s.record_frame(T0, "data")
        self.assertIsNone(s.summary(T0)["rssi"])
        self.assertIsNone(s.summary(T0)["lqi"])


class BucketTests(unittest.TestCase):
    def test_windows_and_series_are_aligned(self):
        s = NodeStats()
        s.record_frame(T0 - 3 * BUCKET_SECONDS + 5, "data", length=10, rssi=-70)   # 3 buckets ago
        s.record_frame(T0 + 5, "data", length=20, rssi=-80)                          # current bucket
        now = T0 + 100
        self.assertEqual(s.window(now, 1)["frames"], 1)
        self.assertEqual(s.window(now, 4)["frames"], 2)
        self.assertEqual(s.window(now, 4)["rssi_avg"], -75.0)
        series = s.series(now, hours=1)  # 6 buckets, the last one is the current
        self.assertEqual(len(series["frames"]), 6)
        self.assertEqual(series["frames"], [0, 0, 1, 0, 0, 1])  # 3 buckets ago, and the current one
        self.assertEqual(series["bytes"], [0, 0, 10, 0, 0, 20])
        self.assertEqual(series["start"], T0 - 5 * BUCKET_SECONDS)
        self.assertEqual(series["rssi_avg"][-1], -80.0)
        self.assertIsNone(series["rssi_avg"][0])

    def test_prune_old_buckets(self):
        s = NodeStats()
        s.record_frame(T0, "data")
        s.record_frame(T0 + (BUCKET_KEEP + 5) * BUCKET_SECONDS, "data")
        s.prune(T0 + (BUCKET_KEEP + 5) * BUCKET_SECONDS)
        self.assertEqual(len(s.buckets), 1)
        self.assertEqual(len(s.dirty), 1)

    def test_dirty_tracks_changed_buckets_only(self):
        s = NodeStats()
        s.record_frame(T0, "data")
        s.record_frame(T0 + BUCKET_SECONDS, "data")
        self.assertEqual(len(s.bucket_rows()), 2)
        s.dirty.clear()
        s.record_frame(T0 + BUCKET_SECONDS + 1, "data")
        self.assertEqual([i for i, _ in s.bucket_rows()], [int((T0 + BUCKET_SECONDS) // BUCKET_SECONDS)])
        self.assertEqual(len(s.bucket_rows(only_dirty=False)), 2)


class PersistMergeTests(unittest.TestCase):
    def filled(self):
        s = NodeStats()
        for i, v in enumerate((-60, -70, -80)):
            s.record_frame(T0 + i * 30, "adv" if i < 2 else "poll", length=10, rssi=v, lqi=100, seq=i, dst="x")
        s.record_addressed(T0 + 5, 7)
        return s

    def test_json_roundtrip(self):
        s = self.filled()
        s2 = NodeStats.from_json(s.to_json())
        for idx, vals in s.bucket_rows(only_dirty=False):
            s2.load_bucket(idx, vals)
        self.assertEqual(s2.summary(T0 + 100), s.summary(T0 + 100))
        self.assertEqual(s2.series(T0 + 100), s.series(T0 + 100))

    def test_json_survives_a_real_json_dump(self):
        import json
        s = self.filled()
        s2 = NodeStats.from_json(json.loads(json.dumps(s.to_json())))
        self.assertEqual(s2.summary(T0 + 100)["rssi"], s.summary(T0 + 100)["rssi"])

    def test_merge_adds_up(self):
        a, b = self.filled(), self.filled()
        a.merge(b)
        self.assertEqual(a.frames, 6)
        self.assertEqual(a.kinds, {"adv": 4, "poll": 2})
        self.assertEqual(a.summary(T0 + 100)["rssi"]["n"], 6)
        self.assertEqual(a.window(T0 + 100, 1)["frames"], 6)
        self.assertEqual(a.addressed, 2)
        self.assertEqual(a.dirty, set(a.buckets))

    def test_merge_into_empty(self):
        a, b = NodeStats(), self.filled()
        a.merge(b)
        self.assertEqual(a.summary(T0 + 100)["rssi"]["min"], -80)

    def test_interval_merge(self):
        a, b = Interval(), Interval()
        a.add(10)
        b.add(30)
        a.merge(b)
        self.assertEqual(a.summary(), {"n": 2, "mean": 20.0, "min": 10, "max": 30})
        self.assertIsNone(Interval().summary())


if __name__ == "__main__":
    unittest.main()
