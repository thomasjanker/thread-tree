"""Traffic statistics per node, from what the sniffer hears.

Counters, signal strength (RSSI/LQI as received *at the sniffer*, not between two nodes), intervals of
MLE advertisements and data polls, and 10-minute buckets for charts. Everything here is measured at the
sniffer's position: a node that is far from it looks quiet and weak without being so.
"""

from __future__ import annotations

BUCKET_SECONDS = 600
BUCKET_KEEP = 144 * 7        # one week of 10-minute buckets
RETRY_WINDOW = 0.5           # same sequence number to the same destination within this time: a retransmission
ADV_MAX_GAP = 120.0          # longer gaps between advertisements mean missed frames, not an interval
POLL_MAX_GAP = 3600.0
RSSI_LOW, RSSI_HIGH, RSSI_STEP = -100, -20, 5

# bucket layout: a plain list so it can be stored and sent as is
B_FRAMES, B_BYTES, B_RETRIES, B_POLLS, B_ADV, B_ADDRESSED, B_RSSI_N, B_RSSI_SUM, B_RSSI_MIN, B_RSSI_MAX = range(10)
BUCKET_FIELDS = ("frames", "bytes", "retries", "polls", "adv", "addressed", "rssi_n", "rssi_sum", "rssi_min",
                 "rssi_max")

KINDS = ("data", "adv", "mle", "poll", "cmd", "beacon", "ack", "other")


def _new_bucket() -> list:
    return [0, 0, 0, 0, 0, 0, 0, 0.0, None, None]


class Interval:
    """Running statistics of the gaps between consecutive events."""

    def __init__(self) -> None:
        self.n, self.total, self.min, self.max = 0, 0.0, None, None

    def add(self, gap: float) -> None:
        self.n += 1
        self.total += gap
        self.min = gap if self.min is None else min(self.min, gap)
        self.max = gap if self.max is None else max(self.max, gap)

    def merge(self, other: "Interval") -> None:
        if other.n:
            self.n += other.n
            self.total += other.total
            self.min = other.min if self.min is None else min(self.min, other.min)
            self.max = other.max if self.max is None else max(self.max, other.max)

    def summary(self) -> dict | None:
        if not self.n:
            return None
        return {"n": self.n, "mean": self.total / self.n, "min": self.min, "max": self.max}

    def to_json(self) -> list:
        return [self.n, self.total, self.min, self.max]

    @classmethod
    def from_json(cls, data: list | None) -> "Interval":
        iv = cls()
        if data:
            iv.n, iv.total, iv.min, iv.max = data
        return iv


def rssi_bin(rssi: float) -> int:
    clamped = min(max(int(rssi), RSSI_LOW), RSSI_HIGH - 1)
    return RSSI_LOW + ((clamped - RSSI_LOW) // RSSI_STEP) * RSSI_STEP


class NodeStats:
    def __init__(self) -> None:
        self.frames = self.bytes = self.retries = 0
        self.kinds: dict[str, int] = {}
        self.addressed = self.addressed_bytes = 0
        self.rssi_n, self.rssi_sum = 0, 0.0
        self.rssi_min = self.rssi_max = self.rssi_last = None
        self.rssi_hist: dict[int, int] = {}
        self.lqi_n, self.lqi_sum, self.lqi_last = 0, 0.0, None
        self.adv, self.poll = Interval(), Interval()
        self.first: float | None = None
        self.last: float | None = None
        self.buckets: dict[int, list] = {}
        self.dirty: set[int] = set()  # bucket indexes changed since the last save
        self._seq: tuple | None = None  # (sequence number, destination, time) of the previous frame
        self._last_adv: float | None = None
        self._last_poll: float | None = None

    # ---- recording ----------------------------------------------------------

    def _bucket(self, ts: float) -> list:
        idx = int(ts // BUCKET_SECONDS)
        bucket = self.buckets.get(idx)
        if bucket is None:
            bucket = self.buckets[idx] = _new_bucket()
        self.dirty.add(idx)
        return bucket

    def record_frame(self, ts: float, kind: str, length: int | None = None, rssi: float | None = None,
                     lqi: float | None = None, seq: int | None = None, dst: str | None = None) -> bool:
        """A frame transmitted by this node. Returns True if it was a retransmission."""
        retry = False
        if seq is not None:
            prev = self._seq
            retry = prev is not None and prev[0] == seq and prev[1] == dst and 0 <= ts - prev[2] <= RETRY_WINDOW
            self._seq = (seq, dst, ts)
        bucket = self._bucket(ts)
        self.frames += 1
        bucket[B_FRAMES] += 1
        self.kinds[kind] = self.kinds.get(kind, 0) + 1
        if length:
            self.bytes += length
            bucket[B_BYTES] += length
        if retry:
            self.retries += 1
            bucket[B_RETRIES] += 1
        else:  # a repeated frame is not a new advertisement or poll
            if kind == "adv":
                bucket[B_ADV] += 1
                if self._last_adv is not None and 0 < ts - self._last_adv <= ADV_MAX_GAP:
                    self.adv.add(ts - self._last_adv)
                self._last_adv = ts
            elif kind == "poll":
                bucket[B_POLLS] += 1
                if self._last_poll is not None and 0 < ts - self._last_poll <= POLL_MAX_GAP:
                    self.poll.add(ts - self._last_poll)
                self._last_poll = ts
        if rssi is not None:
            self.rssi_n += 1
            self.rssi_sum += rssi
            self.rssi_last = rssi
            self.rssi_min = rssi if self.rssi_min is None else min(self.rssi_min, rssi)
            self.rssi_max = rssi if self.rssi_max is None else max(self.rssi_max, rssi)
            b = rssi_bin(rssi)
            self.rssi_hist[b] = self.rssi_hist.get(b, 0) + 1
            bucket[B_RSSI_N] += 1
            bucket[B_RSSI_SUM] += rssi
            bucket[B_RSSI_MIN] = rssi if bucket[B_RSSI_MIN] is None else min(bucket[B_RSSI_MIN], rssi)
            bucket[B_RSSI_MAX] = rssi if bucket[B_RSSI_MAX] is None else max(bucket[B_RSSI_MAX], rssi)
        if lqi is not None:
            self.lqi_n += 1
            self.lqi_sum += lqi
            self.lqi_last = lqi
        self.first = ts if self.first is None else min(self.first, ts)
        self.last = ts if self.last is None else max(self.last, ts)
        return retry

    def record_addressed(self, ts: float, length: int | None = None) -> None:
        """A frame another node sent to this node."""
        bucket = self._bucket(ts)
        self.addressed += 1
        bucket[B_ADDRESSED] += 1
        if length:
            self.addressed_bytes += length

    def prune(self, now: float) -> None:
        cutoff = int(now // BUCKET_SECONDS) - BUCKET_KEEP
        for idx in [i for i in self.buckets if i < cutoff]:
            del self.buckets[idx]
            self.dirty.discard(idx)

    # ---- reading ------------------------------------------------------------

    def window(self, now: float, buckets: int) -> dict:
        """Sums over the last `buckets` buckets (including the current, partial one)."""
        now_idx = int(now // BUCKET_SECONDS)
        total = {name: 0 for name in ("frames", "bytes", "retries", "polls", "adv", "addressed")}
        rssi_n, rssi_sum = 0, 0.0
        for idx in range(now_idx - buckets + 1, now_idx + 1):
            b = self.buckets.get(idx)
            if not b:
                continue
            for name, pos in (("frames", B_FRAMES), ("bytes", B_BYTES), ("retries", B_RETRIES), ("polls", B_POLLS),
                              ("adv", B_ADV), ("addressed", B_ADDRESSED)):
                total[name] += b[pos]
            rssi_n += b[B_RSSI_N]
            rssi_sum += b[B_RSSI_SUM]
        total["retry_rate"] = total["retries"] / total["frames"] if total["frames"] else None
        total["rssi_avg"] = rssi_sum / rssi_n if rssi_n else None
        total["rssi_n"] = rssi_n
        return total

    def summary(self, now: float) -> dict:
        rssi = None
        if self.rssi_n:
            rssi = {"n": self.rssi_n, "avg": self.rssi_sum / self.rssi_n, "min": self.rssi_min, "max": self.rssi_max,
                    "last": self.rssi_last,
                    "hist": [[b, self.rssi_hist.get(b, 0)] for b in range(RSSI_LOW, RSSI_HIGH, RSSI_STEP)]}
        lqi = {"n": self.lqi_n, "avg": self.lqi_sum / self.lqi_n, "last": self.lqi_last} if self.lqi_n else None
        return {
            "frames": self.frames, "bytes": self.bytes, "retries": self.retries,
            "retry_rate": self.retries / self.frames if self.frames else None,
            "kinds": dict(self.kinds), "addressed": self.addressed, "addressed_bytes": self.addressed_bytes,
            "rssi": rssi, "lqi": lqi, "adv": self.adv.summary(), "poll": self.poll.summary(),
            "first": self.first, "last": self.last,
            "last_hour": self.window(now, 6), "last_24h": self.window(now, 144),
        }

    def series(self, now: float, hours: int = 24) -> dict:
        n = int(hours * 3600 // BUCKET_SECONDS)
        now_idx = int(now // BUCKET_SECONDS)
        start = now_idx - n + 1
        out = {"bucket_seconds": BUCKET_SECONDS, "start": start * BUCKET_SECONDS,
               **{name: [] for name in ("frames", "retries", "polls", "adv", "addressed", "bytes")},
               "rssi_avg": [], "rssi_min": [], "rssi_max": []}
        for idx in range(start, now_idx + 1):
            b = self.buckets.get(idx) or _new_bucket()
            for name, pos in (("frames", B_FRAMES), ("retries", B_RETRIES), ("polls", B_POLLS), ("adv", B_ADV),
                              ("addressed", B_ADDRESSED), ("bytes", B_BYTES)):
                out[name].append(b[pos])
            out["rssi_avg"].append(b[B_RSSI_SUM] / b[B_RSSI_N] if b[B_RSSI_N] else None)
            out["rssi_min"].append(b[B_RSSI_MIN])
            out["rssi_max"].append(b[B_RSSI_MAX])
        return out

    # ---- merging and persistence -------------------------------------------

    def merge(self, other: "NodeStats") -> None:
        self.frames += other.frames
        self.bytes += other.bytes
        self.retries += other.retries
        for kind, n in other.kinds.items():
            self.kinds[kind] = self.kinds.get(kind, 0) + n
        self.addressed += other.addressed
        self.addressed_bytes += other.addressed_bytes
        self.rssi_n += other.rssi_n
        self.rssi_sum += other.rssi_sum
        for attr, pick in (("rssi_min", min), ("rssi_max", max)):
            mine, theirs = getattr(self, attr), getattr(other, attr)
            setattr(self, attr, theirs if mine is None else mine if theirs is None else pick(mine, theirs))
        self.rssi_last = self.rssi_last if self.rssi_last is not None else other.rssi_last
        for b, n in other.rssi_hist.items():
            self.rssi_hist[b] = self.rssi_hist.get(b, 0) + n
        self.lqi_n += other.lqi_n
        self.lqi_sum += other.lqi_sum
        self.lqi_last = self.lqi_last if self.lqi_last is not None else other.lqi_last
        self.adv.merge(other.adv)
        self.poll.merge(other.poll)
        if other.first is not None:
            self.first = other.first if self.first is None else min(self.first, other.first)
        if other.last is not None:
            self.last = other.last if self.last is None else max(self.last, other.last)
        for idx, theirs in other.buckets.items():
            mine = self.buckets.setdefault(idx, _new_bucket())
            for pos in (B_FRAMES, B_BYTES, B_RETRIES, B_POLLS, B_ADV, B_ADDRESSED, B_RSSI_N, B_RSSI_SUM):
                mine[pos] += theirs[pos]
            for pos, pick in ((B_RSSI_MIN, min), (B_RSSI_MAX, max)):
                if theirs[pos] is not None:
                    mine[pos] = theirs[pos] if mine[pos] is None else pick(mine[pos], theirs[pos])
        self.dirty.update(self.buckets)  # re-save everything under the surviving node

    def to_json(self) -> dict:
        """Aggregates only; buckets are stored separately, a few at a time."""
        return {
            "frames": self.frames, "bytes": self.bytes, "retries": self.retries, "kinds": self.kinds,
            "addressed": self.addressed, "addressed_bytes": self.addressed_bytes,
            "rssi": [self.rssi_n, self.rssi_sum, self.rssi_min, self.rssi_max, self.rssi_last],
            "rssi_hist": {str(b): n for b, n in self.rssi_hist.items()},
            "lqi": [self.lqi_n, self.lqi_sum, self.lqi_last],
            "adv": self.adv.to_json(), "poll": self.poll.to_json(),
            "first": self.first, "last": self.last,
        }

    @classmethod
    def from_json(cls, data: dict | None) -> "NodeStats":
        st = cls()
        if not data:
            return st
        st.frames, st.bytes, st.retries = data["frames"], data["bytes"], data["retries"]
        st.kinds = dict(data.get("kinds", {}))
        st.addressed, st.addressed_bytes = data.get("addressed", 0), data.get("addressed_bytes", 0)
        st.rssi_n, st.rssi_sum, st.rssi_min, st.rssi_max, st.rssi_last = data["rssi"]
        st.rssi_hist = {int(b): n for b, n in data.get("rssi_hist", {}).items()}
        st.lqi_n, st.lqi_sum, st.lqi_last = data["lqi"]
        st.adv, st.poll = Interval.from_json(data.get("adv")), Interval.from_json(data.get("poll"))
        st.first, st.last = data.get("first"), data.get("last")
        return st

    def bucket_rows(self, only_dirty: bool = True) -> list[tuple[int, list]]:
        idxs = sorted(self.dirty if only_dirty else self.buckets)
        return [(i, list(self.buckets[i])) for i in idxs if i in self.buckets]

    def load_bucket(self, idx: int, values: list) -> None:
        self.buckets[idx] = list(values)
