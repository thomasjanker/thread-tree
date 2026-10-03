"""Synthetic Thread network for the UI demo and for tests (no hardware needed)."""

from __future__ import annotations

import random
import threading
import time

from . import addresses as A
from .engine import Engine

ML_PREFIX = 0xFD123456789A0001
OMR_PREFIX = 0xFDAB000000010000

# nodes that are known only from other nodes' traffic (out of sniffer range)
INDIRECT = {"c8d1d1fffe000016", "a4c138fffe100007"}

# router id -> (ext address, name, is border router)
ROUTERS = {
    0: ("c8d1d1fffe000001", "Leader", False),
    5: ("c8d1d1fffe000005", "Border router (hub)", True),
    9: ("c8d1d1fffe000009", "Router", False),
    17: ("c8d1d1fffe000011", "Router", False),
    22: ("c8d1d1fffe000016", "Router", False),
}
LINKS = [(0, 5, 3, 3), (0, 9, 3, 2), (5, 17, 2, 3), (9, 22, 3, 3), (9, 17, 1, 1)]
# (parent router id, child id, ext, ftd, rx_on_idle)
CHILDREN = [
    (0, 1, "a4c138fffe100001", False, True),
    (5, 1, "a4c138fffe100002", False, False),
    (5, 2, "a4c138fffe100003", True, True),
    (9, 1, "a4c138fffe100004", False, False),
    (17, 1, "a4c138fffe100005", False, False),
    (17, 2, "a4c138fffe100006", False, True),
    (22, 1, "a4c138fffe100007", True, True),
]


def _iid_addr(prefix: int, ext: str) -> str:
    return str(A.addr_from(prefix, (int(ext, 16) * 0x9E3779B97F4A7C15) & ((1 << 64) - 1)))


def _observe(engine: Engine, now: float, ext: str, rloc16: int):
    if ext in INDIRECT:
        return engine.node_for(now, ext=ext, rloc16=rloc16, touch=False)
    return engine.on_frame(now, ext, rloc16)


def advertise(engine: Engine, now: float) -> None:
    """What every router's MLE advertisement carries: leader data and its links (Route64)."""
    with engine.lock:
        by_router: dict[int, list] = {}
        for a, b, lq_in, lq_out in LINKS:
            by_router.setdefault(a, []).append((b, lq_in, lq_out, 1))
            by_router.setdefault(b, []).append((a, lq_out, lq_in, 1))
        for rid, entries in by_router.items():
            node = engine.nodes.get(engine.rloc_index.get(rid << 10, ""))
            engine.on_leader_data(now, node, 0x1A2B3C4D, 0)
            engine.on_route64(now, rid << 10, entries)


# ext -> (mean RSSI at the sniffer in dBm, data frames per 10 minutes, share of retransmitted frames, polls per 10 min)
PROFILES = {
    "c8d1d1fffe000001": (-62, 40, 0.01, 0),    # leader
    "c8d1d1fffe000005": (-68, 110, 0.02, 0),   # border router
    "c8d1d1fffe000009": (-79, 30, 0.06, 0),
    "c8d1d1fffe000011": (-89, 25, 0.24, 0),    # far away and noisy: weak signal, many retransmissions
    "a4c138fffe100001": (-66, 50, 0.02, 0),    # MED
    "a4c138fffe100002": (-72, 4, 0.03, 150),   # SED
    "a4c138fffe100003": (-70, 60, 0.02, 0),    # FED
    "a4c138fffe100004": (-81, 4, 0.05, 150),   # SED
    "a4c138fffe100005": (-86, 4, 0.12, 150),   # SED that keeps changing its parent
    "a4c138fffe100006": (-77, 40, 0.04, 0),    # MED
}
FLAPPER = "a4c138fffe100005"


def _flapper_rloc(parent: int) -> int:
    """Its short address at a router; the child ID differs per router so it never collides with another child."""
    return (parent << 10) | (1 if parent == 17 else 8)
_ROUTER_EXT = {ext for ext, _, _ in ROUTERS.values()}
BUCKET = 600


def _frames(engine: Engine, rng: random.Random, node, ext: str, start: float, seq: list) -> None:
    """One 10-minute bucket of traffic of a node, the way a sniffer would have heard it."""
    mean, data, retry, polls = PROFILES[ext]
    plan = [(rng.uniform(0, BUCKET), "data") for _ in range(max(0, int(rng.gauss(data, data * 0.2))))]
    plan += [(i * BUCKET / polls + rng.uniform(0, 1), "poll") for i in range(polls)]
    if ext in _ROUTER_EXT:
        plan += [(i * BUCKET / 19 + rng.uniform(0, 2), "adv") for i in range(19)]  # about one per 32 s
    for offset, kind in sorted(plan):
        seq[0] = (seq[0] + 1) % 256
        rssi = max(-100, min(-20, round(rng.gauss(mean, 3))))
        dst = "ffff" if kind == "adv" else "1400"
        length = {"adv": 60, "poll": 12, "data": 90}[kind]
        engine.record_frame(start + offset, node, kind, length, rssi, 150, seq[0], dst)
        if rng.random() < retry:
            engine.record_frame(start + offset + 0.01, node, kind, length, rssi, 150, seq[0], dst)


def _count(rng: random.Random, expected: float) -> int:
    """Whole number of events for an expected fractional count."""
    return int(expected) + (rng.random() < expected - int(expected))


def _frames_slice(engine: Engine, rng: random.Random, node, ext: str, now: float, seq: list, share: float) -> None:
    """The part of a 10-minute traffic profile that falls into one live step (`share` of a bucket)."""
    mean, data, retry, polls = PROFILES[ext]
    kinds = ["data"] * _count(rng, data * share) + ["poll"] * _count(rng, polls * share)
    if ext in _ROUTER_EXT:
        kinds += ["adv"] * _count(rng, 19 * share)
    for kind in kinds:
        seq[0] = (seq[0] + 1) % 256
        rssi = max(-100, min(-20, round(rng.gauss(mean, 3))))
        dst = "ffff" if kind == "adv" else "1400"
        length = {"adv": 60, "poll": 12, "data": 90}[kind]
        engine.record_frame(now, node, kind, length, rssi, 150, seq[0], dst)
        if rng.random() < retry:
            engine.record_frame(now + 0.01, node, kind, length, rssi, 150, seq[0], dst)


def seed_history(engine: Engine, now: float, hours: int = 24, seed: int = 7) -> None:
    """A believable past for the demo: traffic statistics and events (an outage, a parent that keeps changing)."""
    rng = random.Random(seed)
    first = now - hours * 3600
    with engine.lock:
        for ext in PROFILES:
            node = engine.nodes.get(ext)
            if node is None:
                continue
            node.first_seen = first
            for event in node.events:
                if event["kind"] == "first_seen":
                    event["ts"] = first
            seq = [rng.randrange(256)]
            for b in range(int(first // BUCKET), int(now // BUCKET)):
                _frames(engine, rng, node, ext, max(first, b * BUCKET), seq)
        weak_router = engine.nodes.get("c8d1d1fffe000011")
        if weak_router is not None:  # an outage of this router a few hours ago
            engine._log(weak_router, now - 5.0 * 3600, "offline")
            engine._log(weak_router, now - 4.8 * 3600, "online")
        flapper = engine.nodes.get(FLAPPER)
        if flapper is not None:
            parents = [17, 9, 17, 9, 17, 9]
            for i, (old, new) in enumerate(zip(parents, parents[1:])):
                ts = now - (len(parents) - i) * 1800
                engine._log(flapper, ts, "parent", **{"from": old, "to": new},
                            rloc16_from=f"0x{_flapper_rloc(old):04x}", rloc16_to=f"0x{_flapper_rloc(new):04x}")
        for node in engine.nodes.values():
            node.events.sort(key=lambda e: e["ts"])


def populate(engine: Engine, now: float | None = None, history: bool = False) -> None:
    now = time.time() if now is None else now
    with engine.lock:
        engine.fixed_ml_prefix = ML_PREFIX
        for rid, (ext, _, is_br) in ROUTERS.items():
            node = _observe(engine, now, ext, rid << 10)
            engine.on_leader_data(now, node, 0x1A2B3C4D, 0)
            engine.on_address_notification(now, _iid_addr(ML_PREFIX, ext), rid << 10)
            if is_br:
                node.border_router = True
                engine.on_address_notification(now, _iid_addr(OMR_PREFIX, ext), rid << 10)
                engine.on_address_notification(now, str(A.addr_from(0x2A0201234567AA00, 0x1)), rid << 10)
        advertise(engine, now)
        for prid, cid, ext, ftd, idle in CHILDREN:
            node = _observe(engine, now, ext, (prid << 10) | cid)
            engine.on_mode(now, node, ftd, idle)
            engine.on_registered_addresses(now, node, [_iid_addr(ML_PREFIX, ext)])
        if history:
            seed_history(engine, now)


class Simulator(threading.Thread):
    """Keeps the demo network alive: traffic with statistics, advertisements, an occasionally moving child."""

    def __init__(self, engine: Engine, interval: float = 5.0):
        super().__init__(daemon=True, name="simulator")
        self.engine, self.interval = engine, interval
        self.rng = random.Random(1)
        self.seqs = {ext: [self.rng.randrange(256)] for ext in PROFILES}
        self._stop_evt = threading.Event()

    def step(self, now: float) -> None:
        share = self.interval / BUCKET
        with self.engine.lock:
            for ext in PROFILES:
                node = self.engine.nodes.get(ext)
                if node is not None:
                    self.engine.on_frame(now, ext, node.rloc16)  # heard directly: stays online
                    _frames_slice(self.engine, self.rng, node, ext, now, self.seqs[ext], share)
            for node in list(self.engine.nodes.values()):
                if node.ext in INDIRECT:  # never heard, but other nodes keep addressing it
                    self.engine.on_destination(now, node.ext)
            advertise(self.engine, now)
            flapper = self.engine.nodes.get(FLAPPER)
            if flapper is not None and self.rng.random() < 0.02:  # now and then it moves to the other router
                new_parent = 9 if flapper.rloc16 and (flapper.rloc16 >> 10) == 17 else 17
                self.engine.on_frame(now, FLAPPER, _flapper_rloc(new_parent))
            self.engine.dirty = True

    def run(self) -> None:
        while not self._stop_evt.wait(self.interval):
            self.step(time.time())

    def stop(self) -> None:
        self._stop_evt.set()
