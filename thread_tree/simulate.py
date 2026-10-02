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


def populate(engine: Engine, now: float | None = None) -> None:
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


class Simulator(threading.Thread):
    """Keeps the demo network 'alive' and occasionally re-parents a child."""

    def __init__(self, engine: Engine, interval: float = 5.0):
        super().__init__(daemon=True, name="simulator")
        self.engine, self.interval = engine, interval
        self._stop_evt = threading.Event()

    def run(self) -> None:
        rng = random.Random(1)
        while not self._stop_evt.wait(self.interval):
            now = time.time()
            with self.engine.lock:
                for n in list(self.engine.nodes.values()):
                    if n.ext and rng.random() < 0.8:
                        n.last_seen = now
                advertise(self.engine, now)
                if rng.random() < 0.2:
                    prid, cid, ext, *_ = rng.choice([c for c in CHILDREN if c[2] not in INDIRECT])
                    new_parent = rng.choice(list(ROUTERS))
                    self.engine.on_frame(now, ext, (new_parent << 10) | cid)
                self.engine.dirty = True

    def stop(self) -> None:
        self._stop_evt.set()
