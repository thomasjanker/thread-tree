"""Synthetic Thread network for the UI demo and for tests (no hardware needed)."""

from __future__ import annotations

import random
import threading
import time

from . import addresses as A
from .engine import Engine
from .otdiag import Child, Router, RouterNeighbor

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


def off_router_id(engine: Engine) -> int | None:
    """The router the demo's outage test switched off (engine.demo_outage = (ext, start)), if any."""
    outage = getattr(engine, "demo_outage", None)
    return next((rid for rid, (ext, _, _) in ROUTERS.items() if outage and ext == outage[0]), None)


def advertise(engine: Engine, now: float) -> None:
    """What every router's MLE advertisement carries: leader data and its links (Route64)."""
    with engine.lock:
        off = off_router_id(engine)
        by_router: dict[int, list] = {}
        for a, b, lq_in, lq_out in LINKS:
            if off in (a, b):
                continue
            by_router.setdefault(a, []).append((b, lq_in, lq_out, 1))
            by_router.setdefault(b, []).append((a, lq_out, lq_in, 1))
        for rid in ROUTERS:
            if rid == off:
                continue
            entries = by_router.get(rid, [])  # a router whose only neighbour is off still advertises: no links
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
                # it lost its parent, searched (a few Parent Requests) and attached to the other router
                engine._log(flapper, ts - 40, "parent_search", parent=old)
                engine._log(flapper, ts - 4, "attached", to=new, seconds=36, requests=3)
                engine._log(flapper, ts, "parent", **{"from": old, "to": new},
                            rloc16_from=f"0x{_flapper_rloc(old):04x}", rloc16_to=f"0x{_flapper_rloc(new):04x}")
        window = engine.nodes.get(OLD_CHILD)
        if window is not None:  # a sleepy device that went quiet for longer than its child timeout
            engine._log(window, now - 3 * 3600, "poll_gap", seconds=420, usual=4.0, timeout=240)
        for node in engine.nodes.values():
            node.events.sort(key=lambda e: e["ts"])


# ---- active diagnostics: what a node that joined the network and asked it would have learned -------------

VERSIONS = {0: 5, 5: 5, 9: 4, 17: 4, 22: 5}   # Thread version of each router: 4 = 1.3, 5 = 1.4
NO_DETAIL = {17}                              # an old router: answers the topology query, not the detail queries
STICK = "f4ce36fffe0000d1"                    # the diagnostic node: a stick that joined as a child of the border router
STICK_RLOC = (5 << 10) | 3
VENDORS = {                                   # devices that answer the vendor query (made-up names)
    "c8d1d1fffe000001": ("Example Corp", "Hub 1", "1.4.2"),
    "c8d1d1fffe000005": ("Example Corp", "Border Router 2", "2.1.0"),
    "c8d1d1fffe000009": ("Sample Lighting", "Bulb A60", "1.0.7"),
    "c8d1d1fffe000016": ("Sample Lighting", "Plug 3", "1.0.7"),
    "a4c138fffe100001": ("Demo Sensors", "Motion 1", "0.9.1"),
    "a4c138fffe100003": ("Demo Sensors", "Switch 2", "0.9.1"),
    "a4c138fffe100007": ("Sample Lighting", "Bulb A60", "1.0.7"),
}
OLD_CHILD = "a4c138fffe100004"                # a sleepy device at the edge of its parent's range: nearly dropped out
CHILD_LINK = {OLD_CHILD: (-91, 27.0, 1.5)}    # its link, which the passive statistics cannot show (RSS, frame %, message %)
# link quality -> (RSS dBm, frame error %, message error %) of a typical link of that quality
LINK_BY_LQ = {3: (-62, 2.0, 0.0), 2: (-82, 6.5, 0.2), 1: (-93, 38.0, 4.0)}


def _link_values(rng: random.Random, rss: int, frame_err: float, msg_err: float) -> dict:
    rss = rss + rng.randint(-2, 2)
    return {"rss_ave": rss, "rss_last": rss + rng.randint(-2, 2), "margin": rss + 100,
            "frame_err": round(max(0.0, frame_err * rng.uniform(0.85, 1.15)), 2), "msg_err": msg_err}


def seed_active(engine: Engine, now: float, seed: int = 3) -> None:
    """Feed the engine what one round of the active diagnostics returns, through the same methods the
    collector uses: versions, both ends of every link, signal and error rates, children with their parent's
    view, vendor data, and the diagnostic node itself."""
    rng = random.Random(seed + int(now // 60))
    with engine.lock:
        engine.set_diag_self(STICK)
        engine.on_frame(now, STICK, STICK_RLOC)     # the stick sits next to the sniffer: heard directly
        stick = engine.nodes[STICK]
        engine.on_mode(now, stick, True, True)      # a full Thread device that stays an end device
        engine.record_frame(now, stick, "data", 80, -45, 200, rng.randrange(256), "1400")
        routers: list[Router] = []
        off = off_router_id(engine)
        for rid, (ext, _, is_br) in ROUTERS.items():
            if rid == off:
                continue  # switched off by the outage test: it does not answer
            links: dict[int, list[int]] = {}
            for a, b, lq_in, lq_out in LINKS:
                if off in (a, b):
                    continue
                if rid == a:
                    links.setdefault(lq_in, []).append(b)
                elif rid == b:
                    links.setdefault(lq_out, []).append(a)
            children = []
            for node in sorted(engine.nodes.values(), key=lambda n: n.rloc16 or 0):
                if node.rloc16 is None or A.is_router_rloc(node.rloc16) or (node.rloc16 >> 10) != rid:
                    continue
                mode = ("r" if node.rx_on_idle else "") + ("d" if node.ftd else "") + ("n" if node.ftd else "")
                children.append(Child(rloc16=node.rloc16, lq=3 if node.rx_on_idle else 2, mode=mode,
                                      me=node.ext == STICK))
            routers.append(Router(router_id=rid, rloc16=rid << 10, ext=ext, version=VERSIONS[rid], leader=rid == 0,
                                  border_router=is_br, links=links, children=children))
        engine.on_diag_topology(now, routers, 0x1A2B3C4D)

        by_rid = {rid: ext for rid, (ext, _, _) in ROUTERS.items()}
        for r in routers:
            if r.router_id in NO_DETAIL:
                continue
            neighbors = []
            for a, b, lq_in, lq_out in LINKS:
                other, lq = (b, lq_in) if r.router_id == a else (a, lq_out) if r.router_id == b else (None, 0)
                if other is not None and other != off:
                    neighbors.append(RouterNeighbor(rloc16=other << 10, ext=by_rid[other], version=VERSIONS[other],
                                                    conn_time=rng.randint(40_000, 400_000), **_link_values(rng, *LINK_BY_LQ[lq])))
            engine.on_diag_neighbors(now, r.rloc16, neighbors)
            kids = []
            for c in r.children or []:
                node = engine.nodes[engine.rloc_index[c.rloc16]]
                sleepy = not node.rx_on_idle
                rss, err, msg = (CHILD_LINK.get(node.ext) or (PROFILES[node.ext][0], PROFILES[node.ext][2] * 220, 0.0)
                                 if node.ext in PROFILES else (-45, 0.0, 0.0))
                age = 215 if node.ext == OLD_CHILD else rng.randint(0, 60) if sleepy else rng.randint(0, 5)
                kids.append(Child(rloc16=c.rloc16, ext=node.ext, version=5 if node.ftd else 4, timeout=240, age=age,
                                  supervision=129 if sleepy else 0, queued=0, rx_on_idle=bool(node.rx_on_idle),
                                  device_type="ftd" if node.ftd else "mtd", full_net=bool(node.ftd),
                                  conn_time=rng.randint(1_000, 800_000), **_link_values(rng, rss, err, msg)))
            engine.on_diag_childtable(now, kids)
        asked = 0
        for node in list(engine.nodes.values()):
            if node.rloc16 is None or node.vendor is not None or node.ext not in VENDORS and node.ext not in (
                    e for e, _, _ in ROUTERS.values()):
                continue
            vendor = VENDORS.get(node.ext)
            engine.on_diag_vendor(now, node.rloc16, None if vendor is None else
                                  {"name": vendor[0], "model": vendor[1], "sw": vendor[2], "stack": "1.4.0"})
            asked += vendor is not None
        engine.diag_info = {"enabled": True, "demo": True, "state": "idle", "error": None, "ts": now, "duration": 6.4,
                            "routers": len(routers), "children": sum(len(r.children or []) for r in routers),
                            "failures": {rid << 10: "ResponseTimeout" for rid in NO_DETAIL}, "vendor": asked,
                            "next": now + 300.0, "own_rloc16": engine.nodes[STICK].rloc16}


def refresh_active(engine: Engine, now: float) -> None:
    """Another round in the demo (also what 'query now' does there)."""
    seed_active(engine, now)


def populate(engine: Engine, now: float | None = None, history: bool = False, active: bool = False) -> None:
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
            if not idle:
                engine.on_child_timeout(now, node, 240)  # what sleepy devices announce when they attach
            engine.on_registered_addresses(now, node, [_iid_addr(ML_PREFIX, ext)])
        if history:
            seed_history(engine, now)
        if active:
            seed_active(engine, now)


class Simulator(threading.Thread):
    """Keeps the demo network alive: traffic with statistics, advertisements, an occasionally moving child."""

    def __init__(self, engine: Engine, interval: float = 5.0):
        super().__init__(daemon=True, name="simulator")
        self.engine, self.interval = engine, interval
        self.rng = random.Random(1)
        self.seqs = {ext: [self.rng.randrange(256)] for ext in PROFILES}
        self._active_at = 0.0
        self._stop_evt = threading.Event()

    def step(self, now: float) -> None:
        share = self.interval / BUCKET
        with self.engine.lock:
            off = off_router_id(self.engine)
            if off is not None:
                self._outage(now, off)
            for ext in PROFILES:
                node = self.engine.nodes.get(ext)
                if node is not None and not (off is not None and ext == ROUTERS[off][0]):  # a switched-off router is silent
                    self.engine.on_frame(now, ext, node.rloc16)  # heard directly: stays online
                    _frames_slice(self.engine, self.rng, node, ext, now, self.seqs[ext], share)
            for node in list(self.engine.nodes.values()):
                if node.ext in INDIRECT:  # never heard, but other nodes keep addressing it
                    self.engine.on_destination(now, node.ext)
            advertise(self.engine, now)
            if self.engine.diag_info.get("demo") and not self.engine.diag_info.get("paused"):  # a round every minute
                if self._active_at == 0.0:
                    self._active_at = now  # populate() has just done the first one
                elif now - self._active_at >= 60.0:
                    refresh_active(self.engine, now)
                    self._active_at = now
            flapper = self.engine.nodes.get(FLAPPER)
            if flapper is not None and off is None and self.rng.random() < 0.02:  # now and then it moves to the other router
                new_parent = 9 if flapper.rloc16 and (flapper.rloc16 >> 10) == 17 else 17
                self.engine.on_parent_request(now, flapper)  # it searches, then attaches to the other router
                self.engine.on_attach_request(now, flapper, self.engine.nodes.get(ROUTERS[new_parent][0]))
                self.engine.on_frame(now, FLAPPER, _flapper_rloc(new_parent))
            self.engine.dirty = True

    def _outage(self, now: float, off: int) -> None:
        """The outage test of the demo: the children of the switched-off router notice it after a while, search
        for a parent and attach to a neighbour of it (one after the other, the sleepy ones later)."""
        start = self.engine.demo_outage[1]
        neighbours = [b if a == off else a for a, b, *_ in LINKS if off in (a, b)]
        new_rid = next((r for r in neighbours if r != off), 0)
        new_router = self.engine.nodes.get(ROUTERS[new_rid][0])
        orphans = [n for n in self.engine.nodes.values()
                   if n.rloc16 is not None and not A.is_router_rloc(n.rloc16) and n.rloc16 >> 10 == off]
        for i, node in enumerate(sorted(orphans, key=lambda n: n.id)):
            notice = 20.0 + 15.0 * i + (40.0 if not node.rx_on_idle else 0.0)
            if now - start < notice:
                continue
            self.engine.on_parent_request(now - 6, node)
            self.engine.on_parent_request(now - 3, node)
            self.engine.on_attach_request(now, node, new_router)
            self.engine.on_frame(now, node.ext, (new_rid << 10) | (40 + i))

    def run(self) -> None:
        while not self._stop_evt.wait(self.interval):
            self.step(time.time())

    def stop(self) -> None:
        self._stop_evt.set()
