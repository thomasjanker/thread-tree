"""Guided tests of Thread behaviour. The program cannot switch devices off or pair them; the user does that, and
the test records what the network does about it, from what the sniffer (and, if running, the active diagnostics)
sees. Times in a report are seconds from the start of the test.

Outage tests (the user cuts a device's power): router outage, leader outage, border router outage, partition and
merge (cut the router that connects two parts), router upgrade (does an end device take over as router).
Other tests: router comes back (power a router on, or power-cycle it), re-attach after a battery change,
commissioning of a new device.
"""

from __future__ import annotations

from . import addresses as A
from .engine import Engine

MAX_DURATION = 30 * 60.0   # a test that is not stopped ends by itself
SILENT = 60.0              # no frame for this long: the device is off (a router advertises every ~30 s)
PARTITION_GONE = 45.0      # no leader data of a partition for this long: it is gone (its routers advertise every <=32 s)
OUTAGE_KINDS = ("router_outage", "leader_outage", "br_outage", "partition", "router_upgrade")
KINDS = OUTAGE_KINDS + ("router_return", "device_rejoin", "commissioning")


def _rel(ts: float | None, start: float) -> float | None:
    return None if ts is None else round(max(0.0, ts - start), 1)


def _is_router(node) -> bool:
    return node is not None and node.rloc16 is not None and A.is_router_rloc(node.rloc16)


def _current_partitions(engine: Engine) -> dict[int, int]:
    """Partitions whose leader data is still being sent: within PARTITION_GONE of the newest one (a partition whose
    leader is gone stops at once, while the engine keeps it for a few minutes)."""
    seen = engine.partition_seen
    newest = max(seen.values(), default=None)
    return {pid: rid for pid, rid in engine.leaders.items()
            if newest is None or seen.get(pid, newest) >= newest - PARTITION_GONE}


class Test:
    kind = ""
    needs_target = True

    def __init__(self, engine: Engine, target: str | None, now: float):
        self.target, self.start, self.end = target, now, None

    @property
    def running(self) -> bool:
        return self.end is None

    def finish(self, now: float) -> None:
        if self.end is None:
            self.end = now

    def observe(self, engine: Engine, now: float) -> None:
        """Called every few seconds while the test runs (for what events do not record)."""

    def until(self, now: float) -> float:
        if self.end is None and now - self.start >= MAX_DURATION:
            self.finish(self.start + MAX_DURATION)
        return self.end if self.end is not None else now

    def events(self, node, kinds: tuple[str, ...]) -> list[dict]:
        return [ev for ev in (node.events if node is not None else [])
                if ev["kind"] in kinds and ev["ts"] >= self.start and (self.end is None or ev["ts"] <= self.end)]

    def base(self, engine: Engine, now: float) -> dict:
        until = self.until(now)
        node = engine.nodes.get(self.target) if self.target else None
        return {"id": int(self.start), "kind": self.kind, "running": self.running, "start": self.start,
                "end": self.end, "duration": round(until - self.start, 1), "target": self.target,
                "target_name": engine.names.get(self.target) if self.target else None,
                "target_rloc16": None if node is None or node.rloc16 is None else f"0x{node.rloc16:04x}"}

    def report(self, engine: Engine, now: float) -> dict:
        with engine.lock:
            return self.base(engine, now)


# ---- outage tests ------------------------------------------------------------------------------------------

class OutageTest(Test):
    """The user cuts the power of the target router. Records its children, the mesh, the leader, partitions,
    border routers, new routers and the Network Data version, as they change."""

    def __init__(self, engine: Engine, target: str | None, now: float):
        super().__init__(engine, target, now)
        with engine.lock:
            node = engine.nodes.get(target or "")
            self.check(engine, node)
            self.rloc16, self.router_id = node.rloc16, A.router_id(node.rloc16)
            self.children = {n.id: n.rloc16 for n in engine.nodes.values()
                             if n.rloc16 is not None and not A.is_router_rloc(n.rloc16)
                             and A.router_id(n.rloc16) == self.router_id}
            self.partitions_before = _current_partitions(engine)
            self.leader_before = engine.leaders.get(engine.partition_of(node))
            self.partition_before = engine.partition_of(node)
            self.routers_before = {n.id for n in engine.nodes.values() if _is_router(n)}
            self.br_before = sorted(n.id for n in engine.nodes.values() if n.border_router)
            self.version_before = engine.data_versions.get(self.partition_before)
        self.timeline: list[dict] = []          # {"ts", "what", ...}: changes seen by observe()
        self._seen: dict = {}

    def check(self, engine: Engine, node) -> None:
        if not _is_router(node):
            raise ValueError("not a router with a known short address")

    def _change(self, now: float, what: str, value, **extra) -> None:
        if self._seen.get(what, object()) != value:
            if what in self._seen:
                self.timeline.append({"ts": now, "what": what, "value": value, **extra})
            self._seen[what] = value

    def observe(self, engine: Engine, now: float) -> None:
        if not self.running:
            return
        with engine.lock:
            parts = _current_partitions(engine)
            self._change(now, "partitions", len(parts), ids=sorted(parts))
            # the partition the network continues in: the old one while it lives, else the newest
            main = self.partition_before if self.partition_before in parts else max(
                parts, key=lambda p: engine.partition_seen.get(p, 0), default=None)
            leader = parts.get(main) if main is not None else None
            self._change(now, "leader", leader, partition=main)
            self._change(now, "partition", main)
            self._change(now, "brs", tuple(sorted(n.id for n in engine.nodes.values() if n.border_router)))
            self._change(now, "version", engine.data_versions.get(main) if main is not None else None)
            for n in engine.nodes.values():
                key = f"router:{n.id}"
                if _is_router(n) and n.id not in self.routers_before and n.id != self.target and key not in self._seen:
                    self._seen[key] = n.rloc16  # a new router: the first sighting is the event
                    self.timeline.append({"ts": now, "what": key, "value": n.rloc16, "node": n.id})

    def first(self, what: str, pred=lambda e: True) -> dict | None:
        return next((e for e in self.timeline if e["what"] == what and pred(e)), None)

    def report(self, engine: Engine, now: float) -> dict:
        self.observe(engine, now)
        with engine.lock:
            out = self.base(engine, now)
            until = out["end"] or self.until(now)
            node = engine.nodes.get(self.target)
            heard = node.last_heard if node is not None and node.last_heard else None
            silent_since = heard if heard is not None and until - heard >= SILENT else None
            links_left = sum(1 for (src, dst), m in engine.links.items()
                             if dst == self.router_id and src != self.router_id and engine.link_is_fresh(m)
                             and min(m["lq_in"], m["lq_out"]) > 0)
            parts = _current_partitions(engine)
            children = [self._child(engine, nid, rloc) for nid, rloc in self.children.items()]
            new_routers = [{"id": e["node"], "name": engine.names.get(e["node"]), "rloc16": f"0x{e['value']:04x}",
                            "after": _rel(e["ts"], self.start)} for e in self.timeline if e["what"].startswith("router:")]
            brs_now = sorted(n.id for n in engine.nodes.values() if n.border_router)
            split = self.first("partitions", lambda e: e["value"] > 1)
            merged = self.first("partitions", lambda e: split is not None and e["ts"] > split["ts"] and e["value"] <= 1)
            br_lost = self.first("brs", lambda e: self.target not in e["value"])
            leader_change = self.first("leader", lambda e: e["value"] is not None and e["value"] != self.leader_before)
        moved = [c for c in children if c["status"] == "moved"]
        out.update({
            "target_rloc16": f"0x{self.rloc16:04x}", "router_id": self.router_id,
            "router_last_heard": heard, "router_silent_after": _rel(silent_since, self.start), "links_left": links_left,
            "leader_before": self.leader_before, "leader_now": parts.get(self._seen.get("partition")) if self._seen.get("partition") is not None else None,
            "leader_changed_after": _rel(leader_change["ts"], self.start) if leader_change else None,
            "partition_before": self.partition_before, "partition_now": self._seen.get("partition"),
            "partitions_now": len(parts), "partitions_max": max([len(self.partitions_before)] + [e["value"] for e in self.timeline if e["what"] == "partitions"]),
            "split_after": _rel(split["ts"], self.start) if split else None,
            "merged_after": _rel(merged["ts"], self.start) if merged else None,
            "version_before": self.version_before, "version_now": self._seen.get("version"),
            "br_before": self.br_before, "br_now": brs_now,
            "br_lost_after": _rel(br_lost["ts"], self.start) if br_lost else None,
            "new_routers": new_routers, "children": children,
            "summary": {"children": len(children), "moved": len(moved),
                        "not_back": sum(1 for c in children if c["status"] != "moved"),
                        "longest": max((c["attached_after"] or 0 for c in moved), default=None)},
        })
        return out

    def _child(self, engine: Engine, nid: str, rloc_before: int) -> dict:
        node = engine.nodes.get(nid)
        out = {"id": nid, "name": engine.names.get(nid), "rloc16_before": f"0x{rloc_before:04x}", "status": "waiting",
               "searched_after": None, "attached_after": None, "new_parent": None, "last_heard": None}
        if node is None:
            return out
        out["last_heard"] = node.last_heard or None
        search = next((ev["ts"] for ev in self.events(node, ("parent_search",))), None)
        attach = next(iter(self.events(node, ("attached", "parent"))), None)
        parent = engine.parent_router_id(node)
        out["searched_after"] = _rel(search, self.start)
        if parent is not None and parent != self.router_id:
            out["status"], out["new_parent"] = "moved", parent
            out["attached_after"] = _rel(attach["ts"], self.start) if attach else None
        elif search is not None:
            out["status"] = "searching"
        return out


class RouterOutageTest(OutageTest):
    kind = "router_outage"


class LeaderOutageTest(OutageTest):
    kind = "leader_outage"

    def check(self, engine: Engine, node) -> None:
        super().check(engine, node)
        if engine.role_of(node) != "leader":
            raise ValueError("this router is not the leader")


class BorderRouterOutageTest(OutageTest):
    kind = "br_outage"

    def check(self, engine: Engine, node) -> None:
        super().check(engine, node)
        if not node.border_router:
            raise ValueError("this router is not a border router")


class PartitionTest(OutageTest):
    kind = "partition"


class RouterUpgradeTest(OutageTest):
    kind = "router_upgrade"


# ---- router comes back ---------------------------------------------------------------------------------------

class RouterReturnTest(Test):
    """The user powers a router on (or off and on again). When is it heard, when does it advertise, does it get its
    router ID back, do devices attach to it again."""
    kind = "router_return"

    def __init__(self, engine: Engine, target: str | None, now: float):
        super().__init__(engine, target, now)
        with engine.lock:
            node = engine.nodes.get(target or "")
            if node is None or (node.rloc16 is not None and not A.is_router_rloc(node.rloc16)) or (
                    node.rloc16 is None and engine.role_of(node) not in ("router", "leader")):
                raise ValueError("not a router")
            self.rloc16 = node.rloc16 if node.rloc16 is not None else None
            self.on_at_start = bool(node.last_heard) and now - node.last_heard < SILENT
            rid = A.router_id(node.rloc16) if node.rloc16 is not None else None
            self.children_before = sorted(n.id for n in engine.nodes.values() if rid is not None
                                          and n.rloc16 is not None and not A.is_router_rloc(n.rloc16) and A.router_id(n.rloc16) == rid)
        self.silent_at: float | None = None if self.on_at_start else now
        self.back_at: float | None = None
        self.adv_at: float | None = None

    def observe(self, engine: Engine, now: float) -> None:
        if not self.running:
            return
        with engine.lock:
            node = engine.nodes.get(self.target)
            if node is None:
                return
            heard = node.last_heard or 0.0
            if self.silent_at is None and now - heard >= SILENT:
                self.silent_at = heard            # it went off (power-cycle)
            if self.silent_at is not None and self.back_at is None and heard > self.silent_at:
                self.back_at = heard
            last_adv = node.stats._last_adv
            if self.back_at is not None and self.adv_at is None and last_adv is not None and last_adv >= self.back_at:
                self.adv_at = last_adv

    def report(self, engine: Engine, now: float) -> dict:
        self.observe(engine, now)
        with engine.lock:
            out = self.base(engine, now)
            node = engine.nodes.get(self.target)
            rid_now = A.router_id(node.rloc16) if node is not None and node.rloc16 is not None and A.is_router_rloc(node.rloc16) else None
            children_now = sorted(n.id for n in engine.nodes.values() if rid_now is not None and n.rloc16 is not None
                                  and not A.is_router_rloc(n.rloc16) and A.router_id(n.rloc16) == rid_now)
        out.update({
            "on_at_start": self.on_at_start, "silent_after": _rel(self.silent_at, self.start) if self.on_at_start else None,
            "back_after": _rel(self.back_at, self.start), "adv_after": _rel(self.adv_at, self.start),
            "rloc16_before": None if self.rloc16 is None else f"0x{self.rloc16:04x}",
            "rloc16_now": None if rid_now is None else f"0x{rid_now << 10:04x}",
            "same_id": None if rid_now is None or self.rloc16 is None else rid_now == A.router_id(self.rloc16),
            "children_before": len(self.children_before), "children_now": len(children_now),
            "returned": sorted(set(self.children_before) & set(children_now)),
        })
        return out


# ---- re-attach after a battery change ------------------------------------------------------------------------

class DeviceRejoinTest(Test):
    """The user takes the battery out of an end device and puts it back (or restarts it)."""
    kind = "device_rejoin"

    def __init__(self, engine: Engine, target: str | None, now: float):
        super().__init__(engine, target, now)
        with engine.lock:
            node = engine.nodes.get(target or "")
            if node is None or _is_router(node) or engine.role_of(node) in ("router", "leader"):
                raise ValueError("not an end device")
            self.rloc16 = node.rloc16
            self.parent_before = engine.parent_router_id(node)
            self.heard_before = node.last_heard or None
        self.silent_at: float | None = None

    def observe(self, engine: Engine, now: float) -> None:
        if not self.running:
            return
        with engine.lock:
            node = engine.nodes.get(self.target)
            if node is not None and self.silent_at is None and node.last_heard and now - node.last_heard >= SILENT:
                self.silent_at = node.last_heard

    def report(self, engine: Engine, now: float) -> dict:
        self.observe(engine, now)
        with engine.lock:
            out = self.base(engine, now)
            node = engine.nodes.get(self.target)
            search = self.events(node, ("parent_search",))
            attached = self.events(node, ("attached",))
            moved = self.events(node, ("parent", "rloc16"))
            parent_now = engine.parent_router_id(node) if node is not None else None
            back = node.last_heard if node is not None and node.last_heard and node.last_heard > max(
                self.silent_at or self.start, self.start) and (search or self.silent_at) else None
        out.update({
            "rloc16_before": None if self.rloc16 is None else f"0x{self.rloc16:04x}",
            "parent_before": self.parent_before, "parent_now": parent_now,
            "silent_after": _rel(self.silent_at, self.start),
            "searched_after": _rel(search[0]["ts"], self.start) if search else None,
            "requests": attached[0]["params"].get("requests") if attached else (len(search) or None),
            "attached_after": _rel((attached or moved)[0]["ts"], self.start) if (attached or moved) else None,
            "back_after": _rel(back, self.start),
            "status": "back" if (attached or moved) and back else "searching" if search else "silent" if self.silent_at else "waiting",
        })
        return out


# ---- commissioning --------------------------------------------------------------------------------------------

class CommissioningTest(Test):
    """The user pairs a new device. Lists every device seen for the first time during the test with its steps."""
    kind = "commissioning"
    needs_target = False

    def __init__(self, engine: Engine, target: str | None, now: float):
        super().__init__(engine, None, now)
        with engine.lock:
            self.known = set(engine.nodes)

    def report(self, engine: Engine, now: float) -> dict:
        with engine.lock:
            out = self.base(engine, now)
            until = self.until(now)
            devices = []
            for n in engine.nodes.values():
                if n.id in self.known or not (self.start <= n.first_seen <= until):
                    continue
                first = lambda kinds: next((ev["ts"] for ev in self.events(n, kinds)), None)
                parent = engine.parent_router_id(n)
                devices.append({"id": n.id, "name": engine.names.get(n.id), "role": engine.role_of(n),
                                "rloc16": None if n.rloc16 is None else f"0x{n.rloc16:04x}",
                                "first_seen_after": _rel(n.first_seen, self.start),
                                "discovery_after": _rel(first(("discovery",)), self.start),
                                "searched_after": _rel(first(("parent_search",)), self.start),
                                "attached_after": _rel(first(("attached",)), self.start),
                                "parent": parent, "heard": bool(n.last_heard)})
            discoveries = sum(len(self.events(n, ("discovery",))) for n in engine.nodes.values())
        devices.sort(key=lambda d: d["first_seen_after"] or 0)
        out.update({"devices": devices, "discoveries": discoveries})
        return out


CLASSES = {c.kind: c for c in (RouterOutageTest, LeaderOutageTest, BorderRouterOutageTest, PartitionTest,
                                RouterUpgradeTest, RouterReturnTest, DeviceRejoinTest, CommissioningTest)}


def make_test(kind: str, engine: Engine, target: str | None, now: float) -> Test:
    cls = CLASSES.get(kind)
    if cls is None:
        raise ValueError(f"unknown test {kind!r}")
    if cls.needs_target and not target:
        raise ValueError("this test needs a device")
    return cls(engine, target, now)
