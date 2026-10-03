"""Guided tests of Thread behaviour. The program cannot switch devices off; the user does that, and the test
records what the network does about it.

Router outage: the user picks a router and starts the test, then cuts the router's power. The test follows what
the sniffer (and, if running, the active diagnostics) sees: when the router fell silent, which of its children
searched for a parent, where and after how long they attached, and which did not come back.
"""

from __future__ import annotations

from . import addresses as A
from .engine import Engine

MAX_DURATION = 30 * 60.0   # a test that is not stopped ends by itself
ROUTER_SILENT = 60.0       # no frame from the router for this long: it is off (it advertises every ~30 s)


def _rel(ts: float | None, start: float) -> float | None:
    return None if ts is None else round(max(0.0, ts - start), 1)


class RouterOutageTest:
    kind = "router_outage"

    def __init__(self, engine: Engine, node_id: str, now: float):
        with engine.lock:
            router = engine.nodes.get(node_id)
            if router is None or router.rloc16 is None or not A.is_router_rloc(router.rloc16):
                raise ValueError("not a router with a known short address")
            self.node_id, self.rloc16, self.router_id = node_id, router.rloc16, A.router_id(router.rloc16)
            self.was_leader = engine.role_of(router) == "leader"
            self.leader_before = engine.leaders.get(engine.partition_of(router))
            self.children = {n.id: n.rloc16 for n in engine.nodes.values()
                             if n.rloc16 is not None and not A.is_router_rloc(n.rloc16)
                             and A.router_id(n.rloc16) == self.router_id}
        self.start, self.end = now, None

    @property
    def running(self) -> bool:
        return self.end is None

    def finish(self, now: float) -> None:
        if self.end is None:
            self.end = now

    def report(self, engine: Engine, now: float) -> dict:
        if self.end is None and now - self.start >= MAX_DURATION:
            self.finish(self.start + MAX_DURATION)
        until = self.end if self.end is not None else now
        with engine.lock:
            router = engine.nodes.get(self.node_id)
            heard = router.last_heard if router is not None and router.last_heard else None
            silent_since = heard if heard is not None and until - heard >= ROUTER_SILENT else None
            links_left = sum(1 for (src, dst), m in engine.links.items()
                             if dst == self.router_id and src != self.router_id and engine.link_is_fresh(m)
                             and min(m["lq_in"], m["lq_out"]) > 0)
            pid = engine.partition_of(router) if router is not None else engine.primary_partition
            leader_now = engine.leaders.get(pid)
            children = [self._child(engine, nid, rloc) for nid, rloc in self.children.items()]
        moved = [c for c in children if c["status"] == "moved"]
        return {
            "id": int(self.start), "kind": self.kind, "running": self.running, "start": self.start, "end": self.end,
            "duration": round(until - self.start, 1), "router": self.node_id, "router_name": engine.names.get(self.node_id),
            "router_rloc16": f"0x{self.rloc16:04x}", "router_id": self.router_id, "was_leader": self.was_leader,
            "router_last_heard": heard, "router_silent_after": _rel(silent_since, self.start),
            "links_left": links_left, "leader_before": self.leader_before, "leader_now": leader_now,
            "children": children,
            "summary": {"children": len(children), "moved": len(moved),
                        "not_back": sum(1 for c in children if c["status"] != "moved"),
                        "longest": max((c["attached_after"] or 0 for c in moved), default=None)},
        }

    def _child(self, engine: Engine, nid: str, rloc_before: int) -> dict:
        node = engine.nodes.get(nid)
        out = {"id": nid, "name": engine.names.get(nid), "rloc16_before": f"0x{rloc_before:04x}", "status": "waiting",
               "searched_after": None, "attached_after": None, "new_parent": None, "last_heard": None}
        if node is None:
            return out
        out["last_heard"] = node.last_heard or None
        events = [ev for ev in node.events if ev["ts"] >= self.start and (self.end is None or ev["ts"] <= self.end)]
        search = next((ev["ts"] for ev in events if ev["kind"] == "parent_search"), None)
        attach = next((ev for ev in events if ev["kind"] in ("attached", "parent")), None)
        parent = engine.parent_router_id(node)
        out["searched_after"] = _rel(search, self.start)
        if parent is not None and parent != self.router_id:
            out["status"], out["new_parent"] = "moved", parent
            out["attached_after"] = _rel(attach["ts"], self.start) if attach else None
        elif search is not None:
            out["status"] = "searching"
        return out
