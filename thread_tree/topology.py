"""Builds the UI snapshot (nodes + per-partition tree) from engine state."""

from __future__ import annotations

import heapq
import time

from . import addresses as A
from .engine import Engine, Node, ROLE_LEADER, ROLE_ROUTER, ROLE_UNKNOWN

# Seconds without a frame before a node is shown as offline.
OFFLINE_AFTER = {"leader": 900, "router": 900, "med": 3600, "fed": 3600, "sed": 6 * 3600,
                 "child": 6 * 3600, "unknown": 6 * 3600}
# After this long without a frame that shows the MAC address, the device is identified only through its
# short address: if that address was handed to another device unnoticed, the name could be on the wrong one.
IDENTITY_VIA_RLOC_AFTER = 3600.0
_TYPE_ORDER = {A.ML_EID: 0, A.OMR: 1, A.RLOC: 2, A.ALOC: 3, A.LINK_LOCAL: 4, A.UNCLASSIFIED: 5}


def _online(n: Node, role: str, now: float) -> dict:
    """A device that was ever heard is judged only by its own activity. A device never heard
    directly counts as "online (indirect)" while other nodes keep sending frames to it."""
    limit = OFFLINE_AFTER.get(role, 3600)
    if n.last_heard > 0:
        return {"online": now - n.last_seen <= limit, "online_indirect": False}
    indirect = now - max(n.last_seen, n.last_addressed) <= limit
    return {"online": indirect, "online_indirect": indirect}


def _node_addresses(engine: Engine, node: Node, role: str) -> list[dict]:
    prefix = engine.ml_prefix
    out: dict[str, dict] = {}

    def put(addr: str, kind: str, source: str, last_seen: float | None) -> None:
        out.setdefault(addr, {"addr": addr, "type": kind, "source": source, "last_seen": last_seen})

    if node.ext:
        put(str(A.link_local_from_ext(node.ext)), A.LINK_LOCAL, "derived", None)
    if prefix is not None and node.rloc16 is not None:
        put(str(A.rloc_address(prefix, node.rloc16)), A.RLOC, "derived", None)
        if role == ROLE_LEADER:
            put(str(A.rloc_address(prefix, 0xFC00)), A.ALOC, "derived", None)
    for text, (_, last) in node.addresses.items():
        addr = A.parse_ip(text)
        if addr is not None:
            put(text, A.classify(addr, prefix), "observed", last)
    return sorted(out.values(), key=lambda a: (_TYPE_ORDER.get(a["type"], 9), a["addr"]))


def snapshot(engine: Engine, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    with engine.lock:
        roles = {n.id: engine.role_of(n) for n in engine.nodes.values()}
        nodes: dict[str, dict] = {}
        pids: dict[str, int] = {}
        default_pid = engine.primary_partition if engine.primary_partition is not None else 0
        for n in engine.nodes.values():
            # a partition that stopped sending leader data is gone: its nodes belong to the current one
            pid = n.partition_id if engine.is_current_partition(n.partition_id) else None
            if pid is None and n.rloc16 is not None and not A.is_router_rloc(n.rloc16):
                parent = engine.nodes.get(engine.rloc_index.get(A.parent_rloc16(n.rloc16), ""))
                if parent is not None and engine.is_current_partition(parent.partition_id):
                    pid = parent.partition_id
            pids[n.id] = pid if pid is not None else default_pid
            role = roles[n.id]
            nodes[n.id] = {
                "id": n.id, "ext": n.ext,
                "rloc16": None if n.rloc16 is None else f"0x{n.rloc16:04x}",
                "router_id": None if n.rloc16 is None else A.router_id(n.rloc16),
                "parent_router_id": (A.router_id(n.rloc16) if n.rloc16 is not None and not A.is_router_rloc(n.rloc16)
                                     else A.router_id(n.parent_hint) if n.rloc16 is None and n.parent_hint is not None
                                     else None),
                "child_id": None if n.rloc16 is None or A.is_router_rloc(n.rloc16) else A.child_id(n.rloc16),
                "name": engine.names.get(n.id),
                "role": role, "border_router": n.border_router, "partition_id": pids[n.id],
                "ftd": n.ftd, "rx_on_idle": n.rx_on_idle,
                **_online(n, role, now),
                "first_seen": n.first_seen, "last_seen": n.last_seen, "last_addressed": n.last_addressed,
                "heard": n.last_heard > 0, "last_heard": n.last_heard,
                "mac_confirmed": n.mac_confirmed,
                "identity_via_rloc": bool(n.ext and n.rloc16 is not None
                                          and n.last_heard - n.mac_confirmed > IDENTITY_VIA_RLOC_AFTER),
                "addresses": _node_addresses(engine, n, role),
            }
        by_rid = {(pids[n.id], A.router_id(n.rloc16)): n.id for n in engine.nodes.values()
                  if n.rloc16 is not None and A.is_router_rloc(n.rloc16)}
        links = []
        for (src, dst), m in engine.links.items():
            if m["lq_in"] <= 0 and m["lq_out"] <= 0:
                continue  # a route over other routers (Route64 lists every router), not a radio link
            for (pid, rid), nid in by_rid.items():
                if rid == src:
                    links.append({"from": nid, "to": by_rid.get((pid, dst)), "from_router_id": src,
                                  "to_router_id": dst, "stale": not engine.link_is_fresh(m), **m})
        partitions = []
        for pid in sorted(set(pids.values()) | {p for p in engine.leaders if engine.is_current_partition(p)}):
            members = [nodes[i] for i in nodes if nodes[i]["partition_id"] == pid]
            partitions.append(_partition(engine, pid, members, nodes, engine.links))
        return {
            "generated": now,
            "mesh_local_prefix": None if engine.ml_prefix is None else A.prefix_str(engine.ml_prefix),
            "partitions": partitions, "nodes": nodes, "links": links,
        }


def _placeholder(nodes: dict, nid: str, **extra) -> None:
    nodes[nid] = {"id": nid, "ext": None, "name": None, "rloc16": None, "router_id": None, "child_id": None,
                  "parent_router_id": None,
                  "role": ROLE_UNKNOWN, "border_router": False, "partition_id": None,
                  "ftd": None, "rx_on_idle": None, "online": False, "online_indirect": False, "first_seen": 0, "last_seen": 0, "last_addressed": 0,
                  "heard": False, "last_heard": 0, "mac_confirmed": 0, "identity_via_rloc": False,
                  "addresses": [], "placeholder": True, **extra}


def _partition(engine: Engine, pid: int, members: list[dict], nodes: dict, links: dict) -> dict:
    routers = {m["router_id"]: m for m in members
               if m["role"] in (ROLE_LEADER, ROLE_ROUTER) and m["router_id"] is not None}
    leader_rid = engine.leaders.get(pid)
    leader = routers.get(leader_rid) if leader_rid is not None else None

    if leader is not None:
        root = {"id": leader["id"], "edge": {"kind": "root"}, "children": []}
    else:
        root_id = f"partition:{pid}:root"
        _placeholder(nodes, root_id, role="leader-unknown")
        root = {"id": root_id, "edge": {"kind": "root"}, "children": []}

    # Routers form a mesh: span it with the best-quality shortest paths from the leader.
    adjacency: dict[int, list[tuple[int, float, int]]] = {rid: [] for rid in routers}
    for (a, b), m in links.items():
        if a in routers and b in routers and engine.link_is_fresh(m):
            if m["lq_in"] <= 0 or m["lq_out"] <= 0:
                continue  # a link needs both directions; 0 = not heard / route only
            lq = min(m["lq_in"], m["lq_out"])
            w = 1 + (3 - lq) * 0.2
            adjacency[a].append((b, w, lq))
            adjacency[b].append((a, w, lq))
    tree: dict[str, dict] = {root["id"]: root}
    if leader is not None:
        best = {leader["router_id"]: 0.0}
        queue = [(0.0, leader["router_id"])]
        while queue:
            dist, rid = heapq.heappop(queue)
            if dist > best.get(rid, 1e9):
                continue
            for nb, w, lq in adjacency[rid]:
                if dist + w < best.get(nb, 1e9):
                    best[nb] = dist + w
                    tree[routers[nb]["id"]] = {"id": routers[nb]["id"], "children": [],
                                               "edge": {"kind": "link", "lq": lq},
                                               "_parent": routers[rid]["id"]}
                    heapq.heappush(queue, (dist + w, nb))
    for rid, m in routers.items():
        if m["id"] not in tree:  # no known path to the leader
            tree[m["id"]] = {"id": m["id"], "children": [], "edge": {"kind": "unknown"}, "_parent": root["id"]}

    detached_id = f"partition:{pid}:detached"
    for m in members:
        if m["role"] in (ROLE_LEADER, ROLE_ROUTER) or m["id"] in tree:
            continue
        parent_id = None
        if m.get("parent_router_id") is not None:
            prid = m["parent_router_id"]
            if prid in routers:
                parent_id = routers[prid]["id"]
            else:
                parent_id = f"partition:{pid}:router:{prid}"
                if parent_id not in tree:
                    _placeholder(nodes, parent_id, role=ROLE_ROUTER, router_id=prid,
                                 rloc16=f"0x{prid << 10:04x}")
                    tree[parent_id] = {"id": parent_id, "children": [], "edge": {"kind": "unknown"},
                                       "_parent": root["id"]}
            kind = "child"
        else:
            if detached_id not in tree:
                _placeholder(nodes, detached_id, role="detached")
                tree[detached_id] = {"id": detached_id, "children": [], "edge": {"kind": "unknown"},
                                     "_parent": root["id"]}
            parent_id, kind = detached_id, "unknown"
        tree[m["id"]] = {"id": m["id"], "children": [], "edge": {"kind": kind}, "_parent": parent_id}
        if m.get("parent_router_id") is not None:
            nodes[m["id"]]["parent"] = parent_id

    for nid, t in tree.items():
        parent = t.pop("_parent", None)
        if parent is not None:
            tree[parent]["children"].append(t)
    for t in tree.values():
        t["children"].sort(key=lambda c: (nodes[c["id"]]["rloc16"] or "~", c["id"]))
    counts: dict[str, int] = {}
    for m in members:
        counts[m["role"]] = counts.get(m["role"], 0) + 1
    return {"id": pid, "leader_router_id": leader_rid, "root": root, "counts": counts}
