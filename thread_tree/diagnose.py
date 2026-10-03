"""Diagnosis: findings per node and for the network, from the topology snapshot, the statistics and the history.

Most of it is derived from what a passive sniffer hears, so those findings are observations with the limits of
that method (see the explanations in the UI). With the active diagnostics (a node that joined the network and
asks it, see collector.py) there are also measurements the routers made themselves. Thresholds are constants
here on purpose.
"""

from __future__ import annotations

import csv
import io
from collections import defaultdict

from .engine import Engine
from .otdiag import THREAD_VERSIONS
from .topology import snapshot

SEVERITY_RANK = {"ok": 0, "info": 1, "warn": 2, "crit": 3}

DAY = 86400.0
RETRY_WARN = 0.15            # share of retransmitted frames (24 h) ...
RETRY_MIN_FRAMES = 50        # ... judged only with at least this many frames
RSSI_WEAK = -85.0            # dBm at the sniffer (24 h average) ...
RSSI_MIN_SAMPLES = 20        # ... with at least this many measurements
REPARENT_WARN = 3            # parent changes in 24 h
FLAP_WARN = 3                # role or short address changes of a router in 24 h
ADV_PER_HOUR_FAST = 360      # more than one MLE advertisement every 10 s on average: trickle timer keeps resetting
ADV_MIN_OBSERVED = 1800.0    # only after the router was observed this long
ROUTER_LIMIT = 32            # Thread allows at most 32 routers
ROUTER_NEAR_LIMIT = 28
SNIFFER_SILENT = 60.0        # seconds without any frame
MANY_OFFLINE = 0.3
LEADER_CHANGES_WARN = 2
# measurements of the routers themselves (active diagnostics); the error rates are percent
LINK_ERR_WARN = 25.0         # share of frames a device could not deliver to a neighbour (no acknowledgement) ...
MSG_ERR_WARN = 5.0           # ... or of messages that were lost although every frame was repeated
RSS_WEAK_LINK = -90          # dBm that a device receives from its neighbour: near what the radios can still decode
CHILD_AGE_WARN = 0.8         # share of its timeout that a parent has not heard a child
ACTIVE_STALE = 3600.0        # active measurements older than this say nothing about now (the collector stopped)


# Every code a finding can have; the UI needs a title, a text and a hint for each (tested in both languages).
FINDING_CODES = (
    "offline", "single_link", "weak_links", "asymmetric_link", "critical_router", "adv_fast", "role_flap",
    "unknown_parent", "parent_offline", "reparenting", "retry_high", "signal_weak", "indirect_only", "no_mac",
    "sniffer_silent", "decrypt_failing", "partitions", "no_border_router", "single_border_router", "router_limit",
    "router_near_limit", "leader_changes", "many_offline",
    "link_lossy", "child_link_poor", "child_age_high", "router_no_detail", "indirect_confirmed", "diag_failing",
)


def finding(code: str, severity: str, **params) -> dict:
    assert code in FINDING_CODES, code
    return {"code": code, "severity": severity, "params": params}


def worst(findings: list[dict]) -> str:
    return max((f["severity"] for f in findings), key=SEVERITY_RANK.get, default="ok")


# ---- router graph -------------------------------------------------------------------------------------

def _router_graph(engine: Engine, nodes: dict) -> dict:
    """Per partition: routers and the fresh links between them (bidirectional ones form the graph)."""
    graphs: dict[int, dict] = {}
    for nid, n in nodes.items():
        if n.get("placeholder") or n["role"] not in ("leader", "router") or n["router_id"] is None:
            continue
        g = graphs.setdefault(n["partition_id"], {"routers": {}, "adj": defaultdict(set), "pairs": {}})
        g["routers"][n["router_id"]] = nid
    for pid, g in graphs.items():
        for (src, dst), m in engine.links.items():
            a, b = g["routers"].get(src), g["routers"].get(dst)
            if a is None or b is None or a == b:
                continue
            fresh = engine.link_is_fresh(m)
            pair = g["pairs"].setdefault(frozenset((a, b)), {"a": a, "b": b, "reports": []})
            pair["reports"].append({"from": a, "lq_in": m["lq_in"], "lq_out": m["lq_out"], "cost": m["cost"],
                                    "fresh": fresh, "last_seen": m["last_seen"]})
            if fresh and m["lq_in"] > 0 and m["lq_out"] > 0:
                g["adj"][a].add(b)
                g["adj"][b].add(a)
    return graphs


def _components(adj: dict, members: set) -> list[set]:
    seen, out = set(), []
    for start in members:
        if start in seen:
            continue
        comp, stack = set(), [start]
        while stack:
            cur = stack.pop()
            if cur in comp:
                continue
            comp.add(cur)
            stack.extend(adj.get(cur, set()) & members - comp)
        seen |= comp
        out.append(comp)
    return out


def critical_routers(g: dict, leader_nid: str | None, children_of: dict[str, int]) -> dict[str, dict]:
    """Routers whose failure splits the (known) router mesh. With few known links this is a lower bound."""
    members = {r for r, nb in g["adj"].items() if nb}
    out: dict[str, dict] = {}
    if len(members) < 3:
        return out
    for r in members:
        rest = members - {r}
        comps = _components(g["adj"], rest)
        if len(comps) < 2:
            continue
        main = next((c for c in comps if leader_nid in c), None) or max(comps, key=len)
        cut = set().union(*(c for c in comps if c is not main))
        out[r] = {"cuts_routers": sorted(cut), "cut_children": sum(children_of.get(c, 0) for c in cut),
                  "own_children": children_of.get(r, 0)}
    return out


# ---- findings -----------------------------------------------------------------------------------------

def _fresh(ts: float | None, now: float, ttl: float = ACTIVE_STALE) -> bool:
    return bool(ts) and now - ts <= ttl


def _ttl(engine: Engine) -> float:
    """How long active measurements count: an hour, or three rounds if the collector is set to a longer interval."""
    return max(ACTIVE_STALE, engine.diag_ttl)


def _lossy(m: dict) -> bool:
    return (m.get("frame_err") or 0.0) >= LINK_ERR_WARN or (m.get("msg_err") or 0.0) >= MSG_ERR_WARN


def _fraction(percent: float | None) -> float | None:
    return None if percent is None else percent / 100.0


def _active_router_findings(engine: Engine, n: dict, raw, graph: dict | None, now: float) -> list[dict]:
    """What the router measured itself: neighbours it cannot deliver frames to; and whether it answers at all."""
    out: list[dict] = []
    by_rid = graph["routers"] if graph else {}
    lossy = sorted(((m.get("frame_err") or 0.0, dst, m) for (src, dst), m in engine.link_metrics.items()
                    if src == n["router_id"] and _fresh(m.get("ts"), now, _ttl(engine)) and _lossy(m)),
                   key=lambda x: (-x[0], x[1]))
    if lossy:
        _, dst, m = lossy[0]
        out.append(finding("link_lossy", "warn", neighbor_node=by_rid.get(dst) or f"0x{dst << 10:04x}",
                           rate=_fraction(m.get("frame_err")), msg_rate=_fraction(m.get("msg_err")),
                           rssi=m.get("rss_ave"), links=len(lossy)))
    failures = engine.diag_info.get("failures") or {}
    if raw is not None and raw.rloc16 in failures and _fresh(engine.diag_info.get("ts"), now, _ttl(engine)):
        out.append(finding("router_no_detail", "info"))
    return out


def _active_child_findings(raw, now: float, ttl: float) -> list[dict]:
    """The parent's measurements of an end device: how well it hears it and delivers to it, and when it last heard it."""
    link = raw.link if raw is not None else None
    if not link or not _fresh(link.get("ts"), now, ttl):
        return []
    out: list[dict] = []
    rss = link.get("rss_ave")  # not the margin: it depends on the noise floor each chip assumes
    if _lossy(link) or (rss is not None and rss <= RSS_WEAK_LINK):
        severity = "warn" if (link.get("msg_err") or 0.0) >= MSG_ERR_WARN else "info"
        out.append(finding("child_link_poor", severity, rssi=rss, rate=_fraction(link.get("frame_err")),
                           msg_rate=_fraction(link.get("msg_err"))))
    age, timeout = link.get("age"), link.get("timeout")
    if age is not None and timeout and age / timeout >= CHILD_AGE_WARN:
        out.append(finding("child_age_high", "info", age=age, timeout=timeout))
    return out


def _recent(events: list[dict], kinds: tuple[str, ...], now: float, both_known: bool = False) -> int:
    count = 0
    for ev in events:
        if ev["kind"] in kinds and ev["ts"] >= now - DAY:
            p = ev["params"]
            if both_known and (p.get("from") is None or p.get("to") is None):
                continue
            count += 1
    return count


def _node_findings(engine: Engine, nodes: dict, nid: str, now: float, graph: dict | None,
                   crit: dict, children_of: dict[str, int]) -> list[dict]:
    n = nodes[nid]
    raw = engine.nodes.get(nid)
    out: list[dict] = []
    is_router = n["role"] in ("leader", "router")
    st = raw.stats if raw else None

    if not n["online"]:
        severity = "crit" if is_router and (n["role"] == "leader" or children_of.get(nid, 0) > 0) else "warn"
        out.append(finding("offline", severity, since=n["last_seen"], children=children_of.get(nid, 0)))

    if is_router and graph is not None:
        nbrs = graph["adj"].get(nid, set())
        if len(graph["routers"]) >= 3 and len(nbrs) == 1 and nid not in crit:
            out.append(finding("single_link", "warn", neighbor_node=next(iter(nbrs))))
        pairs = [p for p in graph["pairs"].values() if nid in (p["a"], p["b"])]
        fresh_lqs, asym = [], []
        for p in pairs:
            other = p["b"] if p["a"] == nid else p["a"]
            for rep in p["reports"]:
                if rep["fresh"] and rep["lq_in"] > 0 and rep["lq_out"] > 0:
                    fresh_lqs.append(min(rep["lq_in"], rep["lq_out"]))
                    if abs(rep["lq_in"] - rep["lq_out"]) >= 2:
                        asym.append((other, rep["lq_in"], rep["lq_out"]))
        if fresh_lqs and max(fresh_lqs) <= 1:
            out.append(finding("weak_links", "warn", links=len(fresh_lqs)))
        if asym:
            other, lq_in, lq_out = asym[0]
            out.append(finding("asymmetric_link", "info", neighbor_node=other, lq_in=lq_in, lq_out=lq_out,
                               links=len(asym)))
        if nid in crit:
            c = crit[nid]
            out.append(finding("critical_router", "warn", cuts_routers=len(c["cuts_routers"]),
                               cut_children=c["cut_children"], own_children=c["own_children"]))
        if raw is not None and (now - (st.first or now)) >= ADV_MIN_OBSERVED:
            per_hour = st.window(now, 6)["adv"]
            if per_hour >= ADV_PER_HOUR_FAST:
                out.append(finding("adv_fast", "warn", per_hour=per_hour, mean=3600.0 / per_hour))
        flaps = _recent(raw.events, ("role", "rloc16"), now) if raw else 0
        if flaps >= FLAP_WARN:
            out.append(finding("role_flap", "warn", count=flaps))
        out.extend(_active_router_findings(engine, n, raw, graph, now))

    if not is_router and not n.get("placeholder"):
        prid = n["parent_router_id"]
        if prid is None:
            out.append(finding("unknown_parent", "info"))
        else:
            parent = next((p for p in nodes.values() if not p.get("placeholder") and p["router_id"] == prid
                           and p["partition_id"] == n["partition_id"] and p["role"] in ("leader", "router")), None)
            if parent is not None and not parent["online"]:
                out.append(finding("parent_offline", "warn", parent_node=parent["id"]))
        moves = _recent(raw.events, ("parent",), now, both_known=True) if raw else 0
        if moves >= REPARENT_WARN:
            out.append(finding("reparenting", "warn", count=moves))
        out.extend(_active_child_findings(raw, now, _ttl(engine)))

    if st is not None:
        w = st.window(now, 144)
        if w["frames"] >= RETRY_MIN_FRAMES and w["retry_rate"] >= RETRY_WARN:
            out.append(finding("retry_high", "warn", rate=w["retry_rate"], frames=w["frames"]))
        if w["rssi_n"] >= RSSI_MIN_SAMPLES and w["rssi_avg"] < RSSI_WEAK:
            out.append(finding("signal_weak", "info", rssi=w["rssi_avg"], samples=w["rssi_n"]))
    if not n["heard"] and not n.get("placeholder"):
        if _fresh(n.get("last_diag"), now, _ttl(engine)):  # the network itself vouches for it
            out.append(finding("indirect_confirmed", "info", since=n["last_diag"]))
        else:
            out.append(finding("indirect_only", "info"))
    if n["ext"] is None and not n.get("placeholder"):
        out.append(finding("no_mac", "info"))
    return out


def _network_findings(engine: Engine, snap: dict, nodes: dict, summary: dict, capture: dict | None,
                      now: float) -> list[dict]:
    out: list[dict] = []
    cap = summary["capture"]
    if capture and capture.get("running") and cap["last_frame_age"] is not None and cap["last_frame_age"] > SNIFFER_SILENT:
        out.append(finding("sniffer_silent", "crit", seconds=cap["last_frame_age"]))
    if cap["decrypt_failed"] > 5 and cap["decrypt_failed"] >= cap["decrypt_ok"]:
        out.append(finding("decrypt_failing", "crit", failed=cap["decrypt_failed"], ok=cap["decrypt_ok"]))
    if len(summary["partitions"]) > 1:
        out.append(finding("partitions", "warn", count=len(summary["partitions"])))
    total = summary["nodes"]["total"]
    if total >= 3:
        if not summary["border_routers"]:
            out.append(finding("no_border_router", "info"))
        elif len(summary["border_routers"]) == 1:
            out.append(finding("single_border_router", "info", br_node=summary["border_routers"][0]["id"]))
    routers = summary["routers"]["count"]
    if routers >= ROUTER_LIMIT:
        out.append(finding("router_limit", "warn", count=routers, limit=ROUTER_LIMIT))
    elif routers >= ROUTER_NEAR_LIMIT:
        out.append(finding("router_near_limit", "info", count=routers, limit=ROUTER_LIMIT))
    leader_changes = sum(1 for n in engine.nodes.values() for e in n.events
                         if e["kind"] == "role" and e["params"].get("to") == "leader" and e["ts"] >= now - DAY)
    if leader_changes >= LEADER_CHANGES_WARN:
        out.append(finding("leader_changes", "warn", count=leader_changes))
    if total >= 5 and summary["nodes"]["offline"] / total >= MANY_OFFLINE:
        out.append(finding("many_offline", "warn", offline=summary["nodes"]["offline"], total=total))
    active = engine.diag_info
    if active.get("enabled") and active.get("state") == "error" and active.get("error"):
        out.append(finding("diag_failing", "warn", message=active["error"]))
    return out


# ---- the report ---------------------------------------------------------------------------------------

def _active_summary(engine: Engine, nodes: dict) -> dict:
    """State of the active collector for the UI. It knows routers by RLOC16, the UI wants the devices."""
    info = engine.diag_info
    if not info:
        return {"enabled": False}
    by_rloc = {n["rloc16"]: nid for nid, n in nodes.items() if n["rloc16"]}
    failures = [{"rloc16": f"0x{rloc:04x}", "node": by_rloc.get(f"0x{rloc:04x}"), "message": message}
                for rloc, message in sorted((info.get("failures") or {}).items())]
    own = info.get("own_rloc16")
    return {"enabled": bool(info.get("enabled")), "demo": bool(info.get("demo")), "paused": bool(info.get("paused")),
            "state": info.get("state"),
            "error": info.get("error"), "ts": info.get("ts"), "duration": info.get("duration"),
            "next": info.get("next"), "routers": info.get("routers"), "children": info.get("children"),
            "vendor": info.get("vendor"), "failures": failures,
            "own_rloc16": None if own is None else f"0x{own:04x}",
            "own_node": engine.diag_self if engine.diag_self in nodes else None}


def analyze(engine: Engine, snap: dict, now: float, capture: dict | None = None) -> dict:
    """capture: {"running": bool, "stats": {"mle_ok", "mle_failed", ...}} of the capture thread, if known."""
    with engine.lock:
        nodes = snap["nodes"]
        real = {nid: n for nid, n in nodes.items() if not n.get("placeholder")}
        children_of: dict[str, int] = defaultdict(int)
        router_by_key = {(n["partition_id"], n["router_id"]): nid for nid, n in real.items()
                         if n["role"] in ("leader", "router") and n["router_id"] is not None}
        for n in real.values():
            if n["role"] not in ("leader", "router") and n["parent_router_id"] is not None:
                parent = router_by_key.get((n["partition_id"], n["parent_router_id"]))
                if parent:
                    children_of[parent] += 1
        graphs = _router_graph(engine, real)
        leaders = {p["id"]: p["root"]["id"] for p in snap["partitions"] if p["root"]["id"] in real}
        crit = {}
        for pid, g in graphs.items():
            crit.update(critical_routers(g, leaders.get(pid), children_of))

        per_node = {}
        for nid in real:
            graph = graphs.get(real[nid]["partition_id"])
            findings = _node_findings(engine, real, nid, now, graph, crit, children_of)
            st = engine.nodes[nid].stats
            w24, w1 = st.window(now, 144), st.window(now, 6)
            per_node[nid] = {
                "findings": findings, "status": worst(findings),
                "brief": {"frames_hour": w1["frames"], "frames_24h": w24["frames"], "retry_rate": w24["retry_rate"],
                          "rssi_avg": w24["rssi_avg"], "children": children_of.get(nid, 0),
                          "adv_mean": (st.adv.summary() or {}).get("mean"),
                          "poll_mean": (st.poll.summary() or {}).get("mean")},
            }

        fresh_lq = {"3": 0, "2": 0, "1": 0}
        fresh_pairs = stale_pairs = 0
        for g in graphs.values():
            for p in g["pairs"].values():
                fresh = [r for r in p["reports"] if r["fresh"]]
                if not fresh:
                    stale_pairs += 1
                    continue
                fresh_pairs += 1
                lqs = [q for r in fresh for q in (r["lq_in"], r["lq_out"]) if q > 0]
                if lqs and min(lqs) in (1, 2, 3):
                    fresh_lq[str(min(lqs))] += 1

        cap_sum = engine.capture.summary(now)
        cap_stats = (capture or {}).get("stats", {})
        by_role: dict[str, int] = defaultdict(int)
        for n in real.values():
            by_role[n["role"]] += 1
        online = sum(1 for n in real.values() if n["online"])
        summary = {
            "generated": now,
            "nodes": {"total": len(real), "online": online, "offline": len(real) - online,
                      "indirect_only": sum(1 for n in real.values() if not n["heard"]),
                      "by_role": dict(by_role)},
            "routers": {"count": by_role["router"] + by_role["leader"], "limit": ROUTER_LIMIT},
            "partitions": [{"id": p["id"], "leader": leaders.get(p["id"]), "leader_router_id": p["leader_router_id"],
                            "nodes": sum(p["counts"].values())} for p in snap["partitions"]],
            "border_routers": [{"id": nid} for nid, n in real.items() if n["border_router"]],
            "links": {"fresh": fresh_pairs, "stale": stale_pairs, "lq": fresh_lq},
            "capture": {
                "frames": cap_sum["frames"], "frames_last_hour": cap_sum["last_hour"]["frames"],
                "acks": cap_sum["kinds"].get("ack", 0), "first_frame": cap_sum["first"],
                "last_frame_age": None if cap_sum["last"] is None else max(0.0, now - cap_sum["last"]),
                "rssi_avg": cap_sum["rssi"]["avg"] if cap_sum["rssi"] else None,
                "decrypt_ok": cap_stats.get("mle_ok", 0), "decrypt_failed": cap_stats.get("mle_failed", 0),
                "running": bool((capture or {}).get("running")),
            },
            "critical_routers": [{"id": r, **c} for r, c in crit.items()],
        }
        summary["active"] = _active_summary(engine, real)
        network = _network_findings(engine, snap, real, summary, capture, now)
        summary["findings"] = network
        summary["status"] = worst(network + [f for v in per_node.values() for f in v["findings"]])
        return {"summary": summary, "nodes": per_node}


def report(engine: Engine, now: float, capture: dict | None = None) -> tuple[dict, dict]:
    """(snapshot with a health status per node, analysis)."""
    with engine.lock:
        snap = snapshot(engine, now)
        analysis = analyze(engine, snap, now, capture)
    for nid, n in snap["nodes"].items():
        n["health"] = analysis["nodes"].get(nid, {}).get("status")
    return snap, analysis


def node_diagnostics(engine: Engine, snap: dict, analysis: dict, node_id: str, now: float) -> dict | None:
    with engine.lock:
        n = snap["nodes"].get(node_id)
        raw = engine.nodes.get(node_id)
        if n is None or raw is None or n.get("placeholder"):
            return None
        nodes = snap["nodes"]
        is_router = n["role"] in ("leader", "router")

        def label(other_id: str | None, detail: bool = False) -> dict | None:
            o = nodes.get(other_id) if other_id else None
            if o is None:
                return None
            out = {"id": o["id"], "name": o["name"], "rloc16": o["rloc16"], "ext": o["ext"], "role": o["role"],
                   "online": o["online"], "placeholder": bool(o.get("placeholder"))}
            if detail:  # what the active diagnostics know about it
                out.update(version=o["version"], link=o["link"], last_diag=o["last_diag"], ftd=o["ftd"],
                           rx_on_idle=o["rx_on_idle"], diag_self=o["diag_self"])
            return out

        links = []
        children = []
        parent = None
        if is_router:
            by_rid = {m["router_id"]: m["id"] for m in nodes.values() if not m.get("placeholder")
                      and m["partition_id"] == n["partition_id"] and m["role"] in ("leader", "router")}
            for (src, dst), m in engine.links.items():
                if n["router_id"] not in (src, dst):
                    continue
                other_rid = dst if src == n["router_id"] else src
                links.append({"neighbor": label(by_rid.get(other_rid)), "neighbor_router_id": other_rid,
                              "reported_by": "self" if src == n["router_id"] else "neighbor",
                              "lq_in": m["lq_in"], "lq_out": m["lq_out"], "cost": m["cost"],
                              "age": max(0.0, engine.clock - m["last_seen"]), "stale": not engine.link_is_fresh(m),
                              "metrics": engine.link_metrics.get((src, dst))})
            links.sort(key=lambda l: (l["neighbor_router_id"], l["reported_by"]))
            children = [label(c["id"], True) for c in nodes.values()
                        if not c.get("placeholder") and c["role"] not in ("leader", "router")
                        and c["parent_router_id"] == n["router_id"] and c["partition_id"] == n["partition_id"]]
        elif n["parent_router_id"] is not None:
            pid = next((m["id"] for m in nodes.values() if not m.get("placeholder") and m["router_id"] == n["parent_router_id"]
                        and m["partition_id"] == n["partition_id"] and m["role"] in ("leader", "router")), None)
            parent = label(pid) or {"id": None, "router_id": n["parent_router_id"], "placeholder": True}
        info = analysis["nodes"].get(node_id, {"findings": [], "status": "ok"})
        return {
            "generated": now, "id": node_id, "name": n["name"], "ext": n["ext"], "rloc16": n["rloc16"],
            "role": n["role"], "online": n["online"], "online_indirect": n["online_indirect"], "heard": n["heard"],
            "border_router": n["border_router"], "partition_id": n["partition_id"], "router_id": n["router_id"],
            "first_seen": n["first_seen"], "last_seen": n["last_seen"], "last_heard": n["last_heard"],
            "last_addressed": n["last_addressed"], "mac_confirmed": n["mac_confirmed"],
            "status": info["status"], "findings": info["findings"],
            "version": n["version"], "last_diag": n["last_diag"], "vendor": n["vendor"], "link": n["link"],
            "diag_self": n["diag_self"], "ftd": n["ftd"], "rx_on_idle": n["rx_on_idle"],
            "stats": raw.stats.summary(now), "series": raw.stats.series(now, 24),
            "links": links, "children": children, "parent": parent,
            "events": [{"ts": e["ts"], "kind": e["kind"], "params": e["params"]} for e in reversed(raw.events[-100:])],
            "addresses": n["addresses"],
        }


# ---- export -------------------------------------------------------------------------------------------

CSV_COLUMNS = ("id", "name", "mac", "rloc16", "role", "online", "heard", "partition", "border_router", "parent_router_id",
               "first_seen", "last_seen", "last_heard", "last_addressed", "frames", "bytes", "retries", "retry_rate",
               "rssi_avg", "rssi_min", "rssi_max", "adv_mean_s", "poll_mean_s", "addressed", "status", "findings",
               "thread_version", "last_diag", "vendor", "model", "firmware", "parent_rssi", "parent_margin",
               "parent_frame_err")


def _csv_text(value) -> str:
    """Text for a user-controlled cell; a leading = + - @ would be run as a formula by spreadsheets."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def nodes_csv(engine: Engine, snap: dict, analysis: dict, now: float) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    with engine.lock:
        for nid, n in sorted(snap["nodes"].items()):
            raw = engine.nodes.get(nid)
            if n.get("placeholder") or raw is None:
                continue
            s = raw.stats.summary(now)
            rssi, adv, poll = s["rssi"], s["adv"], s["poll"]
            info = analysis["nodes"].get(nid, {"findings": [], "status": "ok"})
            ext = n["ext"]
            mac = ":".join(ext[i:i + 2] for i in range(0, 16, 2)) if ext else ""
            row = [nid, n["name"], mac, n["rloc16"], n["role"], int(n["online"]), int(n["heard"]), n["partition_id"],
                   int(n["border_router"]), n["parent_router_id"], n["first_seen"], n["last_seen"], n["last_heard"],
                   n["last_addressed"], s["frames"], s["bytes"], s["retries"],
                   None if s["retry_rate"] is None else round(s["retry_rate"], 4),
                   None if not rssi else round(rssi["avg"], 1), None if not rssi else rssi["min"],
                   None if not rssi else rssi["max"], None if not adv else round(adv["mean"], 1),
                   None if not poll else round(poll["mean"], 1), s["addressed"], info["status"],
                   " ".join(f["code"] for f in info["findings"]),
                   THREAD_VERSIONS.get(n["version"], n["version"]), n["last_diag"] or None,
                   *[_csv_text((n["vendor"] or {}).get(key)) for key in ("name", "model", "sw")],
                   *[(n["link"] or {}).get(key) for key in ("rss_ave", "margin", "frame_err")]]
            row[1] = _csv_text(row[1])  # the user-given name and the texts a device reports need defusing; numbers stay
            writer.writerow(row)
    return out.getvalue()
