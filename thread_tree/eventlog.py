"""The log: every recorded event of the devices and of the network, newest first, each with a severity.

Breaches of the Thread standard (as far as the sniffer can tell) and losses are warnings; the rest is information.
"""

from __future__ import annotations

import csv
import io
import json

from .engine import Engine

# a breach of the standard or a loss: shown as a warning
WARNINGS = {"parent_choice", "reboot", "supervision_gap", "netdata_lag", "adv_gap", "attach_unanswered", "offline",
            "leader_change"}
LEVELS = ("info", "warn")


def severity(kind: str, params: dict) -> str:
    if kind == "poll_gap":  # beyond its own child timeout: its parent drops it
        return "warn" if params.get("timeout") and params.get("seconds", 0) > params["timeout"] else "info"
    if kind == "partitions":
        return "warn" if params.get("count", 1) > 1 else "info"
    if kind == "br_change":
        return "warn" if params.get("removed") else "info"
    if kind == "routers":
        return "warn" if params.get("count", 0) < params.get("before", 0) else "info"
    return "warn" if kind in WARNINGS else "info"


def entries(engine: Engine, level: str | None = None, limit: int = 1000, since: float | None = None) -> list[dict]:
    """level "warn": warnings only."""
    with engine.lock:
        rows = [{"ts": ev["ts"], "node": None, "kind": ev["kind"], "params": ev["params"]} for ev in engine.net_events]
        for node in engine.nodes.values():
            rows.extend({"ts": ev["ts"], "node": node.id, "kind": ev["kind"], "params": ev["params"]} for ev in node.events)
    for row in rows:
        row["severity"] = severity(row["kind"], row["params"])
    rows = [r for r in rows if (level != "warn" or r["severity"] == "warn") and (since is None or r["ts"] >= since)]
    rows.sort(key=lambda r: r["ts"], reverse=True)
    return rows[:limit]


def log_csv(engine: Engine, level: str | None = None) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(("time", "severity", "device", "name", "event", "details"))
    for r in entries(engine, level, limit=100000):
        name = engine.names.get(r["node"]) if r["node"] else None
        if name and name[:1] in ("=", "+", "-", "@"):
            name = "'" + name  # a spreadsheet would run it as a formula
        writer.writerow((round(r["ts"], 3), r["severity"], r["node"] or "network", name or "", r["kind"],
                         json.dumps(r["params"], sort_keys=True)))
    return out.getvalue()
