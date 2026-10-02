"""SQLite persistence: the engine state survives restarts of the program and the host."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from .engine import Engine

SCHEMA_VERSION = 1
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY, ext TEXT, rloc16 INTEGER, partition_id INTEGER,
  ftd INTEGER, rx_on_idle INTEGER, polls INTEGER NOT NULL, border_router INTEGER NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, last_role TEXT,
  last_heard REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS addresses (
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, addr TEXT NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, PRIMARY KEY (node_id, addr));
CREATE TABLE IF NOT EXISTS names (node_id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS links (
  src INTEGER NOT NULL, dst INTEGER NOT NULL, lq_in INTEGER, lq_out INTEGER, cost INTEGER,
  last_seen REAL NOT NULL, PRIMARY KEY (src, dst));
"""
_NODE_COLS = ("id", "ext", "rloc16", "partition_id", "ftd", "rx_on_idle", "polls",
              "border_router", "first_seen", "last_seen", "last_heard", "last_role")
_BOOL_COLS = ("ftd", "rx_on_idle", "polls", "border_router")


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(_SCHEMA)
            if "last_heard" not in {r[1] for r in db.execute("PRAGMA table_info(nodes)")}:
                db.execute("ALTER TABLE nodes ADD COLUMN last_heard REAL NOT NULL DEFAULT 0")  # pre-0.1.1 DB
            db.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def save(self, state: dict) -> None:
        with self._connect() as db:  # one transaction: a crash never leaves half a state
            db.execute("DELETE FROM nodes")
            db.execute("DELETE FROM links")
            db.execute("DELETE FROM names")
            db.executemany("INSERT INTO names VALUES (?,?)", list(state.get("names", {}).items()))
            for n in state["nodes"]:
                row = [None if n[c] is None else (int(n[c]) if c in _BOOL_COLS else n[c]) for c in _NODE_COLS]
                db.execute(f"INSERT INTO nodes ({','.join(_NODE_COLS)}) VALUES ({','.join('?' * len(_NODE_COLS))})", row)
                db.executemany("INSERT INTO addresses VALUES (?,?,?,?)",
                               [(n["id"], a, t[0], t[1]) for a, t in n["addresses"].items()])
            db.executemany("INSERT INTO links VALUES (?,?,?,?,?,?)",
                           [(l["src"], l["dst"], l["lq_in"], l["lq_out"], l["cost"], l["last_seen"])
                            for l in state["links"]])
            db.execute("INSERT OR REPLACE INTO meta VALUES ('engine', ?)", (json.dumps(state["meta"]),))

    def load(self) -> dict:
        with self._connect() as db:
            db.row_factory = sqlite3.Row
            nodes = []
            for r in db.execute("SELECT * FROM nodes"):
                d = dict(r)
                for c in _BOOL_COLS:
                    d[c] = None if d[c] is None else bool(d[c])
                d["addresses"] = {a["addr"]: [a["first_seen"], a["last_seen"]] for a in
                                  db.execute("SELECT * FROM addresses WHERE node_id = ?", (d["id"],))}
                nodes.append(d)
            links = [dict(r) for r in db.execute("SELECT * FROM links")]
            row = db.execute("SELECT value FROM meta WHERE key = 'engine'").fetchone()
            names = {r["node_id"]: r["name"] for r in db.execute("SELECT * FROM names")}
            return {"nodes": nodes, "links": links, "names": names,
                    "meta": json.loads(row[0]) if row else {}}


class Persister(threading.Thread):
    """Writes the engine state periodically (if changed) and on stop()."""

    def __init__(self, engine: Engine, store: Store, interval: float = 10.0,
                 retention_days: float = 30.0):
        super().__init__(daemon=True, name="persister")
        self.engine, self.store, self.interval = engine, store, interval
        self.retention = retention_days * 86400
        self._stop_evt = threading.Event()

    def run(self) -> None:
        while not self._stop_evt.wait(self.interval):
            self.flush()

    def flush(self) -> None:
        self.engine.prune(time.time(), self.retention)
        if self.engine.dirty:
            state = self.engine.export_state()
            self.engine.dirty = False
            self.store.save(state)

    def stop(self) -> None:
        self._stop_evt.set()
        self.flush()
