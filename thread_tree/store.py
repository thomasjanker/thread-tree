"""SQLite persistence: the engine state survives restarts of the program and the host."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .engine import EVENTS_PER_NODE, Engine
from .stats import BUCKET_FIELDS, BUCKET_KEEP, BUCKET_SECONDS

SCHEMA_VERSION = 3
EVENT_RETENTION = 30 * 86400.0
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY, ext TEXT, rloc16 INTEGER, partition_id INTEGER,
  ftd INTEGER, rx_on_idle INTEGER, polls INTEGER NOT NULL, border_router INTEGER NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, last_role TEXT,
  last_heard REAL NOT NULL DEFAULT 0, parent_hint INTEGER, last_addressed REAL NOT NULL DEFAULT 0,
  br_seen REAL NOT NULL DEFAULT 0, mac_confirmed REAL NOT NULL DEFAULT 0, stats TEXT,
  version INTEGER, last_diag REAL NOT NULL DEFAULT 0, link TEXT, vendor TEXT, vendor_try REAL NOT NULL DEFAULT 0,
  child_timeout INTEGER, behavior TEXT);
CREATE TABLE IF NOT EXISTS addresses (
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, addr TEXT NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, PRIMARY KEY (node_id, addr));
CREATE TABLE IF NOT EXISTS names (node_id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS links (
  src INTEGER NOT NULL, dst INTEGER NOT NULL, lq_in INTEGER, lq_out INTEGER, cost INTEGER,
  last_seen REAL NOT NULL, PRIMARY KEY (src, dst));
CREATE TABLE IF NOT EXISTS link_metrics (
  src INTEGER NOT NULL, dst INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY (src, dst));
CREATE TABLE IF NOT EXISTS node_buckets (
  node_id TEXT NOT NULL, bucket INTEGER NOT NULL,
  frames INTEGER NOT NULL, bytes INTEGER NOT NULL, retries INTEGER NOT NULL, polls INTEGER NOT NULL,
  adv INTEGER NOT NULL, addressed INTEGER NOT NULL,
  rssi_n INTEGER NOT NULL, rssi_sum REAL NOT NULL, rssi_min INTEGER, rssi_max INTEGER,
  PRIMARY KEY (node_id, bucket));
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT NOT NULL, ts REAL NOT NULL, kind TEXT NOT NULL,
  params TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_node ON events (node_id, ts);
"""
_NODE_COLS = ("id", "ext", "rloc16", "partition_id", "ftd", "rx_on_idle", "polls",
              "border_router", "first_seen", "last_seen", "last_heard", "parent_hint", "last_role",
              "last_addressed", "br_seen", "mac_confirmed", "stats", "version", "last_diag", "link", "vendor",
              "vendor_try", "child_timeout", "behavior")
_JSON_COLS = ("stats", "link", "vendor", "behavior")
_BOOL_COLS = ("ftd", "rx_on_idle", "polls", "border_router")


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript(_SCHEMA)
            columns = {r[1] for r in db.execute("PRAGMA table_info(nodes)")}
            if "last_heard" not in columns:
                db.execute("ALTER TABLE nodes ADD COLUMN last_heard REAL NOT NULL DEFAULT 0")  # older DB
            if "parent_hint" not in columns:
                db.execute("ALTER TABLE nodes ADD COLUMN parent_hint INTEGER")  # older DB
            if "last_addressed" not in columns:
                db.execute("ALTER TABLE nodes ADD COLUMN last_addressed REAL NOT NULL DEFAULT 0")  # older DB
            if "br_seen" not in columns:
                db.execute("ALTER TABLE nodes ADD COLUMN br_seen REAL NOT NULL DEFAULT 0")  # older DB
            if "mac_confirmed" not in columns:
                db.execute("ALTER TABLE nodes ADD COLUMN mac_confirmed REAL NOT NULL DEFAULT 0")  # older DB
            if "stats" not in columns:
                db.execute("ALTER TABLE nodes ADD COLUMN stats TEXT")  # older DB
            for column, ddl in (("version", "INTEGER"), ("last_diag", "REAL NOT NULL DEFAULT 0"), ("link", "TEXT"),
                                ("vendor", "TEXT"), ("vendor_try", "REAL NOT NULL DEFAULT 0"),
                                ("child_timeout", "INTEGER"), ("behavior", "TEXT")):
                if column not in columns:
                    db.execute(f"ALTER TABLE nodes ADD COLUMN {column} {ddl}")  # older DB
            db.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))

    @contextmanager
    def _db(self):
        """A connection that commits on success, rolls back on error and is always closed."""
        db = self._connect()
        try:
            with db:
                yield db
        finally:
            db.close()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA journal_mode = WAL")    # fewer and smaller writes: friendlier to SD cards
        db.execute("PRAGMA synchronous = NORMAL")
        return db

    def save(self, state: dict) -> None:
        with self._db() as db:  # one transaction: a crash never leaves half a state
            db.execute("DELETE FROM nodes")
            db.execute("DELETE FROM links")
            db.execute("DELETE FROM link_metrics")
            db.execute("DELETE FROM names")
            db.executemany("INSERT INTO names VALUES (?,?)", list(state.get("names", {}).items()))
            for n in state["nodes"]:
                n = {**n, **{k: json.dumps(n[k]) if n.get(k) is not None else None for k in _JSON_COLS}}
                row = [None if n[c] is None else (int(n[c]) if c in _BOOL_COLS else n[c]) for c in _NODE_COLS]
                db.execute(f"INSERT INTO nodes ({','.join(_NODE_COLS)}) VALUES ({','.join('?' * len(_NODE_COLS))})", row)
                db.executemany("INSERT INTO addresses VALUES (?,?,?,?)",
                               [(n["id"], a, t[0], t[1]) for a, t in n["addresses"].items()])
            db.executemany("INSERT INTO links VALUES (?,?,?,?,?,?)",
                           [(l["src"], l["dst"], l["lq_in"], l["lq_out"], l["cost"], l["last_seen"])
                            for l in state["links"]])
            db.executemany("INSERT INTO link_metrics VALUES (?,?,?)",
                           [(m["src"], m["dst"], json.dumps(m["data"])) for m in state.get("link_metrics", [])])
            db.execute("INSERT OR REPLACE INTO meta VALUES ('engine', ?)", (json.dumps(state["meta"]),))
            # statistics: only the buckets that changed; events: only the new ones
            db.executemany("INSERT OR REPLACE INTO node_buckets VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                           [(node_id, idx, *values) for node_id, idx, values in state.get("bucket_updates", [])])
            db.executemany("INSERT INTO events (node_id, ts, kind, params) VALUES (?,?,?,?)",
                           [(node_id, ts, kind, json.dumps(params)) for node_id, ts, kind, params in
                            state.get("events_new", [])])
            db.execute("DELETE FROM node_buckets WHERE node_id NOT IN (SELECT id FROM nodes) AND node_id != '_capture'")
            db.execute("DELETE FROM events WHERE node_id NOT IN (SELECT id FROM nodes)")

    def maintain(self, now: float) -> None:
        """Drop statistics and events beyond their retention."""
        with self._db() as db:
            db.execute("DELETE FROM node_buckets WHERE bucket < ?", (int(now // BUCKET_SECONDS) - BUCKET_KEEP,))
            db.execute("DELETE FROM events WHERE ts < ?", (now - EVENT_RETENTION,))
            db.execute("""DELETE FROM events WHERE id IN (SELECT id FROM (
                              SELECT id, ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY ts DESC, id DESC) AS rn
                              FROM events) WHERE rn > ?)""", (EVENTS_PER_NODE,))

    def load(self) -> dict:
        with self._db() as db:
            db.row_factory = sqlite3.Row
            nodes = []
            for r in db.execute("SELECT * FROM nodes"):
                d = dict(r)
                for c in _BOOL_COLS:
                    d[c] = None if d[c] is None else bool(d[c])
                d["addresses"] = {a["addr"]: [a["first_seen"], a["last_seen"]] for a in
                                  db.execute("SELECT * FROM addresses WHERE node_id = ?", (d["id"],))}
                for key in _JSON_COLS:
                    d[key] = json.loads(d[key]) if d[key] else None
                nodes.append(d)
            links = [dict(r) for r in db.execute("SELECT * FROM links")]
            row = db.execute("SELECT value FROM meta WHERE key = 'engine'").fetchone()
            names = {r["node_id"]: r["name"] for r in db.execute("SELECT * FROM names")}
            buckets = [(r["node_id"], r["bucket"], [r[f] for f in BUCKET_FIELDS])
                       for r in db.execute("SELECT * FROM node_buckets")]
            events = [(r["node_id"], r["ts"], r["kind"], json.loads(r["params"]))
                      for r in db.execute("SELECT * FROM events ORDER BY ts, id")]
            link_metrics = [{"src": r["src"], "dst": r["dst"], "data": json.loads(r["data"])}
                            for r in db.execute("SELECT * FROM link_metrics")]
            return {"nodes": nodes, "links": links, "link_metrics": link_metrics, "names": names,
                    "buckets": buckets, "events": events,
                    "meta": json.loads(row[0]) if row else {}}


class Persister(threading.Thread):
    """Writes the engine state periodically (if changed) and on stop()."""

    def __init__(self, engine: Engine, store: Store, interval: float = 30.0,
                 retention_days: float = 30.0):
        super().__init__(daemon=True, name="persister")
        self.engine, self.store, self.interval = engine, store, interval
        self.retention = retention_days * 86400
        self._stop_evt = threading.Event()
        self._last_maintenance = 0.0

    def run(self) -> None:
        while not self._stop_evt.wait(self.interval):
            self.flush()

    def flush(self) -> None:
        now = time.time()
        self.engine.tick(now)  # record what changed since the last flush (roles, parents, online/offline ...)
        self.engine.prune(now, self.retention)
        if self.engine.dirty:
            state = self.engine.export_state(clear_dirty=True)
            try:
                self.store.save(state)
            except Exception:
                self.engine.restore_unsaved(state)  # retry on the next flush
                raise
        if now - self._last_maintenance > 3600:
            self.store.maintain(now)
            self._last_maintenance = now

    def stop(self) -> None:
        self._stop_evt.set()
        self.flush()
