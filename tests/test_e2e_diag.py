"""The program as a user starts it: `run --diag-port` against a simulated stick, queried over HTTP, restarted."""
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from test_collector import Stick, wait_for
from test_config import KEY, dataset_hex

ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class App:
    """`python -m thread_tree run ...` in a subprocess."""

    def __init__(self, db: str, port: int, *args: str):
        env = {**os.environ, "THREAD_TREE_DATASET": dataset_hex(channel=17), "PYTHONPATH": str(ROOT)}
        self.port = port
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "thread_tree", "run", "--source", "cmd:sleep 600", "--tshark", "definitely-not-installed",
             "--host", "127.0.0.1", "--port", str(port), "--db", db, *args],
            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def call(self, method: str, path: str, body: str | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers={"Content-Type": "application/json"} if body else {})
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return res.status, json.loads(data) if data[:1] in (b"{", b"[") else data

    def get(self, path: str):
        return self.call("GET", path)[1]

    def up(self) -> bool:
        try:
            return self.call("GET", "/api/status")[0] == 200
        except OSError:
            return False

    def stop(self) -> tuple[int, str]:
        self.proc.send_signal(signal.SIGTERM)
        try:
            out, _ = self.proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, _ = self.proc.communicate()
        return self.proc.returncode, out


class EndToEndTests(unittest.TestCase):
    def test_diagnostics_through_the_whole_program_and_across_a_restart(self):
        with tempfile.TemporaryDirectory() as d, Stick() as stick:
            db = str(Path(d) / "t.sqlite")
            app = App(db, free_port(), "--diag-port", stick.port, "--diag-interval", "30")
            try:
                self.assertTrue(wait_for(app.up, 20))
                self.assertTrue(wait_for(lambda: (app.get("/api/diagnostics")["summary"]["active"] or {}).get("state") == "idle", 30))
                report = app.get("/api/diagnostics")
                active = report["summary"]["active"]
                self.assertEqual((active["enabled"], active["routers"], active["children"]), (True, 5, 6))
                topo = app.get("/api/topology")
                real = [n for n in topo["nodes"].values() if not n.get("placeholder")]
                self.assertEqual(len(real), 11)
                self.assertEqual(sum(1 for n in real if n["border_router"]), 1)
                self.assertEqual(sum(1 for n in real if n["diag_self"]), 1)
                self.assertEqual({n["version"] for n in real} - {None}, {4, 5})
                self.assertTrue(app.get("/api/status")["diagnostics"])
                self.assertNotIn(KEY, json.dumps([topo, report, app.get("/api/status"), app.get("/api/config")]))

                first = active["ts"]
                self.assertEqual(app.call("POST", "/api/diagnostics/run", "{}")[1], {"queued": True})
                self.assertTrue(wait_for(lambda: app.get("/api/diagnostics")["summary"]["active"]["ts"] != first, 30))
                rows = app.call("GET", "/api/export/nodes.csv")[1].decode().splitlines()
                self.assertEqual(len(rows), 12)                       # header + 11 devices
                self.assertIn("thread_version", rows[0])
            finally:
                code, out = app.stop()
            self.assertEqual(code, 0, out)
            self.assertNotIn(KEY, out)                                # the log never shows the key
            self.assertNotIn(dataset_hex(channel=17), out)

            # a restart without the stick: everything learned is still there, the missing stick is reported
            again = App(db, free_port(), "--diag-port", "/dev/does-not-exist", "--diag-interval", "30")
            try:
                self.assertTrue(wait_for(again.up, 20))
                self.assertTrue(wait_for(lambda: (again.get("/api/diagnostics")["summary"]["active"] or {}).get("state") == "error", 20))
                topo = again.get("/api/topology")
                real = [n for n in topo["nodes"].values() if not n.get("placeholder")]
                self.assertEqual(len(real), 11)
                self.assertTrue(any(n["vendor"] is None and n["version"] for n in real))   # versions came back from the database
                self.assertIn("does-not-exist", again.get("/api/status")["diagnostics_error"])
                self.assertEqual(again.call("POST", "/api/diagnostics/run", "{}")[0], 200)  # a collector exists, it just fails
            finally:
                code, out = again.stop()
            self.assertEqual(code, 0, out)

    def test_without_the_option_the_endpoint_says_so(self):
        with tempfile.TemporaryDirectory() as d:
            app = App(str(Path(d) / "t.sqlite"), free_port())
            try:
                self.assertTrue(wait_for(app.up, 20))
                status, body = app.call("POST", "/api/diagnostics/run", "{}")
                self.assertEqual(status, 409)
                self.assertIn("--diag-port", body["error"])
                self.assertFalse(app.get("/api/diagnostics")["summary"]["active"]["enabled"])
            finally:
                code, out = app.stop()
            self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
