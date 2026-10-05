"""Runtime controller: owns the capture thread and the Thread dataset.

The dataset (which contains the network key) comes from the command line / environment
(then it is read-only in the UI) or from the UI (then it is saved to a 0600 file next to the
database). The key is never returned by any API.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path

from .capture import DEFAULT_EXTCAP_SCRIPT, CaptureThread, nrf_command
from . import sticks
from .collector import DiagThread
from .dataset import Dataset, normalize_hex, parse_dataset
from .engine import Engine

log = logging.getLogger(__name__)


class ConfigLocked(Exception):
    """Dataset cannot be changed from the UI."""


class DiagUnavailable(Exception):
    """Active diagnostics are not set up (no --diag-port)."""


class TestBusy(Exception):
    """A guided test is already running (or none is running to stop)."""


TESTS_KEPT = 20


class Controller:
    def __init__(self, engine: Engine, mode: str, source: str = "", channel: int | None = None,
                 dataset_path: Path | None = None, cli_dataset: str | None = None,
                 cli_key: str | None = None, tshark: str = "tshark", extra: list[str] | None = None,
                 extcap_script: str = DEFAULT_EXTCAP_SCRIPT, editable: bool = True,
                 locked_reason: str | None = None, allow_remote_config: bool = False,
                 diag_port: str | None = None, diag_interval: float = 300.0, diag_options: dict | None = None,
                 settings_path: Path | None = None):
        self.engine, self.mode, self.source, self.channel = engine, mode, source, channel
        self.diag_port, self.diag_interval, self.diag_options = diag_port, diag_interval, diag_options or {}
        self.diag: DiagThread | None = None
        self._dataset_hex: str | None = None  # the raw dataset for the diagnostic node: contains the key, never leaves here
        self.settings_path = settings_path  # settings changed in the UI (not secret)
        self.diag_paused = bool(self._settings().get("diag_paused", False))
        self.test = None  # the guided test that is running (scenario.py)
        self.past_tests: list[dict] = list(self._settings().get("tests", []))
        if mode == "demo" and self.diag_paused:  # the demo's simulated rounds stay switched off too
            with engine.lock:
                engine.diag_info = {**engine.diag_info, "state": "paused", "paused": True}
        self.path, self.tshark, self.extra, self.extcap_script = dataset_path, tshark, extra, extcap_script
        self.cli_key = cli_key
        self.allow_remote_config = allow_remote_config  # UI may change the dataset from other machines
        self.lock = threading.RLock()
        self.capture: CaptureThread | None = None
        self.dataset: Dataset | None = None
        self.origin: str | None = None
        self.editable, self.locked_reason = editable, locked_reason
        self.waiting = False
        self.no_sniffer = False  # source "auto" and no sniffer stick plugged in
        self.sniffer: str | None = None  # the stick the capture runs on
        self._watching = False
        if cli_dataset:
            self.dataset, self.origin = parse_dataset(cli_dataset), "cli"
            self._dataset_hex = normalize_hex(cli_dataset)
            self.editable, self.locked_reason = False, "cli"
        elif self.path and self.path.is_file():
            try:
                text = self.path.read_text().strip()
                self.dataset, self.origin = parse_dataset(text), "ui"
                self._dataset_hex = normalize_hex(text)
            except (ValueError, OSError) as exc:
                log.error("stored dataset unusable (%s): ignoring it", exc)
        self._apply_prefix()

    # ---- dataset ------------------------------------------------------------

    @property
    def key(self) -> str | None:
        return (self.dataset.network_key if self.dataset else None) or self.cli_key

    def _apply_prefix(self) -> None:
        """The mesh-local prefix comes from the dataset; without a dataset it is learned from traffic."""
        if self.dataset and self.dataset.mesh_local_prefix is not None:
            self.engine.fixed_ml_prefix = self.dataset.mesh_local_prefix

    def config(self) -> dict:
        with self.lock:
            ds = self.dataset
            return {
                "editable": self.editable, "locked_reason": self.locked_reason,
                "dataset": None if ds is None else {
                    "origin": self.origin, "network_name": ds.network_name, "channel": ds.channel,
                    "pan_id": None if ds.pan_id is None else f"0x{ds.pan_id:04x}",
                    "ext_pan_id": ds.ext_pan_id, "mesh_local_prefix": ds.mesh_local_prefix_str,
                    "has_key": bool(ds.network_key),
                },
                "key_set": bool(self.key),
            }

    def set_dataset(self, hex_tlvs: str) -> dict:
        if not self.editable:
            raise ConfigLocked(self.locked_reason or "locked")
        ds = parse_dataset(hex_tlvs)  # ValueError on malformed input
        if not ds.network_key:
            raise ValueError("the dataset contains no network key")
        if ds.channel is not None and not 11 <= ds.channel <= 26:
            raise ValueError(f"dataset channel {ds.channel} is not a valid Thread channel")
        with self.lock:
            if self.path:
                self._write_private(normalize_hex(hex_tlvs))
            self.dataset, self.origin = ds, "ui"
            self._dataset_hex = normalize_hex(hex_tlvs)
            self._apply_prefix()
            self.engine.dirty = True
            self.restart_capture()
            self.restart_diagnostics()
            return self.config()

    def clear_dataset(self) -> dict:
        if not self.editable:
            raise ConfigLocked(self.locked_reason or "locked")
        with self.lock:
            if self.path and self.path.exists():
                self.path.unlink()
            self.dataset, self.origin, self._dataset_hex = None, None, None
            with self.engine.lock:
                self.engine.fixed_ml_prefix = None  # do not keep classifying with the removed network's prefix
                self.engine.dirty = True
            self.restart_capture()
            self.restart_diagnostics()
            return self.config()

    def _write_private(self, text: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".dataset-")  # mkstemp creates 0600
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(text)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    # ---- capture ------------------------------------------------------------

    def _resolve_source(self) -> str | None:
        source = self.source
        self.no_sniffer = False
        if source == "auto":  # the sniffer stick, wherever it is plugged in
            self.sniffer = sticks.find("sniffer")
            if self.sniffer is None:
                self.no_sniffer = True
                return None
            source = "nrf:" + self.sniffer
        if source.startswith("nrf:"):
            channel = self.channel or (self.dataset.channel if self.dataset else None)
            if channel is None:
                return None  # waiting for a dataset (or --channel)
            return "cmd:" + nrf_command(source[4:], channel, self.extcap_script)
        return source

    def start_capture(self) -> None:
        if self.mode != "run":
            return
        with self.lock:
            if self.source == "auto" and not self._watching:
                self._watching = True
                threading.Thread(target=self._watch_sniffer, daemon=True, name="sticks").start()
            source = self._resolve_source()
            self.waiting = source is None and not self.no_sniffer
            if source is None:
                log.warning("no sniffer stick found: waiting for one" if self.no_sniffer
                            else "waiting for a dataset: the sniffer channel is unknown")
                return
            if self.source == "auto":
                log.info("sniffer stick: %s", self.sniffer)
            self.capture = CaptureThread(self.engine, source, self.key, self.dataset, self.tshark, self.extra)
            self.capture.start()

    def _watch_sniffer(self, every: float = 10.0) -> None:
        """Source "auto": start the capture when a sniffer stick appears, and again after it was unplugged."""
        failed_on, failures = None, 0
        while True:
            time.sleep(every if failures < 3 else 6 * every)
            with self.lock:
                cap = self.capture
                if cap is not None and not cap.finished.is_set():
                    failures = 0
                    continue
                if cap is not None:  # the capture ended (stick unplugged, tshark error ...)
                    failures = failures + 1 if failed_on == self.sniffer else 1
                    failed_on = self.sniffer
                    self.capture = None
                if sticks.find("sniffer") is not None:
                    self.start_capture()

    def stop_capture(self) -> None:
        with self.lock:
            if self.capture is not None:
                self.capture.stop()
                self.capture.join(timeout=5)
                self.capture = None

    def restart_capture(self) -> None:
        self.stop_capture()
        self.start_capture()

    # ---- settings -----------------------------------------------------------

    def _settings(self) -> dict:
        try:
            return json.loads(self.settings_path.read_text()) if self.settings_path and self.settings_path.is_file() else {}
        except (OSError, ValueError) as exc:
            log.error("settings file unusable (%s): ignoring it", exc)
            return {}

    def _save_settings(self, **values) -> None:
        if not self.settings_path:
            return
        data = {**self._settings(), **values}
        tmp = self.settings_path.with_name(self.settings_path.name + ".tmp")
        tmp.write_text(json.dumps(data))
        os.replace(tmp, self.settings_path)

    # ---- guided tests -------------------------------------------------------

    def start_router_test(self, node_id: str) -> dict:
        return self.start_test("router_outage", node_id)

    def start_test(self, kind: str, target: str | None) -> dict:
        from .scenario import make_test
        with self.lock:
            self._close_finished_test()
            if self.test is not None:
                raise TestBusy("a test is already running")
            now = time.time()
            self.test = make_test(kind, self.engine, target, now)  # ValueError: unknown test, wrong device
            if self.mode == "demo":  # the simulator plays the user's part: the test has something to show
                self.engine.demo_outage = (target, now, kind)
            threading.Thread(target=self._watch_test, args=(self.test,), daemon=True, name="test").start()
            return self.tests()

    def _watch_test(self, test) -> None:
        """Samples what events do not record (leader, partitions, a router coming back) while the test runs."""
        while True:
            time.sleep(2.0)
            with self.lock:
                if self.test is not test or not test.running:
                    return
                test.observe(self.engine, time.time())
                self._close_finished_test()

    def stop_test(self) -> dict:
        with self.lock:
            if self.test is None:
                raise TestBusy("no test is running")
            self.test.finish(time.time())
            self._close_finished_test()
            return self.tests()

    def _close_finished_test(self) -> None:
        """A finished test (stopped, or over its maximum duration) goes to the kept reports."""
        if self.test is None:
            return
        report = self.test.report(self.engine, time.time())
        if not report["running"]:
            self.engine.demo_outage = None  # the demo's router is switched on again
            self.past_tests = [report, *self.past_tests][:TESTS_KEPT]
            self._save_settings(tests=self.past_tests)
            self.test = None

    def tests(self) -> dict:
        with self.lock:
            self._close_finished_test()
            return {"running": self.test.report(self.engine, time.time()) if self.test else None,
                    "past": self.past_tests}

    # ---- active diagnostics -------------------------------------------------

    def start_diagnostics(self) -> None:
        """Start the node that joins the network and asks it (only with --diag-port, never in demo mode)."""
        if self.mode != "run" or not self.diag_port:
            return
        with self.lock:
            self.stop_diagnostics()
            self.diag = DiagThread(self.engine, self.diag_port, self._dataset_hex, self.diag_interval,
                                   paused=self.diag_paused, **self.diag_options)
            self.diag.start()

    def stop_diagnostics(self) -> None:
        with self.lock:
            if self.diag is not None:
                self.diag.stop()
                self.diag.join(timeout=10)
                self.diag = None
                with self.engine.lock:
                    self.engine.diag_info = {}

    def restart_diagnostics(self) -> None:
        """A new dataset means joining again with it (or waiting for one)."""
        if self.diag is not None:
            self.start_diagnostics()

    def live(self, since: int = 0) -> dict:
        """The live view: frames newer than `since` (sequence number) and the state of the capture."""
        with self.lock:
            cap = self.capture
            handler = cap.handler if cap is not None else None
            frames = [f for f in (handler.recent if handler else []) if f["seq"] > since]
            last = handler.recent[-1]["ts"] if handler and handler.recent else None
            minute = sum(1 for f in (handler.recent if handler else []) if last is not None and f["ts"] >= last - 60)
            ds = self.dataset
            return {
                "frames": frames[-2000:], "seq": handler.seq if handler else 0,
                "capture": {"running": bool(cap and not cap.finished.is_set()), "error": cap.error if cap else None,
                            "source": "auto" if self.source == "auto" else self.source.split(":", 1)[0],
                            "sniffer": self.sniffer or (self.source[4:] if self.source.startswith("nrf:") else None),
                            "channel": self.channel or (ds.channel if ds else None), "decrypting": bool(self.key),
                            "stats": dict(cap.stats) if cap else {}, "last_frame": last,
                            "per_minute": minute, "waiting_for_sniffer": self.no_sniffer, "waiting_for_dataset": self.waiting,
                            "messages": list(cap.messages) if cap else [],
                            "kept": len(cap.raw) if cap else 0,
                            "oldest": handler.recent[0]["ts"] if handler and handler.recent else None},
            }

    def live_frame(self, number: int) -> dict | None:
        """Full decode of one frame the capture kept (None: not kept any more, or no raw stream)."""
        with self.lock:
            cap = self.capture
        return cap.decode(number) if cap is not None else None

    def _sticks(self, cap, diag_error: str | None) -> list[dict]:
        """The USB serial devices plugged in, what they are and what they are used for (for the UI)."""
        if self.mode != "run":
            return []
        diag_port = getattr(self.diag, "current_port", None) or (self.diag_port if self.diag_port != "auto" else None)
        sniffer_port = self.sniffer or (self.source[4:] if self.source.startswith("nrf:") else None)
        out = []
        for s in sticks.find_sticks():
            in_use = (s["kind"] == "sniffer" and sniffer_port in (s["path"], s["tty"])) or (
                s["kind"] == "diag" and diag_port in (s["path"], s["tty"]))
            error = None
            if in_use and s["kind"] == "sniffer" and cap is not None and cap.error:
                error = cap.error
            elif in_use and s["kind"] == "diag":
                error = diag_error
            out.append({**s, "used": bool(in_use), "error": error})
        return out

    def _diag_ready(self) -> bool:
        """A diagnostic node is running: a fixed port, or "auto" and a stick was found."""
        return self.diag is not None and self.diag.found

    def run_diagnostics(self) -> dict:
        """Ask for a round now. Returns at once: the answers arrive within seconds to a minute."""
        with self.lock:
            if self.diag_paused:
                raise DiagUnavailable("active diagnostics are switched off")
            if self.mode == "demo":
                from .simulate import refresh_active
                refresh_active(self.engine, time.time())
                return {"queued": True}
            if not self._diag_ready():
                raise DiagUnavailable("no diagnostic stick found (see --diag-port)")
            self.diag.trigger()
            return {"queued": True}

    def set_diag_enabled(self, enabled: bool) -> dict:
        """The UI switch: off = the node stays in the network but asks nothing. Kept across restarts."""
        with self.lock:
            if self.mode != "demo" and not self._diag_ready():
                raise DiagUnavailable("no diagnostic stick found (or started with --diag-port off)")
            self.diag_paused = not enabled
            self._save_settings(diag_paused=self.diag_paused)
            if self.mode == "demo":
                from .simulate import refresh_active
                if enabled:
                    refresh_active(self.engine, time.time())
                else:
                    with self.engine.lock:
                        self.engine.diag_info = {**self.engine.diag_info, "state": "paused", "paused": True}
            else:
                self.diag.set_paused(not enabled)
            return {"enabled": enabled}

    def rebuild_topology(self) -> dict:
        result = self.engine.reset_topology()
        if self.mode == "demo":  # nothing would refill the simulated network
            from .simulate import populate
            populate(self.engine, active=True)
            if self.diag_paused:  # the fresh demo round must not switch it on again
                with self.engine.lock:
                    self.engine.diag_info = {**self.engine.diag_info, "state": "paused", "paused": True}
        elif self.diag is not None:  # what was cleared comes back with the next round
            self.diag.trigger()
        return result

    # ---- status -------------------------------------------------------------

    def status(self) -> dict:
        with self.lock:
            cap = self.capture
            ds = self.dataset
            with self.engine.lock:
                info = self.engine.diag_info
                diag_error = info.get("error") if info.get("state") == "error" else None
            return {
                "mode": self.mode, "capture_error": cap.error if cap else None,
                "capture_running": bool(cap and not cap.finished.is_set()),
                "waiting_for_dataset": self.waiting,
                "network_name": ds.network_name if ds else None,
                "channel": (self.channel or (ds.channel if ds else None)),
                "decrypting": bool(self.key), "time": time.time(),
                "stats": dict(cap.stats) if cap else {},
                "diagnostics": self.mode == "demo" or self._diag_ready(), "diagnostics_error": diag_error,
                "sniffer": self.sniffer, "waiting_for_sniffer": self.mode == "run" and self.no_sniffer,
                "sticks": self._sticks(cap, diag_error),
                "diagnostics_paused": self.diag_paused,
            }
