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
from .collector import DiagThread
from .dataset import Dataset, normalize_hex, parse_dataset
from .engine import Engine

log = logging.getLogger(__name__)


class ConfigLocked(Exception):
    """Dataset cannot be changed from the UI."""


class DiagUnavailable(Exception):
    """Active diagnostics are not set up (no --diag-port)."""


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
        if self.source.startswith("nrf:"):
            channel = self.channel or (self.dataset.channel if self.dataset else None)
            if channel is None:
                return None  # waiting for a dataset (or --channel)
            return "cmd:" + nrf_command(self.source[4:], channel, self.extcap_script)
        return self.source

    def start_capture(self) -> None:
        if self.mode != "run":
            return
        with self.lock:
            source = self._resolve_source()
            self.waiting = source is None
            if source is None:
                log.warning("waiting for a dataset: the sniffer channel is unknown")
                return
            self.capture = CaptureThread(self.engine, source, self.key, self.dataset, self.tshark, self.extra)
            self.capture.start()

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

    def run_diagnostics(self) -> dict:
        """Ask for a round now. Returns at once: the answers arrive within seconds to a minute."""
        with self.lock:
            if self.diag_paused:
                raise DiagUnavailable("active diagnostics are switched off")
            if self.mode == "demo":
                from .simulate import refresh_active
                refresh_active(self.engine, time.time())
                return {"queued": True}
            if self.diag is None:
                raise DiagUnavailable("active diagnostics are not set up: start with --diag-port")
            self.diag.trigger()
            return {"queued": True}

    def set_diag_enabled(self, enabled: bool) -> dict:
        """The UI switch: off = the node stays in the network but asks nothing. Kept across restarts."""
        with self.lock:
            if self.mode != "demo" and self.diag is None:
                raise DiagUnavailable("active diagnostics are not set up: start with --diag-port")
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
                "diagnostics": self.mode == "demo" or self.diag is not None, "diagnostics_error": diag_error,
                "diagnostics_paused": self.diag_paused,
            }
