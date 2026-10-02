"""Runtime controller: owns the capture thread and the Thread dataset.

The dataset (which contains the network key) comes from the command line / environment
(then it is read-only in the UI) or from the UI (then it is saved to a 0600 file next to the
database). The key is never returned by any API.
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading
import time
from pathlib import Path

from .capture import DEFAULT_EXTCAP_SCRIPT, CaptureThread, nrf_command
from .dataset import Dataset, parse_dataset
from .engine import Engine

log = logging.getLogger(__name__)


class ConfigLocked(Exception):
    """Dataset cannot be changed from the UI."""


class Controller:
    def __init__(self, engine: Engine, mode: str, source: str = "", channel: int | None = None,
                 dataset_path: Path | None = None, cli_dataset: str | None = None,
                 cli_key: str | None = None, tshark: str = "tshark", extra: list[str] | None = None,
                 extcap_script: str = DEFAULT_EXTCAP_SCRIPT, editable: bool = True,
                 locked_reason: str | None = None):
        self.engine, self.mode, self.source, self.channel = engine, mode, source, channel
        self.path, self.tshark, self.extra, self.extcap_script = dataset_path, tshark, extra, extcap_script
        self.cli_key = cli_key
        self.lock = threading.RLock()
        self.capture: CaptureThread | None = None
        self.dataset: Dataset | None = None
        self.origin: str | None = None
        self.editable, self.locked_reason = editable, locked_reason
        self.waiting = False
        if cli_dataset:
            self.dataset, self.origin = parse_dataset(cli_dataset), "cli"
            self.editable, self.locked_reason = False, "cli"
        elif self.path and self.path.is_file():
            try:
                self.dataset, self.origin = parse_dataset(self.path.read_text().strip()), "ui"
            except (ValueError, OSError) as exc:
                log.error("stored dataset unusable (%s): ignoring it", exc)
        self._apply_prefix()

    # ---- dataset ------------------------------------------------------------

    @property
    def key(self) -> str | None:
        return (self.dataset.network_key if self.dataset else None) or self.cli_key

    def _apply_prefix(self) -> None:
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
                self._write_private("".join(hex_tlvs.split()).lower())
            self.dataset, self.origin = ds, "ui"
            self._apply_prefix()
            self.engine.dirty = True
            self.restart_capture()
            return self.config()

    def clear_dataset(self) -> dict:
        if not self.editable:
            raise ConfigLocked(self.locked_reason or "locked")
        with self.lock:
            if self.path and self.path.exists():
                self.path.unlink()
            self.dataset, self.origin = None, None
            self.restart_capture()
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

    # ---- status -------------------------------------------------------------

    def status(self) -> dict:
        with self.lock:
            cap = self.capture
            ds = self.dataset
            return {
                "mode": self.mode, "capture_error": cap.error if cap else None,
                "capture_running": bool(cap and not cap.finished.is_set()),
                "waiting_for_dataset": self.waiting,
                "network_name": ds.network_name if ds else None,
                "channel": (self.channel or (ds.channel if ds else None)),
                "decrypting": bool(self.key), "time": time.time(),
                "stats": dict(cap.stats) if cap else {},
            }
