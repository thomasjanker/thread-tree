"""Capture sources. Everything ends in tshark producing EK (NDJSON) packets.

  pcap:FILE      replay a capture file
  iface:NAME     live capture from a tshark interface (e.g. the nRF Sniffer extcap)
  cmd:COMMAND    run COMMAND that writes a pcap stream to stdout (e.g. an ESP32-C6
                 sniffer bridge) and feed it to tshark
  ek:FILE        read already converted EK NDJSON (no tshark needed)
  nrf:PORT       Nordic nRF 802.15.4 sniffer on serial PORT (e.g. /dev/ttyACM0); needs a
                 channel (--channel or the dataset's) and Nordic's extcap script
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import threading
from collections.abc import Iterator

from .dataset import Dataset
from .ek import FIELDS, Handler, resolve_fields
from .engine import Engine

log = logging.getLogger(__name__)


DEFAULT_EXTCAP_SCRIPT = "~/.config/wireshark/extcap/nrf802154_sniffer.py"


def nrf_command(port: str, channel: int, script: str = DEFAULT_EXTCAP_SCRIPT) -> str:
    """Shell-quoted producer command: Nordic extcap -> pcap on stdout (with RSSI/LQI TAP metadata)."""
    if not 11 <= channel <= 26:
        raise ValueError(f"invalid 802.15.4 channel {channel}: Thread uses 11-26")
    return shlex.join(["python3", os.path.expanduser(script), "--capture", "--extcap-interface", port,
                       "--channel", str(channel), "--metadata", "ieee802154-tap", "--fifo", "/dev/stdout"])


def tshark_fields(tshark: str) -> set[str]:
    out = subprocess.run([tshark, "-G", "fields"], capture_output=True, text=True, check=True).stdout
    return {cols[2] for line in out.splitlines() if line.startswith("F\t") and len(cols := line.split("\t")) > 2}


def build_tshark_argv(tshark: str, source: str, chosen: dict[str, str], available: set[str],
                      network_key: str | None, dataset: Dataset | None,
                      extra: list[str]) -> tuple[list[str], str | None]:
    """Returns (tshark argv, optional producer command piped into tshark stdin)."""
    kind, _, value = source.partition(":")
    argv = [tshark, "-n", "-l", "-T", "ek"]
    for name in dict.fromkeys(chosen.values()):
        argv += ["-e", name]
    if network_key:
        # Thread MAC key is derived from the network key: Wireshark's "Thread hash" mode.
        argv += ["-o", f'uat:ieee802154_keys:"{network_key}","1","Thread hash"']
    if dataset and dataset.pan_id is not None and {"wpan.dst_pan", "wpan.src_pan"} <= available:
        argv += ["-Y", f"wpan.dst_pan == 0x{dataset.pan_id:04x} || wpan.src_pan == 0x{dataset.pan_id:04x}"]
    argv += extra
    producer = None
    if kind == "pcap":
        argv += ["-r", value]
    elif kind == "iface":
        argv += ["-i", value]
    elif kind == "cmd":
        argv += ["-r", "-"]
        producer = value
    else:
        raise ValueError(f"unknown source {source!r}; use pcap:, iface:, cmd: or ek:")
    return argv, producer


def iter_ek(lines: Iterator[str]) -> Iterator[dict]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "layers" in obj:  # skip the {"index": ...} bulk header lines
            yield obj


class CaptureThread(threading.Thread):
    def __init__(self, engine: Engine, source: str, network_key: str | None = None,
                 dataset: Dataset | None = None, tshark: str = "tshark", extra: list[str] | None = None):
        super().__init__(daemon=True, name="capture")
        self.engine, self.source = engine, source
        self.network_key, self.dataset = network_key, dataset
        self.tshark, self.extra = tshark, extra or []
        self._procs: list[subprocess.Popen] = []
        self.error: str | None = None
        self.stats: dict[str, int] = {}
        self.finished = threading.Event()

    def run(self) -> None:
        try:
            if self.source.startswith("ek:"):
                with open(self.source[3:], encoding="utf-8") as fh:
                    handler = Handler(self.engine, {k: v[0] for k, v in FIELDS.items()})
                    self.stats = handler.stats
                    for packet in iter_ek(fh):
                        handler.handle(packet)
                return
            if shutil.which(self.tshark) is None:
                raise RuntimeError(f"{self.tshark!r} not found: install Wireshark's tshark")
            available = tshark_fields(self.tshark)
            chosen = resolve_fields(available)
            argv, producer = build_tshark_argv(self.tshark, self.source, chosen, available,
                                               self.network_key, self.dataset, self.extra)
            stdin = None
            if producer:
                prod = subprocess.Popen(shlex.split(producer), stdout=subprocess.PIPE)
                self._procs.append(prod)
                stdin = prod.stdout
            log.info("starting tshark (key %s)", "set" if self.network_key else "NOT set: frames stay encrypted")
            proc = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self._procs.append(proc)
            threading.Thread(target=self._log_stderr, args=(proc,), daemon=True).start()
            handler = Handler(self.engine, chosen)
            self.stats = handler.stats
            for packet in iter_ek(proc.stdout):
                handler.handle(packet)
            if proc.wait() not in (0, -15):
                raise RuntimeError(f"tshark exited with status {proc.returncode}")
        except Exception as exc:  # surfaced via /api/status
            self.error = str(exc)
            log.error("capture stopped: %s", exc)
        finally:
            self.finished.set()

    @staticmethod
    def _log_stderr(proc: subprocess.Popen) -> None:
        for line in proc.stderr:
            log.info("tshark: %s", line.rstrip())

    def stop(self) -> None:
        for p in self._procs:
            if p.poll() is None:
                p.terminate()
