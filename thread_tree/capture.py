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
import re
import struct
import shlex
import shutil
import subprocess
import threading
import time
from collections import deque
from collections.abc import Iterator

from .dataset import Dataset
from .ek import FIELDS, Handler, resolve_fields
from .engine import Engine

log = logging.getLogger(__name__)


DEFAULT_EXTCAP_SCRIPT = "~/.config/wireshark/extcap/nrf802154_sniffer.py"
RAW_FRAMES = 2000            # raw frames kept for the full decode of the live view
SRP_PORT = 53535             # OpenThread's SRP server port: decoded as DNS (Wireshark only knows port 53)
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}


def nrf_command(port: str, channel: int, script: str = DEFAULT_EXTCAP_SCRIPT) -> str:
    """Shell-quoted producer command: Nordic extcap -> pcap on stdout (with RSSI/LQI TAP metadata)."""
    if not 11 <= channel <= 26:
        raise ValueError(f"invalid 802.15.4 channel {channel}: Thread uses 11-26")
    return shlex.join(["python3", os.path.expanduser(script), "--capture", "--extcap-interface", port,
                       "--channel", str(channel), "--metadata", "ieee802154-tap", "--fifo", "/dev/stdout"])


def pan_filter(pan_id: int) -> str:
    """Frames of our PAN, plus frames without any PAN ID (IEEE 802.15.4-2015 frames may omit both)."""
    return f"wpan.dst_pan == 0x{pan_id:04x} || wpan.src_pan == 0x{pan_id:04x} || (!wpan.dst_pan && !wpan.src_pan)"


def tshark_fields(tshark: str) -> set[str]:
    out = subprocess.run([tshark, "-G", "fields"], capture_output=True, text=True, check=True).stdout
    return {cols[2] for line in out.splitlines() if line.startswith("F\t") and len(cols := line.split("\t")) > 2}


def decode_options(network_key: str | None) -> list[str]:
    """tshark options for decryption and decoding, shared by the capture and the full decode of one frame."""
    out = ["-d", f"udp.port=={SRP_PORT},dns"]
    if network_key:
        # Thread MAC key is derived from the network key: Wireshark's "Thread hash" mode.
        out += ["-o", f'uat:ieee802154_keys:"{network_key}","1","Thread hash"']
    return out


def _scrub(obj, key: str | None):
    """Remove anything key-like from a decoded frame: fields named like a key, and any value containing the key."""
    norm = (key or "").lower()
    if isinstance(obj, dict):
        return {k: ("<redacted>" if re.search(r"key|pskc|kek", k, re.I) and not re.search(r"key_?(id|index|mode|seq|source)", k, re.I)
                    else _scrub(v, key)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v, key) for v in obj]
    if isinstance(obj, str) and norm and norm in re.sub(r"[^0-9a-f]", "", obj.lower()):
        return "<redacted>"
    return obj


def build_tshark_argv(tshark: str, source: str, chosen: dict[str, str], available: set[str],
                      network_key: str | None, dataset: Dataset | None,
                      extra: list[str]) -> tuple[list[str], str | None]:
    """Returns (tshark argv, optional producer command piped into tshark stdin)."""
    kind, _, value = source.partition(":")
    argv = [tshark, "-n", "-l", "-T", "ek"]
    for name in dict.fromkeys(chosen.values()):
        argv += ["-e", name]
    argv += decode_options(network_key)
    if dataset and dataset.pan_id is not None and {"wpan.dst_pan", "wpan.src_pan"} <= available:
        argv += ["-Y", pan_filter(dataset.pan_id)]
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
        self.handler: Handler | None = None
        self.messages: deque[dict] = deque(maxlen=40)  # what tshark and the sniffer script printed (key masked)
        self.raw: deque[tuple[int, bytes]] = deque(maxlen=RAW_FRAMES)  # (frame number, pcap record) for the full decode
        self.pcap_header: bytes | None = None

    def run(self) -> None:
        try:
            if self.source.startswith("ek:"):
                with open(self.source[3:], encoding="utf-8") as fh:
                    handler = self.handler = Handler(self.engine, {k: v[0] for k, v in FIELDS.items()})
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
            prod = None
            if producer:
                prod = subprocess.Popen(shlex.split(producer), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False)
                self._procs.append(prod)
                threading.Thread(target=self._collect, args=(prod.stderr, "sniffer"), daemon=True).start()
            log.info("starting tshark (key %s)", "set" if self.network_key else "NOT set: frames stay encrypted")
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE if prod else None, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            self._procs.append(proc)
            if prod:  # the pcap stream passes through us: the raw frames are kept for the full decode
                threading.Thread(target=self._pump, args=(prod.stdout, proc.stdin), daemon=True).start()
            threading.Thread(target=self._collect, args=(proc.stderr, "tshark"), daemon=True).start()
            handler = self.handler = Handler(self.engine, chosen)
            self.stats = handler.stats
            for packet in iter_ek(proc.stdout):
                handler.handle(packet)
            if proc.wait() not in (0, -15):
                raise RuntimeError(f"tshark exited with status {proc.returncode}")
        except Exception as exc:  # surfaced via /api/status
            self.error = str(exc)
            self.messages.append({"ts": time.time(), "from": "thread-tree", "text": f"capture stopped: {exc}"})
            log.error("capture stopped: %s", exc)
        finally:
            self.stop()  # the sniffer script must not outlive tshark: it holds the serial port
            self.finished.set()

    def _pump(self, src, dst) -> None:
        """Copy the producer's pcap stream to tshark, keeping the last frames (pcapng is only passed through)."""
        def read(n: int) -> bytes:
            buf = b""
            while len(buf) < n:
                chunk = src.read(n - len(buf))
                if not chunk:
                    raise EOFError
                buf += chunk
            return buf
        try:
            head = read(24)
            dst.write(head)
            dst.flush()
            endian = PCAP_MAGIC.get(head[:4])
            if endian is None:  # not classic pcap: no frame boundaries known
                while chunk := src.read(65536):
                    dst.write(chunk)
                    dst.flush()
                return
            self.pcap_header = head
            number = 0
            while True:
                record = read(16)
                length = struct.unpack(endian + "IIII", record)[2]
                data = read(length)
                dst.write(record + data)
                dst.flush()
                number += 1
                self.raw.append((number, record + data))
        except (EOFError, BrokenPipeError, OSError, struct.error):
            pass
        finally:
            for stream in (dst, src):  # closing our end of the producer's pipe ends it (instead of blocking on a full pipe)
                try:
                    stream.close()
                except OSError:
                    pass

    def decode(self, number: int, timeout: float = 15.0) -> dict | None:
        """The full Wireshark decode of one kept frame (all layers and fields), without anything key-like."""
        record = next((r for n, r in self.raw if n == number), None)
        if record is None or self.pcap_header is None:
            return None
        argv = [self.tshark, "-n", "-r", "-", "-T", "json"] + decode_options(self.network_key)
        out = subprocess.run(argv, input=self.pcap_header + record, capture_output=True, timeout=timeout)
        try:
            packets = json.loads(out.stdout or b"[]")
        except json.JSONDecodeError:
            return None
        layers = packets[0]["_source"]["layers"] if packets else None
        return _scrub(layers, self.network_key)

    def _collect(self, stream, source: str) -> None:
        """Lines a process prints on stderr: into the log and the live view, with anything that looks like a key masked."""
        from .diagprobe import redact
        for raw in stream:
            line = redact((raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw).rstrip(), (self.network_key or "",))
            if line:
                self.messages.append({"ts": time.time(), "from": source, "text": line})
                log.info("%s: %s", source, line)

    def stop(self, wait: float = 3.0) -> None:
        """End tshark and the sniffer script, and wait until they are gone: the serial port is free only then."""
        for p in self._procs:
            if p.poll() is None:
                p.terminate()
        for p in self._procs:
            try:
                p.wait(timeout=wait)
            except subprocess.TimeoutExpired:
                log.warning("process %s did not end: killing it", p.args[0] if isinstance(p.args, list) else p.args)
                p.kill()
                try:
                    p.wait(timeout=wait)
                except subprocess.TimeoutExpired:
                    pass
