"""Active diagnostics: a nRF52840 with OpenThread CLI firmware joins the network as an end device and asks it.

collect_round() is one round of questions, independent of the serial port (it gets a `run` function), so it
can be tested against recorded output. DiagThread keeps the node joined, repeats the round, and survives
a missing stick, a stick that is unplugged and routers that do not answer.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from . import addresses as A
from . import behavior as B
from . import sticks
from .dataset import parse_dataset
from .engine import DIAG_TTL, Engine
from .otcli import OtCli, OtCliCancelled, OtCliError, OtCliTimeout
from .otdiag import (parse_childip6, parse_childtable, parse_keyvalues, parse_netdata, parse_router_neighbors,
                     parse_topology)

log = logging.getLogger(__name__)

NO_DETAIL_BACKOFF = 6 * 3600.0      # a router that does not answer the detail queries is not asked again for this long
VENDOR_RETRY = 6 * 3600.0           # vendor data that is missing is asked for again after this long
VENDOR_TLVS = "25 26 27 28"         # vendor name, model, software version, Thread stack version
VENDOR_PER_ROUND = 3                # a few per round, so one round stays short
MAC_TLVS = "0 3"                    # extended MAC address, timeout (of a sleepy child)
MAC_PER_ROUND = 2                   # children asked for their MAC per round (a sleepy one answers on its next poll)
MAC_RETRY = 3600.0                  # a child that did not answer is asked again after this long
MAX_INTERVAL = 3600.0               # longer than this and the answers would be stale before the next round
Run = Callable[..., list[str]]      # run(command, timeout) -> output lines; raises OtCliError / OtCliTimeout


class CollectorError(Exception):
    """The round cannot work at all (for example: the firmware has no meshdiag)."""


def _int(text: str | None) -> int | None:
    try:
        return int(text) if text is not None else None
    except ValueError:
        return None


def parse_vendor(lines: list[str]) -> dict | None:
    """Output of `networkdiagnostic get <addr> 25 26 27 28`."""
    kv = parse_keyvalues(lines)
    info = {key: kv[source] for key, source in (("name", "Vendor Name"), ("model", "Vendor Model"),
                                                ("sw", "Vendor SW Version"), ("stack", "Thread Stack Version"))
            if kv.get(source)}
    return info or None


def parse_mac(lines: list[str]) -> tuple[str | None, int | None]:
    """Output of `networkdiagnostic get <addr> 0 3`: the extended MAC address and the timeout."""
    kv = parse_keyvalues(lines)
    ext = A.normalize_ext(kv.get("Ext Address", "").strip("'\" ")) if kv.get("Ext Address") else None
    return ext, _int((kv.get("Timeout") or "").split()[0] if kv.get("Timeout") else None)


def _mac_candidates(engine: Engine, now: float, tried: dict[int, float]) -> list[tuple[int, int, float]]:
    """(rank, RLOC16, answer time limit) of children known only by their RLOC16: neither the sniffer nor the
    child tables (Thread 1.3 routers do not answer those) told their MAC. Always-listening ones first; a sleepy
    child gets the message from its parent on its next poll, so it may take a poll period to answer."""
    out = []
    for n in engine.nodes.values():
        if n.ext is not None or n.rloc16 is None or A.is_router_rloc(n.rloc16) or tried.get(n.rloc16, 0) > now:
            continue
        usual = B.usual_interval(n.behavior)
        limit = 20.0 if n.rx_on_idle else min(120.0, max(30.0, 1.5 * (usual or 60.0) + 15.0))
        out.append((0 if n.rx_on_idle else 1, n.rloc16, limit))
    return sorted(out)


def _ask_macs(run: Run, engine: Engine, now: float, tried: dict[int, float], budget: int) -> int:
    prefix = engine.ml_prefix
    if budget <= 0 or prefix is None:
        return 0
    with engine.lock:
        candidates = _mac_candidates(engine, now, tried)
    learned = 0
    for _, rloc16, limit in candidates[:budget]:
        tried[rloc16] = now + MAC_RETRY
        try:
            ext, timeout = parse_mac(run(f"networkdiagnostic get {A.rloc_address(prefix, rloc16)} {MAC_TLVS}", limit))
        except (OtCliError, OtCliTimeout):
            continue  # does not answer (or not in time): asked again later
        if ext:
            engine.on_diag_mac(now, rloc16, ext, timeout)
            tried.pop(rloc16, None)
            learned += 1
    return learned


def collect_round(run: Run, engine: Engine, now: float, no_detail: dict[int, float],
                  vendor_per_round: int = VENDOR_PER_ROUND, mac_tried: dict[int, float] | None = None,
                  mac_per_round: int = MAC_PER_ROUND) -> dict:
    """One round: topology, then per router its children and neighbour table, then Network Data and vendor data.
    no_detail maps the RLOC16 of routers that did not answer the detail queries to the time until which they are
    not asked again; the function updates it."""
    leader = parse_keyvalues(run("leaderdata", 15))
    partition = _int(leader.get("Partition ID"))
    routers = parse_topology(run("meshdiag topology ip6-addrs children", 90))
    if not routers:
        raise CollectorError("meshdiag topology listed no router")
    engine.on_diag_topology(now, routers, partition, _int(leader.get("Leader Router ID")))
    summary: dict = {"ts": now, "routers": len(routers), "children": sum(len(r.children or []) for r in routers),
                     "failures": {}, "vendor": 0, "partition": partition}

    for r in routers:
        if no_detail.get(r.rloc16, 0) > now:
            summary["failures"][r.rloc16] = "no answer earlier"
            continue
        wanted = ["routerneighbortable"] if r.children == [] else ["childtable", "childip6", "routerneighbortable"]
        for name in wanted:
            try:
                lines = run(f"meshdiag {name} 0x{r.rloc16:04x}", 30)
            except OtCliError as exc:  # typically ResponseTimeout: Thread 1.3 routers lack these queries
                summary["failures"][r.rloc16] = exc.message or f"error {exc.code}"
                no_detail[r.rloc16] = now + NO_DETAIL_BACKOFF
                break
            if name == "childtable":
                engine.on_diag_childtable(now, parse_childtable(lines))
            elif name == "childip6":
                engine.on_diag_childip6(now, parse_childip6(lines))
            else:
                engine.on_diag_neighbors(now, r.rloc16, parse_router_neighbors(lines))

    engine.on_diag_netdata(now, parse_netdata(run("netdata show", 15)))
    summary["vendor"] = _ask_vendors(run, engine, now, vendor_per_round)
    summary["macs"] = _ask_macs(run, engine, now, {} if mac_tried is None else mac_tried, mac_per_round)
    return summary


def _ask_vendors(run: Run, engine: Engine, now: float, budget: int) -> int:
    prefix = engine.ml_prefix
    if budget <= 0 or prefix is None:
        return 0
    with engine.lock:
        candidates = _vendor_candidates(engine, now)
    asked = 0
    for _, rloc16 in candidates[:budget]:
        try:
            info = parse_vendor(run(f"networkdiagnostic get {A.rloc_address(prefix, rloc16)} {VENDOR_TLVS}", 15))
        except OtCliError:
            info = None  # does not answer: remember that we asked, try again much later
        engine.on_diag_vendor(now, rloc16, info)
        asked += 1
    return asked


def _vendor_candidates(engine: Engine, now: float) -> list[tuple[int, int]]:
    """(rank, RLOC16) of routers and always-listening children whose vendor data is missing and was not asked for
    recently; routers first."""
    out = []
    for n in engine.nodes.values():
        if n.rloc16 is None or n.vendor is not None or now - n.vendor_try < VENDOR_RETRY:
            continue
        if n.ext and n.ext == engine.diag_self:
            continue
        router = A.is_router_rloc(n.rloc16)
        if router or n.rx_on_idle:
            out.append((0 if router else 1, n.rloc16))
    return sorted(out)


class DiagThread(threading.Thread):
    """Keeps the node joined as an end device and runs a round every `interval` seconds (or on trigger())."""

    def __init__(self, engine: Engine, port: str, dataset_hex: str | None, interval: float = 300.0,
                 open_cli: Callable[[str], OtCli] = OtCli, clock: Callable[[], float] = time.time,
                 join_timeout: float = 120.0, poll: float = 3.0, retry_delay: float = 15.0, paused: bool = False):
        super().__init__(daemon=True, name="diagnostics")
        self.engine, self.port, self.dataset_hex = engine, port, dataset_hex
        self.interval, self.open_cli, self.clock = min(MAX_INTERVAL, max(10.0, interval)), open_cli, clock
        self.join_timeout, self.poll, self.retry_delay = join_timeout, poll, retry_delay
        self.no_detail: dict[int, float] = {}
        self.mac_tried: dict[int, float] = {}  # RLOC16 of a child asked for its MAC -> when to ask again
        self._stop_evt = threading.Event()
        self._wake = threading.Event()
        self._paused = threading.Event()  # set: stay joined, but ask nothing (switched off in the UI)
        if paused:
            self._paused.set()
        with engine.lock:
            engine.diag_ttl = max(DIAG_TTL, 3 * self.interval)  # its answers stay current for three rounds
            engine.diag_interval = self.interval
        self.auto = port == "auto"  # find the stick by its USB identity (and again after it was unplugged)
        self.found = not self.auto  # nothing is shown before a stick turned up
        self.current_port: str | None = None
        if self.found:
            self._set(enabled=True, port=port, state="starting", error=None)

    # ---- status for the UI --------------------------------------------------

    def _set(self, **values) -> None:
        with self.engine.lock:
            self.engine.diag_info = {**self.engine.diag_info, **values}

    def trigger(self) -> None:
        """Ask for a round now."""
        self._wake.set()

    def stop(self) -> None:
        self._stop_evt.set()
        self._wake.set()

    def set_paused(self, paused: bool) -> None:
        """Switched off: the node stays in the network but stops asking; switched on: a round at once."""
        if paused:
            self._paused.set()
        else:
            self._paused.clear()
        self._wake.set()

    # ---- main loop ----------------------------------------------------------

    def run(self) -> None:
        delay = self.retry_delay
        while not self._stop_evt.is_set():
            try:
                self._session()
                delay = self.retry_delay
            except OtCliCancelled:
                break
            except Exception as exc:  # never takes the application down; the message cannot contain the dataset
                message = str(exc) or exc.__class__.__name__
                log.warning("active diagnostics: %s", message)
                self._set(state="error", error=message)
                if self._stop_evt.wait(delay):
                    break
                delay = min(delay * 2, 300.0)

    def _session(self) -> None:
        if not self.dataset_hex:
            self._set(state="waiting for dataset", error=None)
            self._stop_evt.wait(5.0)
            return
        port = self.port
        if self.auto:
            port = sticks.find("diag")
            if port is None:
                if self.found:
                    self._set(state="no stick", error=None)
                self._stop_evt.wait(10.0)
                return
            if not self.found:
                log.info("diagnostic stick: %s", port)
                self.found = True
                self._set(enabled=True, port=port, state="starting", error=None)
        cli = self.open_cli(port).open()
        self.current_port = port
        cli.cancel = self._stop_evt
        try:
            self._set(state="joining", error=None)
            self._ensure_end_device(cli)
            while not self._stop_evt.is_set():
                if self._paused.is_set():
                    self._set(state="paused", paused=True)
                    self._wake.wait(self.interval)
                    self._wake.clear()
                    continue
                self._set(state="querying", paused=False)
                started = self.clock()
                summary = collect_round(cli.command, self.engine, started, self.no_detail, mac_tried=self.mac_tried)
                self._set(state="idle", error=None, ts=started, duration=self.clock() - started,
                          routers=summary["routers"], children=summary["children"], failures=summary["failures"],
                          vendor=summary["vendor"], next=started + self.interval)
                self._wake.wait(self.interval)
                self._wake.clear()
        finally:
            cli.close()

    # ---- joining ------------------------------------------------------------

    def _ensure_end_device(self, cli: OtCli) -> None:
        names = cli.commands()
        if "meshdiag" not in names:  # ask once more: right after plugging in, the answer to `help` can be cut short
            cli._commands = None
            names = cli.commands()
        if "meshdiag" not in names:
            raise CollectorError("this firmware has no meshdiag command: use the build from docs/diagnostics.md")
        state = (cli.command("state") or [""])[0]
        eligible = (cli.command("routereligible") or [""])[0].lower() if "routereligible" in names else "disabled"
        other = self._other_network(cli, names) if state == "child" else None
        if other:
            log.info("the diagnostic node is attached to another network (%s differs): joining ours", other)
        if state != "child" or eligible != "disabled" or other:
            self._join(cli, names)
        extaddr = (cli.command("extaddr") or [""])[0].lower()
        self.engine.set_diag_self(extaddr if len(extaddr) == 16 else None)
        rloc = (cli.command("rloc16") or [""])[0]
        try:
            own = int(rloc, 16)
        except ValueError:  # only shown in the UI: not worth failing for
            own = None
        self._set(own_rloc16=own, state="joined")

    def _other_network(self, cli: OtCli, names: set[str]) -> str | None:
        """The first setting (its name, never its value) in which the node's network differs from the dataset's,
        for example after the dataset was changed or when the stick was used elsewhere. A setting that cannot be
        read counts as equal."""
        ds = parse_dataset(self.dataset_hex or "")
        wanted = (("networkname", ds.network_name, False), ("channel", None if ds.channel is None else str(ds.channel), True),
                  ("panid", None if ds.pan_id is None else f"0x{ds.pan_id:04x}", True), ("extpanid", ds.ext_pan_id, True),
                  ("networkkey", ds.network_key, True))
        for command, value, ignore_case in wanted:
            if value is None or command not in names:
                continue
            try:
                have = (cli.command(command) or [""])[0].strip()
            except OtCliError:
                continue
            if (have.lower() != value.lower()) if ignore_case else (have != value):
                return command
        return None

    def _join(self, cli: OtCli, names: set[str]) -> None:
        for command in ("thread stop", "ifconfig down"):
            self._try(cli, command)
        if "routereligible" in names:
            cli.command("routereligible disable")  # an end device: no router ID, no influence on the routing
        try:
            cli.command("dataset set active " + self.dataset_hex, secret=True)
        except OtCliError as exc:
            raise CollectorError(f"the node rejected the dataset ({exc.message})") from None
        cli.command("ifconfig up")
        cli.command("thread start")
        deadline = time.monotonic() + self.join_timeout
        state = ""
        while time.monotonic() < deadline and not self._stop_evt.is_set():
            state = (cli.command("state") or [""])[0]
            if state in ("child", "router", "leader"):
                break
            self._stop_evt.wait(self.poll)
        if state != "child":
            if state in ("router", "leader"):
                self._try(cli, "thread stop")
            raise CollectorError("the node did not attach to the network" if state not in ("router", "leader")
                                 else f"the node attached as {state}, not as end device")

    @staticmethod
    def _try(cli: OtCli, command: str) -> None:
        try:
            cli.command(command)
        except (OtCliError, OtCliTimeout):
            pass
