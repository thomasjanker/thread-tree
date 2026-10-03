"""Phase 0 of active diagnostics: find out what an nRF52840 running OpenThread CLI firmware can ask the
network, and write a transcript that is safe to share (no network key).

The node joins as an *end device* (router role disabled): it takes no router ID and does not change the
routing of the network.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable
from pathlib import Path

from . import addresses as A
from .otcli import OtCli, OtCliError, OtCliTimeout

CAPABILITIES = ("meshdiag", "networkdiagnostic", "routereligible", "router", "neighbor", "netdata", "parent")
IDENTITY_COMMANDS = ("eui64", "extaddr", "rloc16", "ipaddr", "leaderdata", "networkname", "channel", "panid",
                     "parent", "router table", "neighbor table", "netdata show")
# Network Diagnostic TLV types (Thread spec): extended address, RLOC16, mode, IPv6 addresses, child table ...
NETDIAG_BASIC = "0 1 2 8 16"
# ... EUI-64, Thread version, vendor name/model/software version, stack version
NETDIAG_INFO = "23 24 25 26 27 28"
MAX_ROUTERS = 12

_SECRET_RUN = re.compile(r"\b[0-9a-fA-F]{32,}\b")  # network key, PSKc, dataset TLVs
_ROUTER_ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*0x([0-9a-fA-F]{4})\s*\|")
_RLOC_FIELD = re.compile(r"rloc16:0x([0-9a-fA-F]{4})")


def redact(text: str, secrets: tuple[str, ...] = ()) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return _SECRET_RUN.sub("<redacted>", text)


def list_ports() -> list[tuple[str, str]]:
    """Serial devices by their stable name (tty numbers can swap after a reboot)."""
    base = Path("/dev/serial/by-id")
    return [(str(p), str(p.resolve())) for p in sorted(base.iterdir())] if base.is_dir() else []


class Probe:
    def __init__(self, cli: OtCli, emit: Callable[[str], None], secrets: tuple[str, ...]):
        self.cli = cli
        self._emit = emit
        self.secrets = secrets

    def emit(self, text: str) -> None:
        self._emit(redact(text, self.secrets))

    def step(self, command: str, timeout: float | None = None, shown: str | None = None) -> list[str] | None:
        """Run a command, record command and output; None if the device answered with an error."""
        self.emit(f"$ {shown or command}")
        try:
            lines = self.cli.command(command, timeout)
        except OtCliError as err:
            self.emit(f"  ! {err.message or 'error'} (error {err.code})")
            return None
        except OtCliTimeout:
            self.emit("  ! timeout")
            return None
        for line in lines:
            self.emit("  " + line)
        return lines

    def wait_state(self, wanted: tuple[str, ...], timeout: float, interval: float) -> str | None:
        deadline = time.monotonic() + timeout
        state = None
        while time.monotonic() < deadline:
            result = self.step("state")
            state = result[0] if result else None
            if state in wanted:
                return state
            time.sleep(interval)
        return state


def _routers(*outputs: list[str] | None) -> list[int]:
    found: set[int] = set()
    for lines in outputs:
        for line in lines or []:
            match = _ROUTER_ROW.match(line) or _RLOC_FIELD.search(line)
            if match:
                found.add(int(match.group(match.lastindex), 16))
    return sorted(found)


def run_probe(cli: OtCli, dataset_hex: str | None, join: bool = True, emit: Callable[[str], None] = print,
              poll_interval: float = 3.0, attach_timeout: float = 120.0, long_timeout: float = 60.0,
              stop_after: bool = False) -> dict:
    secrets = (dataset_hex,) if dataset_hex else ()
    p = Probe(cli, emit, secrets)
    summary: dict = {"joined": False, "state": None, "routers": [], "capabilities": {}}
    p.emit(f"# thread-tree diag-probe {time.strftime('%Y-%m-%d %H:%M:%S')}")

    p.step("version")
    help_lines = p.step("help")
    names = cli.commands() if help_lines is not None else set()
    summary["capabilities"] = {name: name in names for name in CAPABILITIES}

    if join:
        if not dataset_hex:
            raise ValueError("a dataset is needed to join the network")
        p.emit("# joining as end device (router role disabled)")
        p.step("thread stop")
        p.step("ifconfig down")
        if "routereligible" in names:
            p.step("routereligible disable")
        else:
            p.emit("# WARNING: this firmware has no 'routereligible': the node may upgrade itself to a router")
        p.step("dataset set active " + dataset_hex, shown="dataset set active <dataset>")
        p.step("ifconfig up")
        p.step("thread start")
        state = p.wait_state(("child", "router", "leader"), attach_timeout, poll_interval)
    else:
        state = (p.step("state") or [None])[0]
    summary["state"] = state

    if state != "child":
        problem = ("did not attach to the network" if state in (None, "disabled", "detached")
                   else f"attached as {state}, not as end device")
        p.emit(f"# ABORT: the node {problem}")
        if state in ("router", "leader"):
            p.step("thread stop")
        return summary
    summary["joined"] = True

    p.emit("# --- identity and local view ---")
    results = {cmd: p.step(cmd) for cmd in IDENTITY_COMMANDS}

    caps = summary["capabilities"]
    routers: list[int] = []
    if caps.get("meshdiag"):
        p.emit("# --- mesh diagnostics ---")
        topology = p.step("meshdiag topology", long_timeout)
        p.step("meshdiag topology ip6-addrs children", long_timeout)
        routers = _routers(results.get("router table"), topology)
        for rloc16 in routers[:MAX_ROUTERS]:
            p.step(f"meshdiag childtable 0x{rloc16:04x}", 30)
            p.step(f"meshdiag childip6 0x{rloc16:04x}", 30)
            p.step(f"meshdiag routerneighbortable 0x{rloc16:04x}", 30)
    elif caps.get("networkdiagnostic"):
        p.emit("# --- network diagnostics (no meshdiag in this firmware) ---")
        routers = _routers(results.get("router table"))
        own_rloc = p.step("ipaddr rloc")
        try:
            prefix = int(ipaddress.IPv6Address(own_rloc[0])) >> 64 if own_rloc else None
        except ValueError:
            prefix = None
        if prefix is None:
            p.emit("# cannot derive router addresses: the node's own RLOC address is unknown")
        for rloc16 in routers[:MAX_ROUTERS] if prefix is not None else []:
            target = A.rloc_address(prefix, rloc16)
            p.step(f"networkdiagnostic get {target} {NETDIAG_BASIC}", 30)
            p.step(f"networkdiagnostic get {target} {NETDIAG_INFO}", 30)
    else:
        p.emit("# NO DIAGNOSTIC COMMANDS in this firmware: build with OT_MESH_DIAG=ON and OT_NETDIAG_CLIENT=ON "
               "(see docs/diagnostics.md)")
    summary["routers"] = routers

    p.emit("# --- summary ---")
    for name, present in caps.items():
        p.emit(f"# command {name}: {'yes' if present else 'NO'}")
    p.emit(f"# state: {state}; routers found: {len(routers)}")
    if stop_after:
        p.step("thread stop")
    return summary
