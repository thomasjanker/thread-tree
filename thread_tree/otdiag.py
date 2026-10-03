"""Parsers for the output of OpenThread's diagnostic CLI commands (meshdiag, netdata, parent, ...).

The formats were taken from a real run (tests/fixtures/probe_real.txt, anonymized). The parsers read
structure by keywords, not by indentation, and ignore what they do not know, so another OpenThread
version that adds a field does not break them.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

_ROUTER = re.compile(r"^id:(\d+)\s+rloc16:0x([0-9a-fA-F]{4})\s+ext-addr:([0-9a-fA-F]{16})\s+ver:(\d+)(.*)$")
_LINKS = re.compile(r"^(\d)-links:\{([\d\s]*)\}$")
_CHILD_LISTED = re.compile(r"^rloc16:0x([0-9a-fA-F]{4})\s+lq:(\d+),\s*mode:(\S+)(.*)$")
_ENTRY = re.compile(r"^rloc16:0x([0-9a-fA-F]{4})\s+ext-addr:([0-9a-fA-F]{16})\s+ver:(\d+)\s*$")
_CONN = re.compile(r"^(?:(\d+)d\.)?(\d+):(\d{2}):(\d{2})$")


@dataclass
class Child:
    rloc16: int
    lq: int | None = None            # link quality as the parent sees it (from the topology listing)
    mode: str | None = None          # 'rdn' flags: rx-on-when-idle, device type FTD, full network data; '' = none
    me: bool = False                 # this is the node that asked
    ext: str | None = None           # from the child table
    version: int | None = None
    timeout: int | None = None       # child timeout, seconds
    age: int | None = None           # seconds since the parent last heard from the child
    supervision: int | None = None
    queued: int | None = None        # messages waiting for the (sleepy) child
    rx_on_idle: bool | None = None
    device_type: str | None = None   # "ftd" or "mtd"
    full_net: bool | None = None
    rss_ave: int | None = None       # signal strength as the PARENT receives the child, dBm
    rss_last: int | None = None
    margin: int | None = None        # link margin in dB
    frame_err: float | None = None   # percent of frames that failed
    msg_err: float | None = None
    conn_time: int | None = None     # seconds attached to this parent


@dataclass
class RouterNeighbor:
    rloc16: int
    ext: str
    version: int
    rss_ave: int | None = None       # signal strength as the router receives this neighbour, dBm
    rss_last: int | None = None
    margin: int | None = None
    frame_err: float | None = None
    msg_err: float | None = None
    conn_time: int | None = None


@dataclass
class Router:
    router_id: int
    rloc16: int
    ext: str
    version: int                     # Thread version number: 3 = 1.2, 4 = 1.3, 5 = 1.4
    leader: bool = False
    border_router: bool = False
    me: bool = False
    parent: bool = False             # the router the asking node is attached to
    links: dict[int, list[int]] = field(default_factory=dict)  # link quality (1-3) -> router IDs, as this router measures
    ip6: list[str] = field(default_factory=list)
    children: list[Child] | None = None   # None: not requested; []: none


@dataclass
class Netdata:
    prefixes: list[dict] = field(default_factory=list)   # {"prefix", "flags", "pref", "rloc16"}
    routes: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)   # {"enterprise", "data", "server", "flags", "rloc16", "id"}
    contexts: dict[int, str] = field(default_factory=dict)  # 6LoWPAN context id -> prefix

    def border_router_rloc16s(self) -> set[int]:
        return {e["rloc16"] for e in self.prefixes + self.routes if e["rloc16"] is not None}

    def context_prefixes64(self) -> dict[int, int]:
        """Context id -> upper 64 bits, for /64 contexts (the ones that compress addresses of devices)."""
        out = {}
        for cid, text in self.contexts.items():
            try:
                net = ipaddress.ip_network(text, strict=False)
            except ValueError:
                continue
            if net.prefixlen == 64:
                out[cid] = int(net.network_address) >> 64
        return out


# ---- helpers ------------------------------------------------------------------------------------------

def _ip6(text: str) -> str | None:
    try:
        return str(ipaddress.IPv6Address(text.strip()))
    except ValueError:
        return None


def _fields(line: str) -> dict[str, str]:
    """'rss - ave:-79 last:-80' -> {'rss.ave': '-79', 'rss.last': '-80'}; 'conn-time:16:22:50' keeps its colons."""
    out: dict[str, str] = {}
    group = ""
    tokens = line.split()
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if ":" not in token:
            if i + 1 < len(tokens) and tokens[i + 1] == "-":  # 'rss -': a group name
                group = token
                i += 2
                continue
            i += 1
            continue
        key, _, value = token.partition(":")
        out[f"{group}.{key}" if group else key] = value
        i += 1
    return out


def _int(value: str | None) -> int | None:
    try:
        return None if value is None else int(value, 0)
    except ValueError:
        return None


def _percent(value: str | None) -> float | None:
    try:
        return None if value is None else float(value.rstrip("%"))
    except ValueError:
        return None


def _yes(value: str | None) -> bool | None:
    return None if value is None else value.lower() == "yes"


def parse_conn_time(text: str | None) -> int | None:
    """'16:22:50' or '9d.06:31:04' -> seconds."""
    match = _CONN.match(text.strip()) if text else None
    if not match:
        return None
    days, hours, minutes, seconds = match.groups()
    return int(days or 0) * 86400 + int(hours) * 3600 + int(minutes) * 60 + int(seconds)


def _apply_link_fields(target, f: dict[str, str]) -> None:
    """Copy what this line contains; the values of the other lines of the entry must stay."""
    for key, attr, convert in (("rss.ave", "rss_ave", _int), ("rss.last", "rss_last", _int),
                               ("rss.margin", "margin", _int), ("err-rate.frame", "frame_err", _percent),
                               ("err-rate.msg", "msg_err", _percent), ("conn-time", "conn_time", parse_conn_time)):
        if key in f:
            setattr(target, attr, convert(f[key]))


# ---- meshdiag topology --------------------------------------------------------------------------------

def parse_topology(lines: list[str]) -> list[Router]:
    """`meshdiag topology [ip6-addrs] [children]`."""
    routers: list[Router] = []
    cur: Router | None = None
    section = ""
    for raw in lines:
        line = raw.strip()
        head = _ROUTER.match(line)
        if head:
            flags = {part.strip() for part in head.group(5).split(" - ")}
            cur = Router(router_id=int(head.group(1)), rloc16=int(head.group(2), 16), ext=head.group(3).lower(),
                         version=int(head.group(4)), leader="leader" in flags, border_router="br" in flags,
                         me="me" in flags, parent="parent" in flags)
            routers.append(cur)
            section = ""
            continue
        if cur is None:
            continue
        links = _LINKS.match(line)
        if links:
            cur.links[int(links.group(1))] = [int(x) for x in links.group(2).split()]
        elif line == "ip6-addrs:":
            section = "ip6"
        elif line.startswith("children:"):
            cur.children = []
            section = "children" if "none" not in line else ""
        elif section == "ip6":
            address = _ip6(line)
            if address:
                cur.ip6.append(address)
        elif section == "children":
            child = _CHILD_LISTED.match(line)
            if child and cur.children is not None:
                mode = child.group(3)
                cur.children.append(Child(rloc16=int(child.group(1), 16), lq=int(child.group(2)),
                                          mode="" if mode == "-" else mode, me="me" in child.group(4)))
    return routers


# ---- meshdiag childtable / childip6 / routerneighbortable -----------------------------------------------

def parse_childtable(lines: list[str]) -> list[Child]:
    children: list[Child] = []
    cur: Child | None = None
    for raw in lines:
        line = raw.strip()
        head = _ENTRY.match(line)
        if head:
            cur = Child(rloc16=int(head.group(1), 16), ext=head.group(2).lower(), version=int(head.group(3)))
            children.append(cur)
            continue
        if cur is None:
            continue
        f = _fields(line)
        if "timeout" in f and "age" in f:
            cur.timeout, cur.age, cur.supervision = _int(f.get("timeout")), _int(f.get("age")), _int(f.get("supvn"))
            cur.queued = _int(f.get("q-msg"))
        elif "rx-on" in f:
            cur.rx_on_idle, cur.device_type, cur.full_net = _yes(f.get("rx-on")), f.get("type"), _yes(f.get("full-net"))
        else:
            _apply_link_fields(cur, f)
    return children


def parse_childip6(lines: list[str]) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    cur: list[str] | None = None
    for raw in lines:
        line = raw.strip()
        if line.startswith("child-rloc16:"):
            cur = out.setdefault(int(line.split(":", 1)[1].strip(), 16), [])
        elif cur is not None:
            address = _ip6(line)
            if address:
                cur.append(address)
    return out


def parse_router_neighbors(lines: list[str]) -> list[RouterNeighbor]:
    out: list[RouterNeighbor] = []
    cur: RouterNeighbor | None = None
    for raw in lines:
        line = raw.strip()
        head = _ENTRY.match(line)
        if head:
            cur = RouterNeighbor(rloc16=int(head.group(1), 16), ext=head.group(2).lower(), version=int(head.group(3)))
            out.append(cur)
        elif cur is not None:
            _apply_link_fields(cur, _fields(line))
    return out


# ---- netdata, key/value commands ----------------------------------------------------------------------------

def parse_netdata(lines: list[str]) -> Netdata:
    data = Netdata()
    section = ""
    for raw in lines:
        line = raw.strip()
        if line.endswith(":") and " " not in line:
            section = line[:-1].lower()
            continue
        tokens = line.split()
        if section in ("prefixes", "routes") and len(tokens) >= 4:
            entry = {"prefix": tokens[0], "flags": tokens[1], "pref": tokens[2], "rloc16": _hex16(tokens[3])}
            (data.prefixes if section == "prefixes" else data.routes).append(entry)
        elif section == "services" and len(tokens) >= 5:
            data.services.append({"enterprise": _int(tokens[0]), "data": tokens[1], "server": tokens[2],
                                  "flags": tokens[3], "rloc16": _hex16(tokens[4]),
                                  "id": _int(tokens[5]) if len(tokens) > 5 else None})
        elif section == "contexts" and len(tokens) >= 2 and _int(tokens[1]) is not None:
            data.contexts[_int(tokens[1])] = tokens[0]
    return data


def _hex16(text: str) -> int | None:
    try:
        return int(text, 16)
    except ValueError:
        return None


def parse_keyvalues(lines: list[str]) -> dict[str, str]:
    """'Partition ID: 123' lines (leaderdata, parent) -> {'Partition ID': '123'}."""
    out = {}
    for raw in lines:
        key, sep, value = raw.strip().partition(": ")
        if sep:
            out[key] = value.strip()
    return out


def parse_router_table(lines: list[str]) -> list[tuple[int, int]]:
    """(router id, rloc16) of every row of `router table`."""
    out = []
    for raw in lines:
        match = re.match(r"^\|\s*(\d+)\s*\|\s*0x([0-9a-fA-F]{4})\s*\|", raw.strip())
        if match:
            out.append((int(match.group(1)), int(match.group(2), 16)))
    return out


THREAD_VERSIONS = {1: "1.0", 2: "1.1", 3: "1.2", 4: "1.3", 5: "1.4"}
