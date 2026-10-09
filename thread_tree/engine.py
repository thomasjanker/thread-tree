"""Topology engine: turns observations (from a sniffer or a simulator) into
a persistent model of the Thread network.

Identity: a node is keyed by its extended address (EUI-64) once known. Until
then it is a provisional node keyed by RLOC16 and is merged on first binding.
The RLOC16 is *not* an identity: it changes when a device re-parents or a
router ID is reassigned, so parent/child structure is derived from the current
RLOC16 at snapshot time, never stored.
"""

from __future__ import annotations

import bisect
import ipaddress
import threading
from collections import Counter
from dataclasses import dataclass, field

from . import addresses as A
from . import behavior as B
from .otdiag import Child, Netdata, Router, RouterNeighbor
from .presence import OFFLINE_AFTER, presence
from .stats import NodeStats

MAX_NAME = 64
EVENTS_PER_NODE = 200
CHILD_TIMEOUT_DEFAULT = 240.0  # a child in a parent's table was heard within its timeout (this is the usual value)
CAPTURE_ID = "_capture"  # statistics of the whole capture are stored like a node, under this id
NETWORK_ID = "_network"  # events of the network as a whole (leader, partitions, border routers) are stored under this id
NETWORK_EVENTS = 1000
# Freshness, measured on the capture's own clock (latest observed timestamp), so a paused capture or a
# replayed pcap keeps its last known state. Routers advertise at least every 32 s (MLE trickle).
PARTITION_TTL = 180.0  # a partition without leader data for this long is gone (network re-formed)
LINK_TTL = 180.0       # a router link not re-reported for this long is stale
DIAG_TTL = 900.0       # links listed by the latest active round stay current this long without a new round (3 x the default interval)
ROLE_LEADER, ROLE_ROUTER = "leader", "router"
ROLE_FED, ROLE_MED, ROLE_SED = "fed", "med", "sed"
ROLE_CHILD, ROLE_UNKNOWN = "child", "unknown"  # child: end device, type not yet known


@dataclass
class Node:
    id: str
    ext: str | None = None
    rloc16: int | None = None
    partition_id: int | None = None
    ftd: bool | None = None
    rx_on_idle: bool | None = None
    polls: bool = False  # sent MAC data requests => sleepy
    border_router: bool = False
    addresses: dict[str, list[float]] = field(default_factory=dict)  # observed: addr -> [first, last]
    first_seen: float = 0.0
    last_seen: float = 0.0
    last_heard: float = 0.0  # last frame transmitted by this node itself and received by the sniffer
    last_addressed: float = 0.0  # last frame another node sent to this node (MAC destination)
    br_seen: float = 0.0  # last time Network Data listed this node as border router
    mac_confirmed: float = 0.0  # last own frame with its MAC address, or MAC<->RLOC16 binding
    parent_hint: int | None = None  # RLOC16 of the router this end device polls, learned from MAC data requests
    last_role: str | None = None
    version: int | None = None  # Thread version number (4 = 1.3, 5 = 1.4), from an active diagnostic answer
    last_diag: float = 0.0  # last time the node proved to be alive in an active diagnostic answer
    link: dict | None = None  # its link to the parent as the parent measures it (children only)
    vendor: dict | None = None  # name / model / software, from networkdiagnostic
    vendor_try: float = 0.0  # when the vendor data was last asked for (also when it failed)
    child_timeout: int | None = None  # seconds, as the device itself announced it (MLE Timeout TLV)
    behavior: dict = field(default_factory=dict)  # poll rhythm and parent searches, see behavior.py
    stats: NodeStats = field(default_factory=NodeStats)
    events: list = field(default_factory=list)  # {"ts", "kind", "params"}, oldest first, capped
    sig: dict | None = None  # state at the last tick, to detect changes (not persisted)


def _service_kind(enterprise: int | None, data: str | None) -> str:
    """Thread services (enterprise number 44970): 0x01 backbone router, 0x5c/0x5d SRP server, else other."""
    if enterprise == 44970 and data:
        head = data.lower()[:2]
        return {"01": "bbr", "5c": "srp", "5d": "srp"}.get(head, "other")
    return "other"


def end_device_role(node: Node) -> str:
    if node.ftd is True:
        return ROLE_FED  # FED or REED: indistinguishable passively
    if node.ftd is False and node.rx_on_idle is not None:
        return ROLE_MED if node.rx_on_idle else ROLE_SED
    return ROLE_SED if node.polls else ROLE_CHILD


class Engine:
    def __init__(self, ml_prefix: int | None = None):
        self.lock = threading.RLock()
        self.nodes: dict[str, Node] = {}
        self.rloc_index: dict[int, str] = {}
        # placeholder id -> [(time of the merge, stable id)]: frames kept from before the MAC was known point to it
        self.aliases: dict[str, list[tuple[float, str]]] = {}
        self.links: dict[tuple[int, int], dict] = {}  # (src router id, dst router id) -> metrics
        self.leaders: dict[int, int] = {}  # partition id -> leader router id
        self.partition_seen: dict[int, float] = {}  # partition id -> last leader data
        self.primary_partition: int | None = None
        self.clock = 0.0  # latest observation timestamp
        self.fixed_ml_prefix = ml_prefix
        self.ml_votes: Counter[int] = Counter()
        # user-given device names, keyed by node id (the extended address: stable across re-parenting
        # and across pruning; a name for an RLOC16-only node is dropped if that node is pruned)
        self.names: dict[str, str] = {}
        # measurements between routers, from the neighbour tables: (measuring router id, neighbour router id) -> dict
        self.link_metrics: dict[tuple[int, int], dict] = {}
        self.contexts: dict[int, int] = {}  # 6LoWPAN context id -> upper 64 bits of its prefix (from Network Data)
        self.services: dict[int, list] = {}  # server RLOC16 -> [{"id", "kind"}] (from the Network Data of the diagnostics)
        self.diag_self: str | None = None  # extended address of the node that runs the active diagnostics
        self.diag_ts = 0.0  # time of the latest topology answer of the active diagnostics
        self.diag_ttl = DIAG_TTL  # how long its answers count as current (the collector raises it for long intervals)
        self.diag_interval = DIAG_TTL / 3  # time between two active rounds (set by the collector)
        self.diag_info: dict = {}  # status of the active collector, for the UI (not persisted)
        self.capture = NodeStats()  # all frames heard, including those without transmitter address (ACKs)
        self.last_frame_any: float | None = None  # last frame the sniffer received (not persisted)
        self.data_versions: dict[int, int] = {}  # partition id -> latest advertised Network Data version (not persisted)
        self.data_version_ts: dict[int, float] = {}  # ... and when it appeared
        self.net_events: list[dict] = []  # events of the network as a whole, oldest first
        self._net_state: dict = {}  # what the network looked like at the last check (to log changes; not persisted)
        self._last_tick: float | None = None
        self.demo_outage: tuple | None = None  # demo only: (router id, since) switched off by an outage test
        self.sniffer_outages: list[tuple[float, float]] = []  # periods without any frame: the sniffer was deaf
        self.pending_events: list[tuple[str, dict]] = []  # not yet saved
        self.events_cleared = False  # the log was cleared: the next save deletes the stored events
        self.dirty = False

    # ---- derived properties -------------------------------------------------

    @property
    def ml_prefix(self) -> int | None:
        if self.fixed_ml_prefix is not None:
            return self.fixed_ml_prefix
        if self.ml_votes:
            return self.ml_votes.most_common(1)[0][0]
        return None

    def is_current_partition(self, pid: int | None) -> bool:
        if pid is None:
            return False
        if not self.partition_seen:  # state written before partitions had timestamps
            return pid in self.leaders
        seen = self.partition_seen.get(pid)
        return seen is not None and seen >= max(self.partition_seen.values()) - PARTITION_TTL

    def partition_of(self, node: Node) -> int | None:
        """The node's partition if it is still current, otherwise the primary one."""
        return node.partition_id if self.is_current_partition(node.partition_id) else self.primary_partition

    def link_is_fresh(self, link: dict) -> bool:
        if link["last_seen"] >= self.clock - LINK_TTL:
            return True
        # a link the latest active round listed stays current while rounds keep coming: they are minutes apart,
        # advertisements (which refresh links passively) seconds
        return self.diag_ts > 0 and link["last_seen"] >= self.diag_ts and self.clock - self.diag_ts <= self.diag_ttl

    def role_of(self, node: Node) -> str:
        if node.rloc16 is not None:
            if A.is_router_rloc(node.rloc16):
                pid = self.partition_of(node)
                leader = self.leaders.get(pid) if pid is not None else None
                return ROLE_LEADER if leader == A.router_id(node.rloc16) else ROLE_ROUTER
            return end_device_role(node)
        # Without a current RLOC16 a node cannot be shown as router/leader: its router ID may now
        # belong to another device, or it became an end device whose new address is not known yet.
        if node.last_role and node.last_role not in (ROLE_LEADER, ROLE_ROUTER):
            return node.last_role
        if node.ftd is not None or node.polls or node.parent_hint is not None:
            return end_device_role(node)
        return ROLE_UNKNOWN

    def parent_router_id(self, node: Node) -> int | None:
        """Router ID of the parent of an end device: from its RLOC16, else from the poll destination."""
        if node.rloc16 is not None:
            return None if A.is_router_rloc(node.rloc16) else A.router_id(node.rloc16)
        return A.router_id(node.parent_hint) if node.parent_hint is not None else None

    def _net_log(self, ts: float, kind: str, **params) -> None:
        event = {"ts": ts, "kind": kind, "params": params}
        self.net_events.append(event)
        del self.net_events[:-NETWORK_EVENTS]
        self.pending_events.append((NETWORK_ID, event))
        self.dirty = True

    def _log(self, node: Node, ts: float, kind: str, **params) -> None:
        event = {"ts": ts, "kind": kind, "params": params}
        if node.events and ts < node.events[-1]["ts"]:  # dated back to when it happened: keep the order
            bisect.insort(node.events, event, key=lambda e: e["ts"])
        else:
            node.events.append(event)
        if len(node.events) > EVENTS_PER_NODE:
            del node.events[:-EVENTS_PER_NODE]
        self.pending_events.append((node.id, event))

    # ---- node resolution ----------------------------------------------------

    def node_for(self, ts: float, ext: str | None = None, rloc16: int | None = None,
                 touch: bool = True) -> Node | None:
        if rloc16 is not None and not A.is_valid_rloc16(rloc16):
            rloc16 = None  # 0xfffe/0xffff markers, ALOCs and the unusable router ID 63
        if ext is None and rloc16 is None:
            return None
        if ext is not None:
            node = self.nodes.get(ext)
            if node is None:
                node = self.nodes[ext] = Node(id=ext, ext=ext, first_seen=ts, last_seen=ts)
                self._log(node, ts, "first_seen", how="heard" if touch else "mentioned")
            if rloc16 is not None:
                self._bind(node, rloc16, ts)
            if (touch or rloc16 is not None) and ts > node.mac_confirmed:
                node.mac_confirmed = ts  # its MAC was seen in its own frame, or tied to its RLOC16
        else:
            nid = self.rloc_index.get(rloc16)
            node = self.nodes.get(nid) if nid else None
            if node is None:
                node = Node(id=f"rloc16:{rloc16:04x}", rloc16=rloc16, first_seen=ts, last_seen=ts)
                self.nodes[node.id] = node
                self.rloc_index[rloc16] = node.id
                self._log(node, ts, "first_seen", how="heard" if touch else "mentioned")
        if touch and ts > node.last_seen:
            node.last_seen = ts
        self.clock = max(self.clock, ts)
        self.dirty = True
        return node

    def _bind(self, node: Node, rloc16: int, ts: float) -> None:
        current = self.rloc_index.get(rloc16)
        if current == node.id:
            node.rloc16 = rloc16
            return
        if current is not None and current in self.nodes:
            other = self.nodes[current]
            if other.ext is None:
                self._merge(other, node)
                self._log(node, ts, "mac_learned", rloc16=f"0x{rloc16:04x}")
            else:
                other.rloc16 = None  # stale: RLOC16 was reassigned
        if node.rloc16 is not None and self.rloc_index.get(node.rloc16) == node.id:
            del self.rloc_index[node.rloc16]
        node.rloc16 = rloc16
        node.behavior["rloc_ts"] = ts  # when it changed: the history dates the parent change to this moment
        self.rloc_index[rloc16] = node.id

    def resolve_id(self, nid: str | None, ts: float) -> str | None:
        """The id a frame heard at ts belongs to now: a placeholder (RLOC16 only) that was merged into the device
        once its MAC was known. The same RLOC16 can later belong to another device: the merge time tells which."""
        for _ in range(8):  # a merge into a node that was merged again
            if nid is None or nid in self.nodes:
                return nid
            into = next((into for until, into in self.aliases.get(nid, []) if ts <= until), None)
            if into is None:
                return nid  # gone (pruned) or never merged: the id as it was
            nid = into
        return nid

    def _merge(self, prov: Node, into: Node) -> None:
        self.aliases.setdefault(prov.id, []).append((max(self.clock, prov.last_seen), into.id))
        del self.aliases[prov.id][:-20]
        for addr, (first, last) in prov.addresses.items():
            cur = into.addresses.setdefault(addr, [first, last])
            cur[0], cur[1] = min(cur[0], first), max(cur[1], last)
        into.border_router |= prov.border_router
        into.br_seen = max(into.br_seen, prov.br_seen)
        into.mac_confirmed = max(into.mac_confirmed, prov.mac_confirmed)
        if into.parent_hint is None:
            into.parent_hint = prov.parent_hint
        into.polls |= prov.polls
        for attr in ("partition_id", "ftd", "rx_on_idle", "last_role"):
            if getattr(into, attr) is None:
                setattr(into, attr, getattr(prov, attr))
        into.first_seen = min(into.first_seen, prov.first_seen)
        into.last_seen = max(into.last_seen, prov.last_seen)
        into.last_heard = max(into.last_heard, prov.last_heard)
        into.last_addressed = max(into.last_addressed, prov.last_addressed)
        into.last_diag = max(into.last_diag, prov.last_diag)
        for attr in ("version", "link", "vendor", "child_timeout"):
            if getattr(into, attr) is None:
                setattr(into, attr, getattr(prov, attr))
        if not into.behavior:
            into.behavior = prov.behavior
        into.vendor_try = max(into.vendor_try, prov.vendor_try)
        into.stats.merge(prov.stats)
        self.pending_events = [(nid, ev) for nid, ev in self.pending_events if nid != prov.id]
        for event in prov.events:  # the history follows the device to its stable id (and is saved under it)
            into.events.append(event)
            self.pending_events.append((into.id, event))
        into.events.sort(key=lambda e: e["ts"])
        del into.events[:-EVENTS_PER_NODE]
        self.nodes.pop(prov.id, None)
        if prov.id in self.names:  # the name follows the device to its stable id
            self.names.setdefault(into.id, self.names.pop(prov.id))
        for rloc, nid in list(self.rloc_index.items()):
            if nid == prov.id:
                del self.rloc_index[rloc]

    def _add_addr(self, node: Node, addr: ipaddress.IPv6Address, ts: float) -> None:
        cur = node.addresses.setdefault(str(addr), [ts, ts])
        cur[1] = max(cur[1], ts)
        self.dirty = True

    # ---- observations -------------------------------------------------------

    def on_frame(self, ts: float, src_ext: str | None, src_rloc16: int | None) -> Node | None:
        """Any 802.15.4 frame transmitted by a node: the only evidence of direct reception."""
        node = self.node_for(ts, ext=src_ext, rloc16=src_rloc16)
        if node is not None and ts > node.last_heard:
            node.last_heard = ts
        return node

    def on_destination(self, ts: float, dst_ext: str | None, dst_rloc16: int | None = None,
                       length: int | None = None) -> None:
        """MAC destination of a frame: another node addresses this one. Proves that the device exists
        and is still being talked to, but not that it is alive (that needs its own frames)."""
        if dst_ext == "ffffffffffffffff":
            dst_ext = None
        if dst_rloc16 is not None and not A.is_valid_rloc16(dst_rloc16):  # 0xffff broadcast etc.
            dst_rloc16 = None
        if dst_ext is None and dst_rloc16 is None:
            return
        # a frame carries one destination address: MAC or short, never both
        node = self.node_for(ts, ext=dst_ext, touch=False) if dst_ext else self.node_for(ts, rloc16=dst_rloc16, touch=False)
        if node is not None:
            node.stats.record_addressed(ts, length)
            if ts > node.last_addressed:
                node.last_addressed = ts
            gap = B.on_addressed(node.behavior, ts, self.sniffer_was_down)
            if gap:  # its parent did not contact it within its supervision interval
                self._log(node, ts, "supervision_gap", parent=self.parent_router_id(node), **gap)

    def record_frame(self, ts: float, node: Node | None, kind: str, length: int | None = None,
                     rssi: float | None = None, lqi: float | None = None, seq: int | None = None,
                     dst: str | None = None) -> bool:
        """Statistics of one frame heard. node is None when the frame has no transmitter address (ACKs).
        Returns True if it was a retransmission."""
        if self.last_frame_any is not None and ts - self.last_frame_any > B.SNIFFER_OUTAGE:
            self.sniffer_outages.append((self.last_frame_any, ts))
            del self.sniffer_outages[:-B.OUTAGES_KEPT]
        self.last_frame_any = ts if self.last_frame_any is None else max(self.last_frame_any, ts)
        retry = False
        if node is not None:
            retry = node.stats.record_frame(ts, kind, length, rssi, lqi, seq, dst)
            if kind == "poll" and not retry:
                gap = B.on_poll(node.behavior, ts, self.sniffer_was_down, node.child_timeout)
                if gap:
                    self._log(node, ts, "poll_gap", timeout=node.child_timeout, **gap)
            elif kind == "adv" and not retry:
                gap = B.on_advertisement(node.behavior, ts, self.sniffer_was_down)
                if gap:
                    self._log(node, ts, "adv_gap", **gap)
        self.capture.record_frame(ts, kind, length, rssi, lqi)
        self.clock = max(self.clock, ts)
        self.dirty = True
        return bool(node is not None and retry)

    def sniffer_was_down(self, start: float, end: float) -> bool:
        return any(s < end and e > start for s, e in self.sniffer_outages)

    def _unanswered(self, ts: float, node: Node) -> None:
        """A Child ID Request that got no Child ID Response: the router did not accept the device (full child
        table, or the frames got lost)."""
        pending = node.behavior.pop("attach", None)
        if pending and B.ATTACH_ANSWER <= ts - pending["ts"] <= B.ATTACH_RETRY:
            self._log(node, ts, "attach_unanswered", router=pending["router"])

    def on_parent_response(self, ts: float, router: Node | None, child_ext: str | None, margin: int | None) -> None:
        """MLE Parent Response: a router offers itself to the searching device (with the link margin it measured)."""
        child = self.nodes.get(child_ext or "")
        if child is not None and router is not None and router.rloc16 is not None and A.is_router_rloc(router.rloc16):
            B.on_parent_response(child.behavior, A.router_id(router.rloc16), margin)

    def on_parent_request(self, ts: float, node: Node | None) -> None:
        """MLE Parent Request: the device looks for a parent. If it has one, it has lost the link to it."""
        if node is not None:
            self._unanswered(ts, node)
        if node is not None and B.on_parent_request(node.behavior, ts):
            self._log(node, ts, "parent_search", parent=self.parent_router_id(node))
            self.dirty = True

    def on_attach_request(self, ts: float, node: Node | None, parent: Node | None) -> None:
        """MLE Child ID Request: the device chose a parent (the destination); ends a search."""
        if node is None:
            return
        self._unanswered(ts, node)
        to = A.router_id(parent.rloc16) if parent is not None and parent.rloc16 is not None else None
        choice = B.judge_choice(node.behavior.get("search"), to)
        done = B.on_attach_request(node.behavior, ts)
        if choice:
            self._log(node, ts, "parent_choice", **choice)
        if done:
            self._log(node, ts, "attached", to=to, **done)
            self.dirty = True
        if to is not None:
            node.behavior["attach"] = {"router": to, "ts": ts}

    def on_discovery_request(self, ts: float, node: Node | None) -> None:
        """MLE Discovery Request: a device looks for Thread networks, typically a new one before commissioning."""
        if node is not None:
            self._log(node, ts, "discovery")
            self.dirty = True

    def on_frame_counter(self, ts: float, node: Node | None, counter: int, key: int | None, context: str = "mac") -> None:
        """Frame counter of a secured frame (MAC or MLE): it only grows, so a jump back (or far ahead) means a restart."""
        if node is not None:
            restart = B.on_frame_counter(node.behavior, ts, counter, key, context)
            if restart:
                when = restart.pop("ts", ts)
                self._log(node, when, "reboot", counter=context, **restart)

    def node_for_ip(self, text: str | None) -> Node | None:
        """The device an IPv6 address belongs to: RLOC and MAC-based link-local addresses tell it directly,
        others are looked up among the addresses seen."""
        addr = A.parse_ip(text) if text else None
        if addr is None or addr.is_multicast:
            return None
        iid = A.iid(addr)
        if A.is_rloc_iid(iid):
            return self.nodes.get(self.rloc_index.get(iid & 0xFFFF, ""))
        if A.classify(addr, self.ml_prefix) == A.LINK_LOCAL:
            return self.nodes.get(A.ext_from_link_local(addr) or "")
        key = str(addr)
        return next((n for n in self.nodes.values() if key in n.addresses), None)

    def on_poll_answer(self, ts: float, node: Node | None, pending: bool) -> None:
        """The parent acknowledged a data poll; "frame pending" set means it holds data for the device."""
        if node is not None:
            counts = node.behavior.setdefault("polls_acked", [0, 0])  # [answered, with data waiting]
            counts[0] += 1
            counts[1] += int(pending)

    def on_relay(self, ts: float, transmitter: Node | None, origin: Node | None, dest: Node | None) -> None:
        """A frame with a mesh header: sent over several hops. The transmitter forwards it unless it is the origin."""
        if transmitter is not None and origin is not None and transmitter.id != origin.id:
            transmitter.behavior["forwarded"] = transmitter.behavior.get("forwarded", 0) + 1
        if origin is not None and transmitter is not None and transmitter.id == origin.id:
            origin.behavior["multihop"] = origin.behavior.get("multihop", 0) + 1

    def on_matter(self, ts: float, src: Node | None, dst: Node | None, length: int | None) -> None:
        """Matter traffic (UDP 5540, end-to-end encrypted): who sends and receives application data, and when."""
        for node, direction in ((src, "out"), (dst, "in")):
            if node is not None:
                m = node.behavior.setdefault("matter", {"out": 0, "in": 0, "bytes": 0, "last": 0.0})
                m[direction] += 1
                m["bytes"] += length or 0
                m["last"] = max(m["last"], ts)

    def on_router_id(self, ts: float, node: Node | None, what: str) -> None:
        """TMF Address Solicit / Release: a device asks the leader for a router ID, or gives it back."""
        if node is not None:
            self._log(node, ts, "router_id", what=what)

    def on_srp(self, ts: float, node: Node | None, names: list[str]) -> None:
        """An SRP registration (DNS update to the border router): the device's host name and its services."""
        if node is None:
            return
        # the update names the zone (default.service.arpa) first: the host is a name inside it
        host = next((n for n in names if "._" not in n and not n.startswith("_") and n.endswith(".service.arpa")
                     and n.count(".") > 2), None)
        services = sorted({n for n in names if "._" in n and not n.startswith("_")})
        if host or services:
            node.behavior["srp"] = {"host": (host or "").replace(".default.service.arpa", "") or None,
                                    "services": services[:10], "ts": ts}
            self.dirty = True

    def on_csl(self, ts: float, node: Node | None, period: int | None = None) -> None:
        """The device uses CSL (Thread 1.2 synchronized sleepy end device): its parent sends at agreed times, it does
        not poll in a rhythm, so poll gaps say nothing about it."""
        if node is not None and not node.behavior.get("csl"):
            node.behavior["csl"] = period or True
            self.dirty = True

    def on_router_restart(self, ts: float, node: Node | None) -> None:
        """Multicast MLE Link Request of a router: it re-establishes its links after a restart."""
        if node is not None and ts - node.behavior.get("restart_ts", 0.0) > 60.0:
            node.behavior["restart_ts"] = ts
            self._log(node, ts, "reboot", how="link_request")

    def on_supervision_interval(self, ts: float, node: Node | None, seconds: int) -> None:
        """Supervision Interval TLV of a child (Thread 1.2): its parent must contact it at least this often."""
        if node is not None and seconds > 0:
            node.behavior["supervision"] = seconds

    def on_child_timeout(self, ts: float, node: Node | None, seconds: int) -> None:
        if node is not None and 0 < seconds and node.child_timeout != seconds:
            node.child_timeout = seconds
            self.dirty = True

    def on_address_assignment(self, ts: float, ext: str | None, rloc16: int | None) -> None:
        """A parent told a child its new RLOC16 (Child ID Response): binds MAC address and short address."""
        if ext is not None and rloc16 is not None and rloc16 not in (0xFFFE, 0xFFFF):
            node = self.node_for(ts, ext=ext, rloc16=rloc16, touch=False)
            if node is not None:
                node.behavior.pop("attach", None)  # answered

    def on_ip(self, ts: float, sender: Node | None, src: str | None, dst: str | None) -> None:
        """IPv6 addresses of a frame. Only addresses that identify their owner
        are attributed: link-local (IID = EUI-64), RLOC (IID = RLOC16). Other
        source addresses are attributed only if the transmitter is an end
        device, because end devices never forward foreign traffic."""
        for text, is_src in ((src, True), (dst, False)):
            addr = A.parse_ip(text) if text else None
            if addr is None or addr.is_multicast:
                continue
            self._vote_prefix(addr)
            kind = A.classify(addr, self.ml_prefix)
            if kind == A.LINK_LOCAL:
                if A.is_rloc_iid(A.iid(addr)):  # fe80::ff:fe00:xxxx is built from the RLOC16, not the MAC
                    self.node_for(ts, rloc16=A.iid(addr) & 0xFFFF, touch=is_src)
                else:
                    self.node_for(ts, ext=A.ext_from_link_local(addr), touch=is_src)
            elif kind == A.RLOC:
                self.node_for(ts, rloc16=A.iid(addr) & 0xFFFF, touch=is_src)
            elif (is_src and kind in (A.ML_EID, A.OMR) and sender is not None
                  and sender.rloc16 is not None and not A.is_router_rloc(sender.rloc16)):
                self._add_addr(sender, addr, ts)

    def _vote_prefix(self, addr: ipaddress.IPv6Address) -> None:
        if A.is_rloc_iid(A.iid(addr)) and (int(addr) >> 121) == 0x7E:  # fc00::/7 (ULA)
            self.ml_votes[A.prefix64(addr)] += 1

    def on_leader_data(self, ts: float, sender: Node | None, partition_id: int,
                       leader_router_id: int, data_version: int | None = None) -> None:
        known = partition_id in self.leaders
        if known and self.leaders[partition_id] != leader_router_id:
            self._net_log(ts, "leader_change", partition=partition_id, **{"from": self.leaders[partition_id], "to": leader_router_id})
        elif not known and self.leaders:
            self._net_log(ts, "partition_new", partition=partition_id, leader=leader_router_id)
        self.leaders[partition_id] = leader_router_id
        if data_version is not None:  # Network Data version the sender has (the leader raises it on every change)
            current = self.data_versions.get(partition_id)
            if current is None or B.serial_newer(data_version, current):
                if current is not None:
                    self._net_log(ts, "netdata_version", partition=partition_id, version=data_version)
                self.data_versions[partition_id] = current = data_version
                self.data_version_ts[partition_id] = ts
            if sender is not None and sender.rloc16 is not None and A.is_router_rloc(sender.rloc16):
                # routers only: an end device without full Network Data may legitimately keep an older version
                self._netdata_lag(ts, sender, data_version, current, self.data_version_ts.get(partition_id, ts))
        self.partition_seen[partition_id] = max(self.partition_seen.get(partition_id, ts), ts)
        self.clock = max(self.clock, ts)
        # stay with the primary partition while it is alive: no flapping between concurrent partitions
        if not self.is_current_partition(self.primary_partition):
            self.primary_partition = partition_id
        if sender is not None:
            sender.partition_id = partition_id
        self.dirty = True

    def _netdata_lag(self, ts: float, node: Node, version: int, current: int, since: float) -> None:
        """A router that keeps advertising an older Network Data version than its partition does not get the update."""
        b = node.behavior
        if version == current or not B.serial_newer(current, version):
            b.pop("dv_lag", None)
            return
        lag = b.setdefault("dv_lag", {"since": since, "logged": False})  # behind since its partition got the new version
        if not lag["logged"] and ts - lag["since"] >= B.NETDATA_LAG:
            lag["logged"] = True
            self._log(node, ts, "netdata_lag", version=version, current=current, seconds=round(ts - lag["since"]))

    def on_route64(self, ts: float, sender_rloc16: int,
                   entries: list[tuple[int, int, int, int]]) -> None:
        """entries: (router_id, link_quality_in, link_quality_out, route_cost)"""
        if not A.is_router_rloc(sender_rloc16):
            return
        src = A.router_id(sender_rloc16)
        listed = {rid for rid, *_ in entries}
        for key in [k for k in self.links if k[0] == src and k[1] not in listed]:
            del self.links[key]
        for rid, lq_in, lq_out, cost in entries:
            if rid != src:
                self.links[(src, rid)] = {"lq_in": lq_in, "lq_out": lq_out, "cost": cost, "last_seen": ts}
        self.clock = max(self.clock, ts)
        self.dirty = True

    def on_mode(self, ts: float, node: Node | None, ftd: bool, rx_on_idle: bool) -> None:
        if node is not None:
            node.ftd, node.rx_on_idle = ftd, rx_on_idle
            self.dirty = True

    def on_data_poll(self, ts: float, node: Node | None) -> None:
        if node is not None and not node.polls:
            node.polls = True
            self.dirty = True

    def on_data_request(self, ts: float, sender: Node | None, dst_rloc16: int | None,
                        dst_ext: str | None, sender_by_mac: bool = False) -> None:
        """MAC data request: a sleepy end device asks its parent for pending frames, so the destination
        of the frame is the sender's parent router. sender_by_mac: the frame carried the sender's MAC
        address (not its RLOC16), so a known RLOC16 under a different parent is outdated."""
        if sender is None:
            return
        sender.polls = True  # only sleepy end devices poll their parent
        parent = dst_rloc16
        if parent is None and dst_ext is not None:
            known = self.nodes.get(dst_ext)
            parent = known.rloc16 if known is not None else None
        if parent is None or not A.is_valid_rloc16(parent) or not A.is_router_rloc(parent):
            return
        if (sender_by_mac and sender.rloc16 is not None and not A.is_router_rloc(sender.rloc16)
                and A.parent_rloc16(sender.rloc16) != parent):
            if self.rloc_index.get(sender.rloc16) == sender.id:  # re-parented: its new RLOC16 is unknown
                del self.rloc_index[sender.rloc16]
            sender.rloc16 = None
        if sender.parent_hint != parent:
            sender.parent_hint = parent
        self.dirty = True

    def on_registered_addresses(self, ts: float, sender: Node | None, addrs: list[str]) -> None:
        """Address Registration TLV of a child (MLE Parent/Child ID/Child Update Request)."""
        if sender is None:
            return
        for text in addrs:
            addr = A.parse_ip(text)
            if addr is not None and not addr.is_multicast and A.classify(addr, self.ml_prefix) in (A.ML_EID, A.OMR):
                self._add_addr(sender, addr, ts)

    def on_address_notification(self, ts: float, target: str, rloc16: int) -> None:
        addr = A.parse_ip(target)
        if addr is None:
            return
        node = self.node_for(ts, rloc16=rloc16, touch=False)
        if node is not None:
            self._add_addr(node, addr, ts)

    def on_network_data(self, ts: float, border_router_rloc16s: set[int], complete: bool = True) -> None:
        """Network Data lists these RLOC16s as border routers. complete=False for the stable subset that
        sleepy children receive: its entries carry 0xfffe instead of RLOC16s, so it names no border
        router and must not clear a flag. A complete copy defines the border routers exactly."""
        for rloc16 in border_router_rloc16s:
            node = self.node_for(ts, rloc16=rloc16, touch=False)
            if node is not None:
                node.border_router = True
                node.br_seen = max(node.br_seen, ts)
        if complete:
            for node in self.nodes.values():
                if node.border_router and node.rloc16 not in border_router_rloc16s:
                    node.border_router = False
            brs = sorted(n.id for n in self.nodes.values() if n.border_router)
            before = self._net_state.get("brs")
            if before is not None and brs != before:
                self._net_log(ts, "br_change", added=sorted(set(brs) - set(before)), removed=sorted(set(before) - set(brs)))
            self._net_state["brs"] = brs
        self.dirty = True

    # ---- active diagnostics: a node that joined the network and asks it (meshdiag) ---------------------

    def set_diag_self(self, ext: str | None) -> None:
        with self.lock:
            old, self.diag_self = self.diag_self, ext
            if old and ext and old != ext:
                self._retire(old, ext)
            self.dirty = True

    def _retire(self, old_id: str, new_id: str) -> None:
        """The diagnostic node came back with another extended address (it was reset, or the stick was replaced).
        The old identity is gone for good: it must not stay behind as an offline device. Its name moves on."""
        node = self.nodes.pop(old_id, None)
        if node is None:
            return
        if node.rloc16 is not None and self.rloc_index.get(node.rloc16) == old_id:
            del self.rloc_index[node.rloc16]
        self.pending_events = [(nid, ev) for nid, ev in self.pending_events if nid != old_id]
        if old_id in self.names:
            self.names.setdefault(new_id, self.names.pop(old_id))

    def _add_diag_addr(self, node: Node, text: str, ts: float) -> None:
        addr = A.parse_ip(text)
        if addr is None or addr.is_multicast:
            return
        if A.classify(addr, self.ml_prefix) not in (A.LINK_LOCAL, A.RLOC):  # those two are derived anyway
            self._add_addr(node, addr, ts)

    def on_diag_topology(self, ts: float, routers: list[Router], partition_id: int | None = None,
                         leader_router_id: int | None = None) -> None:
        """Result of `meshdiag topology ip6-addrs children`: every router that answered, with its links,
        addresses and children. The border-router flag of a listed router is taken as authoritative.
        leader_router_id: from `leaderdata`, for the case that the leader itself is not in the list."""
        with self.lock:
            leader_rid = next((r.router_id for r in routers if r.leader), leader_router_id)
            for r in routers:
                node = self.node_for(ts, ext=r.ext, rloc16=r.rloc16, touch=False)
                if node is None:
                    continue
                node.version = r.version
                node.last_diag = max(node.last_diag, ts)
                node.border_router = r.border_router
                if r.border_router:
                    node.br_seen = max(node.br_seen, ts)
                if partition_id is not None and leader_rid is not None:
                    self.on_leader_data(ts, node, partition_id, leader_rid)
                for text in r.ip6:
                    self._add_diag_addr(node, text, ts)
                for child in r.children or []:
                    self._diag_child_listed(ts, child)
            self._diag_links(ts, routers)
            self.dirty = True

    def _diag_child_listed(self, ts: float, child: Child) -> None:
        node = self.node_for(ts, rloc16=child.rloc16, touch=False)
        if node is None:
            return
        if child.mode is not None:  # flags r (rx on when idle), d (full thread device), n (full network data)
            self.on_mode(ts, node, "d" in child.mode, "r" in child.mode)
        # listed in its parent's child table: the parent heard it within the child timeout, not necessarily just now
        node.last_diag = max(node.last_diag, ts - CHILD_TIMEOUT_DEFAULT)
        if child.me and self.diag_self and node.ext is None:
            self.node_for(ts, ext=self.diag_self, rloc16=child.rloc16, touch=False)

    def _diag_links(self, ts: float, routers: list[Router]) -> None:
        """Each router lists its neighbours by link quality as it measures them: both directions of a link are known."""
        measured = {(r.router_id, rid): lq for r in routers for lq, ids in r.links.items() for rid in ids}
        listed = {r.router_id for r in routers}
        for key in [k for k in self.links if k[0] in listed and k not in measured]:
            del self.links[key]  # these routers described all their neighbours: the rest is not a link
        for (a, b), lq in measured.items():
            old = self.links.get((a, b))
            # the other direction is what b measures; a router that did not answer cannot say, keep what its advertisements said
            out = measured.get((b, a), old["lq_out"] if old and b not in listed else 0)
            self.links[(a, b)] = {"lq_in": lq, "lq_out": out, "cost": old["cost"] if old else None, "last_seen": ts}
        self.diag_ts = max(self.diag_ts, ts)
        self.clock = max(self.clock, ts)

    def on_diag_childtable(self, ts: float, children: list[Child]) -> None:
        """`meshdiag childtable <router>`: the children of one router with their MAC address and link measurements."""
        with self.lock:
            for c in children:
                node = self.node_for(ts, ext=c.ext, rloc16=c.rloc16, touch=False)
                if node is None:
                    continue
                node.version = c.version
                if c.device_type is not None and c.rx_on_idle is not None:
                    self.on_mode(ts, node, c.device_type == "ftd", c.rx_on_idle)
                node.last_diag = max(node.last_diag, ts - (c.age or 0))  # the age is when the parent last heard it
                node.link = {"rss_ave": c.rss_ave, "rss_last": c.rss_last, "margin": c.margin, "frame_err": c.frame_err,
                             "msg_err": c.msg_err, "conn_time": c.conn_time, "timeout": c.timeout,
                             "supervision": c.supervision, "queued": c.queued, "age": c.age, "ts": ts}
            self.dirty = True

    def on_diag_childip6(self, ts: float, addresses: dict[int, list[str]]) -> None:
        with self.lock:
            for rloc16, texts in addresses.items():
                node = self.nodes.get(self.rloc_index.get(rloc16, ""))
                if node is not None:
                    for text in texts:
                        self._add_diag_addr(node, text, ts)
            self.dirty = True

    def on_diag_neighbors(self, ts: float, router_rloc16: int, neighbors: list[RouterNeighbor]) -> None:
        """`meshdiag routerneighbortable <router>`: how this router hears each neighbour (real signal and error rate)."""
        with self.lock:
            rid = A.router_id(router_rloc16)
            listed = {A.router_id(n.rloc16) for n in neighbors}
            for key in [k for k in self.link_metrics if k[0] == rid and k[1] not in listed]:
                del self.link_metrics[key]  # the table is complete: a neighbour that is gone is not a link any more
            for n in neighbors:
                self.link_metrics[(rid, A.router_id(n.rloc16))] = {
                    "rss_ave": n.rss_ave, "rss_last": n.rss_last, "margin": n.margin, "frame_err": n.frame_err,
                    "msg_err": n.msg_err, "conn_time": n.conn_time, "ts": ts}
                node = self.node_for(ts, ext=n.ext, rloc16=n.rloc16, touch=False)
                if node is not None:
                    node.version = n.version
            self.clock = max(self.clock, ts)
            self.dirty = True

    def on_diag_netdata(self, ts: float, data: Netdata) -> None:
        """Network Data as the diagnostic node sees it (it asks for the full copy): contexts, border routers and the
        servers of services (each service has an anycast address: ALOC 0xfc10 + service id; the primary backbone
        router also 0xfc38)."""
        with self.lock:
            self.contexts.update(data.context_prefixes64())
            services: dict[int, list] = {}
            for s in data.services:
                if s.get("rloc16") is not None and s.get("id") is not None:
                    services.setdefault(s["rloc16"], []).append(
                        {"id": s["id"], "kind": _service_kind(s.get("enterprise"), s.get("data"))})
            self.services = services
            self.on_network_data(ts, data.border_router_rloc16s(), complete=True)

    def on_contexts(self, contexts: dict[int, int]) -> None:
        """6LoWPAN contexts from the Network Data the sniffer heard (context id -> upper 64 bits of the prefix)."""
        if any(self.contexts.get(cid) != prefix for cid, prefix in contexts.items()):
            self.contexts.update(contexts)
            self.dirty = True

    def on_diag_mac(self, ts: float, rloc16: int, ext: str, timeout: int | None = None) -> None:
        """A child answered a diagnostic query with its MAC: the device known only by its RLOC16 gets its identity."""
        with self.lock:
            node = self.node_for(ts, ext=ext, rloc16=rloc16, touch=False)
            if node is None:
                return
            node.last_diag = max(node.last_diag, ts)
            if timeout and not node.child_timeout:
                node.child_timeout = timeout
            self.dirty = True

    def on_diag_vendor(self, ts: float, rloc16: int, info: dict | None) -> None:
        """Vendor data of the device with this RLOC16; info None if it did not answer (do not ask again at once)."""
        with self.lock:
            node = self.nodes.get(self.rloc_index.get(rloc16, ""))
            if node is None:
                return
            node.vendor_try = ts
            if info:
                node.vendor = info
                node.last_diag = max(node.last_diag, ts)
            self.dirty = True

    # ---- history ------------------------------------------------------------

    def offline_limit(self, node: Node, role: str) -> float:
        """Silence after which a device counts as offline, from its own rhythm where the sniffer knows it: a router
        advertises at least every 32 s, a child must reach its parent within its child timeout. Otherwise the
        defaults per role (presence.OFFLINE_AFTER)."""
        base = float(OFFLINE_AFTER.get(role, 3600))
        if not node.last_heard:
            return base  # known only from others' frames: their rhythm says nothing about this device
        if role in (ROLE_LEADER, ROLE_ROUTER):
            adv = node.stats.adv.summary()
            return min(base, max(300.0, 10 * adv["mean"])) if adv and adv["n"] >= 10 else base
        if node.child_timeout:  # its parent drops it after the timeout; margin for frames the sniffer missed
            usual = B.usual_interval(node.behavior) or 0.0
            return min(base, max(300.0, 2.0 * node.child_timeout, 4.0 * usual))
        return base

    def presence_now(self, now: float) -> float:
        """The time online/offline is judged at. While the sniffer hears nothing at all it is the sniffer, not the
        network, that is silent: time stands still at its last frame, nobody goes offline because of it."""
        if self.last_frame_any is not None and now - self.last_frame_any > B.SNIFFER_OUTAGE:
            return self.last_frame_any + B.SNIFFER_OUTAGE
        return now

    def presence_of(self, node: Node, role: str, now: float) -> tuple[bool, bool]:
        return presence(node.last_heard, node.last_seen, node.last_addressed, role, self.presence_now(now),
                        node.last_diag, self.diag_ttl, self.offline_limit(node, role), self.diag_interval)

    def alive_until(self, node: Node, role: str) -> float:
        """When the device's silence passed the limit (what presence_of judges by): the offline event's time."""
        limit = self.offline_limit(node, role)
        until = node.last_seen + limit
        if node.last_diag > 0:
            until = max(until, node.last_diag + limit + (self.diag_interval if node.last_heard else 0.0))
        return until

    def _signature(self, node: Node, now: float) -> dict:
        role = self.role_of(node)
        online, _ = self.presence_of(node, role, now)
        return {"role": role, "rloc16": node.rloc16, "parent": self.parent_router_id(node),
                "partition": self.partition_of(node), "br": node.border_router, "online": online}

    def tick(self, now: float) -> None:
        """Compare every node with its state at the previous tick and record what changed. Call it regularly
        with the wall-clock time (online/offline is time based). The first tick only sets the baseline."""
        with self.lock:
            prev = self._last_tick if self._last_tick is not None else now
            self._last_tick = now
            within = lambda ts: ts if ts is not None and prev < ts <= now else now  # date events to when they happened
            for node in self.nodes.values():
                sig = self._signature(node, now)
                old = node.sig
                node.sig = sig
                if old is None:
                    continue
                changed = within(node.behavior.get("rloc_ts")) if sig["rloc16"] != old["rloc16"] else now
                if sig["role"] != old["role"]:
                    self._log(node, changed, "role", **{"from": old["role"], "to": sig["role"]})
                hexed = lambda v: None if v is None else f"0x{v:04x}"
                if sig["parent"] != old["parent"]:
                    params = {"from": old["parent"], "to": sig["parent"]}
                    if sig["rloc16"] != old["rloc16"]:  # an end device's short address follows its parent: one event
                        params.update(rloc16_from=hexed(old["rloc16"]), rloc16_to=hexed(sig["rloc16"]))
                    self._log(node, changed, "parent", **params)
                elif sig["rloc16"] != old["rloc16"]:
                    self._log(node, changed, "rloc16", **{"from": hexed(old["rloc16"]), "to": hexed(sig["rloc16"])})
                if sig["partition"] != old["partition"]:
                    self._log(node, now, "partition", **{"from": old["partition"], "to": sig["partition"]})
                if sig["br"] != old["br"]:
                    self._log(node, now, "br_on" if sig["br"] else "br_off")
                if sig["online"] != old["online"]:
                    alive = max(node.last_seen, node.last_diag)
                    if sig["online"]:  # back with the frame (or answer) that brought it back
                        self._log(node, within(alive), "online")
                    else:  # offline since its silence passed the limit
                        self._log(node, within(self.alive_until(node, sig["role"])), "offline")
            self._network_tick()
            self.capture.prune(now)
            for node in self.nodes.values():
                node.stats.prune(now)

    def live_partitions(self) -> dict[int, int]:
        """Partitions whose leader data still arrives (within 45 s of the newest one)."""
        newest = max(self.partition_seen.values(), default=None)
        return {pid: rid for pid, rid in self.leaders.items()
                if newest is None or self.partition_seen.get(pid, newest) >= newest - 45.0}

    def _network_tick(self) -> None:
        """The network as a whole: a split into partitions and the merge, and the number of routers."""
        ts = self.clock
        parts = self.live_partitions()
        routers = sum(1 for n in self.nodes.values() if n.rloc16 is not None and A.is_router_rloc(n.rloc16)
                      and self.role_of(n) in (ROLE_LEADER, ROLE_ROUTER) and self.presence_of(n, "router", ts)[0])
        before = self._net_state.get("partitions")
        if before is not None and len(parts) != before:
            self._net_log(ts, "partitions", count=len(parts), ids=sorted(parts))
        self._net_state["partitions"] = len(parts)
        before = self._net_state.get("routers")
        if before is not None and routers != before:
            self._net_log(ts, "routers", count=routers, before=before)
        self._net_state["routers"] = routers

    def clear_events(self) -> dict:
        """Clear the log: the history of every device and of the network (also in the database at the next save)."""
        with self.lock:
            removed = sum(len(n.events) for n in self.nodes.values()) + len(self.net_events)
            for node in self.nodes.values():
                node.events.clear()
            self.net_events.clear()
            self.pending_events.clear()
            self.events_cleared = True
            self.dirty = True
            return {"events_removed": removed}

    def set_name(self, node_id: str, name: str | None) -> str | None:
        """Give a device a name; an empty name removes it. Returns the stored name."""
        with self.lock:
            if node_id not in self.nodes:
                raise KeyError(node_id)
            name = (name or "").strip()
            if len(name) > MAX_NAME:
                raise ValueError(f"name too long (max {MAX_NAME} characters)")
            if name and not name.isprintable():
                raise ValueError("name contains control characters")
            if name:
                self.names[node_id] = name
            else:
                self.names.pop(node_id, None)
            self.dirty = True
            return self.names.get(node_id)

    def reset_topology(self) -> dict:
        """Forget everything learned from traffic and rebuild from scratch. Names stay: they are bound
        to MAC addresses and reappear as soon as a device is seen again; names of nodes known only by
        their short address are dropped, because that id may belong to another device afterwards."""
        with self.lock:
            removed = len(self.nodes)
            dropped = [nid for nid in self.names if nid.startswith("rloc16:")]
            for nid in dropped:
                del self.names[nid]
            self.nodes.clear()
            self.pending_events.clear()
            self._net_state.clear()  # the network log itself stays: it is the history
            self.rloc_index.clear()
            self.links.clear()
            self.link_metrics.clear()
            self.diag_ts = 0.0
            self.contexts.clear()
            self.services.clear()
            self.leaders.clear()
            self.partition_seen.clear()
            self.primary_partition = None
            self.ml_votes.clear()  # a prefix from the dataset (fixed_ml_prefix) is kept
            self.dirty = True
            return {"nodes_removed": removed, "names_kept": len(self.names), "names_dropped": len(dropped)}

    # ---- housekeeping / persistence ----------------------------------------

    def prune(self, now: float, max_age: float) -> int:
        with self.lock:
            stale = [n.id for n in self.nodes.values()
                     if max(n.last_seen, n.last_addressed, n.last_diag) < now - max_age]
            for nid in stale:
                del self.nodes[nid]
                if nid.startswith("rloc16:"):  # unstable id: its name cannot be re-attached later
                    self.names.pop(nid, None)
            self.rloc_index = {r: i for r, i in self.rloc_index.items() if i in self.nodes}
            for key in [k for k, v in self.links.items() if v["last_seen"] < now - max_age]:
                del self.links[key]
            for key in [k for k, v in self.link_metrics.items() if v["ts"] < now - max_age]:
                del self.link_metrics[key]
            for pid in [p for p, seen in self.partition_seen.items() if seen < now - max_age]:
                del self.partition_seen[pid]
                self.leaders.pop(pid, None)
            if stale:
                self.dirty = True
            return len(stale)

    def export_state(self, clear_dirty: bool = False) -> dict:
        """clear_dirty: reset the change flag atomically with the export, so a change made right
        after it is saved next time instead of being lost."""
        with self.lock:
            if clear_dirty:
                self.dirty = False
            for node in self.nodes.values():
                node.last_role = self.role_of(node)
            bucket_updates = [(n.id, i, vals) for n in self.nodes.values() for i, vals in n.stats.bucket_rows()]
            bucket_updates += [(CAPTURE_ID, i, vals) for i, vals in self.capture.bucket_rows()]
            events_new = [(nid, ev["ts"], ev["kind"], ev["params"]) for nid, ev in self.pending_events]
            events_cleared = self.events_cleared
            if clear_dirty:
                self.events_cleared = False
                for node in self.nodes.values():
                    node.stats.dirty.clear()
                self.capture.dirty.clear()
                self.pending_events = []
            return {
                "bucket_updates": bucket_updates, "events_new": events_new, "events_cleared": events_cleared,
                "nodes": [
                    {**{k: getattr(n, k) for k in (
                        "id", "ext", "rloc16", "partition_id", "ftd", "rx_on_idle", "polls",
                        "border_router", "br_seen", "mac_confirmed", "first_seen", "last_seen", "last_heard",
                        "last_addressed", "parent_hint", "last_role", "version", "last_diag", "link", "vendor",
                        "vendor_try", "child_timeout", "behavior")},
                     "stats": n.stats.to_json(),
                     "addresses": {a: list(t) for a, t in n.addresses.items()}}
                    for n in self.nodes.values()
                ],
                "links": [{"src": s, "dst": d, **v} for (s, d), v in self.links.items()],
                "link_metrics": [{"src": s, "dst": d, "data": dict(v)} for (s, d), v in self.link_metrics.items()],
                "names": dict(self.names),
                "meta": {
                    "leaders": {str(k): v for k, v in self.leaders.items()},
                    "partition_seen": {str(k): v for k, v in self.partition_seen.items()},
                    "clock": self.clock,
                    "primary_partition": self.primary_partition,
                    "ml_votes": {str(k): v for k, v in self.ml_votes.items()},
                    "fixed_ml_prefix": self.fixed_ml_prefix,
                    "capture_stats": self.capture.to_json(),
                    "contexts": {str(k): v for k, v in self.contexts.items()},
                    "services": {str(k): v for k, v in self.services.items()},
                    "diag_self": self.diag_self,
                },
            }

    def restore_unsaved(self, state: dict) -> None:
        """A save failed: make the exported changes pending again so the next save retries them."""
        with self.lock:
            for node_id, idx, _ in state.get("bucket_updates", []):
                target = self.capture if node_id == CAPTURE_ID else (
                    self.nodes[node_id].stats if node_id in self.nodes else None)
                if target is not None and idx in target.buckets:
                    target.dirty.add(idx)
            self.pending_events = [(nid, {"ts": ts, "kind": kind, "params": params})
                                   for nid, ts, kind, params in state.get("events_new", [])] + self.pending_events
            self.events_cleared = self.events_cleared or bool(state.get("events_cleared"))
            self.dirty = True

    def load_state(self, state: dict) -> None:
        with self.lock:
            for d in state.get("nodes", []):
                d = dict(d)
                d["behavior"] = d.get("behavior") or {}  # written by an older version
                stats = NodeStats.from_json(d.pop("stats", None))
                node = Node(**{**d, "addresses": {a: list(t) for a, t in d.get("addresses", {}).items()}})
                node.stats = stats
                if node.rloc16 is not None and not A.is_valid_rloc16(node.rloc16):  # written by an older version
                    if node.ext is None:
                        continue  # a pseudo node made of an invalid short address: drop it
                    node.rloc16 = None
                self.nodes[node.id] = node
                if node.rloc16 is not None:
                    self.rloc_index[node.rloc16] = node.id
            for d in state.get("links", []):
                self.links[(d["src"], d["dst"])] = {k: d[k] for k in ("lq_in", "lq_out", "cost", "last_seen")}
            for d in state.get("link_metrics", []):
                self.link_metrics[(d["src"], d["dst"])] = dict(d["data"])
            meta = state.get("meta", {})
            self.names = {k: v for k, v in state.get("names", {}).items()
                          if k in self.nodes or not k.startswith("rloc16:")}
            self.leaders = {int(k): v for k, v in meta.get("leaders", {}).items()}
            self.partition_seen = {int(k): v for k, v in meta.get("partition_seen", {}).items()}
            self.clock = meta.get("clock", 0.0)
            self.capture = NodeStats.from_json(meta.get("capture_stats"))
            self.contexts = {int(k): v for k, v in meta.get("contexts", {}).items()}
            self.services = {int(k): v for k, v in meta.get("services", {}).items()}
            if self.diag_self is None:
                self.diag_self = meta.get("diag_self")
            for node_id, idx, values in state.get("buckets", []):
                target = self.capture if node_id == CAPTURE_ID else (
                    self.nodes[node_id].stats if node_id in self.nodes else None)
                if target is not None:
                    target.load_bucket(idx, values)
            for node_id, ts, kind, params in state.get("events", []):
                if kind == "reboot" and params.get("how") in ("reset", "skip") and "counter" not in params:
                    continue  # written by a version that mixed the MAC and MLE counters: false alarms
                if (kind == "reboot" and params.get("how") == "reset" and isinstance(params.get("from"), int)
                        and isinstance(params.get("to"), int) and params["to"] >= B.COUNTER_AHEAD and params["from"] - params["to"] <= B.COUNTER_AHEAD):
                    continue  # a frame repeated to a sleepy child, taken for a restart by an older version
                if node_id == NETWORK_ID:
                    self.net_events.append({"ts": ts, "kind": kind, "params": params})
                elif node_id in self.nodes:
                    self.nodes[node_id].events.append({"ts": ts, "kind": kind, "params": params})
            for node in self.nodes.values():
                node.events.sort(key=lambda e: e["ts"])
                del node.events[:-EVENTS_PER_NODE]
            self.primary_partition = meta.get("primary_partition")
            self.ml_votes = Counter({int(k): v for k, v in meta.get("ml_votes", {}).items()})
            if self.fixed_ml_prefix is None:  # a dataset given on the command line wins
                self.fixed_ml_prefix = meta.get("fixed_ml_prefix")
            self.dirty = False
