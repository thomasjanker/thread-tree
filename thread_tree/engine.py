"""Topology engine: turns observations (from a sniffer or a simulator) into
a persistent model of the Thread network.

Identity: a node is keyed by its extended address (EUI-64) once known. Until
then it is a provisional node keyed by RLOC16 and is merged on first binding.
The RLOC16 is *not* an identity: it changes when a device re-parents or a
router ID is reassigned, so parent/child structure is derived from the current
RLOC16 at snapshot time, never stored.
"""

from __future__ import annotations

import ipaddress
import threading
from collections import Counter
from dataclasses import dataclass, field

from . import addresses as A
from . import behavior as B
from .otdiag import Child, Netdata, Router, RouterNeighbor
from .presence import presence
from .stats import NodeStats

MAX_NAME = 64
EVENTS_PER_NODE = 200
CHILD_TIMEOUT_DEFAULT = 240.0  # a child in a parent's table was heard within its timeout (this is the usual value)
CAPTURE_ID = "_capture"  # statistics of the whole capture are stored like a node, under this id
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
        self.diag_self: str | None = None  # extended address of the node that runs the active diagnostics
        self.diag_ts = 0.0  # time of the latest topology answer of the active diagnostics
        self.diag_ttl = DIAG_TTL  # how long its answers count as current (the collector raises it for long intervals)
        self.diag_info: dict = {}  # status of the active collector, for the UI (not persisted)
        self.capture = NodeStats()  # all frames heard, including those without transmitter address (ACKs)
        self.last_frame_any: float | None = None  # last frame the sniffer received (not persisted)
        self.data_versions: dict[int, int] = {}  # partition id -> latest advertised Network Data version (not persisted)
        self.demo_outage: tuple | None = None  # demo only: (router id, since) switched off by an outage test
        self.sniffer_outages: list[tuple[float, float]] = []  # periods without any frame: the sniffer was deaf
        self.pending_events: list[tuple[str, dict]] = []  # not yet saved
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

    def _log(self, node: Node, ts: float, kind: str, **params) -> None:
        event = {"ts": ts, "kind": kind, "params": params}
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
        self.rloc_index[rloc16] = node.id

    def _merge(self, prov: Node, into: Node) -> None:
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

    def record_frame(self, ts: float, node: Node | None, kind: str, length: int | None = None,
                     rssi: float | None = None, lqi: float | None = None, seq: int | None = None,
                     dst: str | None = None) -> None:
        """Statistics of one frame heard. node is None when the frame has no transmitter address (ACKs)."""
        if self.last_frame_any is not None and ts - self.last_frame_any > B.SNIFFER_OUTAGE:
            self.sniffer_outages.append((self.last_frame_any, ts))
            del self.sniffer_outages[:-B.OUTAGES_KEPT]
        self.last_frame_any = ts if self.last_frame_any is None else max(self.last_frame_any, ts)
        if node is not None:
            retry = node.stats.record_frame(ts, kind, length, rssi, lqi, seq, dst)
            if kind == "poll" and not retry:
                gap = B.on_poll(node.behavior, ts, self.sniffer_was_down)
                if gap:
                    self._log(node, ts, "poll_gap", timeout=node.child_timeout, **gap)
        self.capture.record_frame(ts, kind, length, rssi, lqi)
        self.clock = max(self.clock, ts)
        self.dirty = True

    def sniffer_was_down(self, start: float, end: float) -> bool:
        return any(s < end and e > start for s, e in self.sniffer_outages)

    def on_parent_request(self, ts: float, node: Node | None) -> None:
        """MLE Parent Request: the device looks for a parent. If it has one, it has lost the link to it."""
        if node is not None and B.on_parent_request(node.behavior, ts):
            self._log(node, ts, "parent_search", parent=self.parent_router_id(node))
            self.dirty = True

    def on_attach_request(self, ts: float, node: Node | None, parent: Node | None) -> None:
        """MLE Child ID Request: the device chose a parent (the destination); ends a search."""
        if node is None:
            return
        done = B.on_attach_request(node.behavior, ts)
        if done:
            to = A.router_id(parent.rloc16) if parent is not None and parent.rloc16 is not None else None
            self._log(node, ts, "attached", to=to, **done)
            self.dirty = True

    def on_discovery_request(self, ts: float, node: Node | None) -> None:
        """MLE Discovery Request: a device looks for Thread networks, typically a new one before commissioning."""
        if node is not None:
            self._log(node, ts, "discovery")
            self.dirty = True

    def on_child_timeout(self, ts: float, node: Node | None, seconds: int) -> None:
        if node is not None and 0 < seconds and node.child_timeout != seconds:
            node.child_timeout = seconds
            self.dirty = True

    def on_address_assignment(self, ts: float, ext: str | None, rloc16: int | None) -> None:
        """A parent told a child its new RLOC16 (Child ID Response): binds MAC address and short address."""
        if ext is not None and rloc16 is not None and rloc16 not in (0xFFFE, 0xFFFF):
            self.node_for(ts, ext=ext, rloc16=rloc16, touch=False)

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
        self.leaders[partition_id] = leader_router_id
        if data_version is not None:  # Network Data version the sender has (the leader raises it on every change)
            self.data_versions[partition_id] = data_version
        self.partition_seen[partition_id] = max(self.partition_seen.get(partition_id, ts), ts)
        self.clock = max(self.clock, ts)
        # stay with the primary partition while it is alive: no flapping between concurrent partitions
        if not self.is_current_partition(self.primary_partition):
            self.primary_partition = partition_id
        if sender is not None:
            sender.partition_id = partition_id
        self.dirty = True

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
        """Network Data as the diagnostic node sees it (it asks for the full copy): contexts and border routers."""
        with self.lock:
            self.contexts.update(data.context_prefixes64())
            self.on_network_data(ts, data.border_router_rloc16s(), complete=True)

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

    def _signature(self, node: Node, now: float) -> dict:
        role = self.role_of(node)
        online, _ = presence(node.last_heard, node.last_seen, node.last_addressed, role, now, node.last_diag, self.diag_ttl)
        return {"role": role, "rloc16": node.rloc16, "parent": self.parent_router_id(node),
                "partition": self.partition_of(node), "br": node.border_router, "online": online}

    def tick(self, now: float) -> None:
        """Compare every node with its state at the previous tick and record what changed. Call it regularly
        with the wall-clock time (online/offline is time based). The first tick only sets the baseline."""
        with self.lock:
            for node in self.nodes.values():
                sig = self._signature(node, now)
                old = node.sig
                node.sig = sig
                if old is None:
                    continue
                if sig["role"] != old["role"]:
                    self._log(node, now, "role", **{"from": old["role"], "to": sig["role"]})
                hexed = lambda v: None if v is None else f"0x{v:04x}"
                if sig["parent"] != old["parent"]:
                    params = {"from": old["parent"], "to": sig["parent"]}
                    if sig["rloc16"] != old["rloc16"]:  # an end device's short address follows its parent: one event
                        params.update(rloc16_from=hexed(old["rloc16"]), rloc16_to=hexed(sig["rloc16"]))
                    self._log(node, now, "parent", **params)
                elif sig["rloc16"] != old["rloc16"]:
                    self._log(node, now, "rloc16", **{"from": hexed(old["rloc16"]), "to": hexed(sig["rloc16"])})
                if sig["partition"] != old["partition"]:
                    self._log(node, now, "partition", **{"from": old["partition"], "to": sig["partition"]})
                if sig["br"] != old["br"]:
                    self._log(node, now, "br_on" if sig["br"] else "br_off")
                if sig["online"] != old["online"]:
                    self._log(node, now, "online" if sig["online"] else "offline")
            self.capture.prune(now)
            for node in self.nodes.values():
                node.stats.prune(now)

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
            self.rloc_index.clear()
            self.links.clear()
            self.link_metrics.clear()
            self.diag_ts = 0.0
            self.contexts.clear()
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
            if clear_dirty:
                for node in self.nodes.values():
                    node.stats.dirty.clear()
                self.capture.dirty.clear()
                self.pending_events = []
            return {
                "bucket_updates": bucket_updates, "events_new": events_new,
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
            if self.diag_self is None:
                self.diag_self = meta.get("diag_self")
            for node_id, idx, values in state.get("buckets", []):
                target = self.capture if node_id == CAPTURE_ID else (
                    self.nodes[node_id].stats if node_id in self.nodes else None)
                if target is not None:
                    target.load_bucket(idx, values)
            for node_id, ts, kind, params in state.get("events", []):
                if node_id in self.nodes:
                    self.nodes[node_id].events.append({"ts": ts, "kind": kind, "params": params})
            for node in self.nodes.values():
                node.events.sort(key=lambda e: e["ts"])
                del node.events[:-EVENTS_PER_NODE]
            self.primary_partition = meta.get("primary_partition")
            self.ml_votes = Counter({int(k): v for k, v in meta.get("ml_votes", {}).items()})
            if self.fixed_ml_prefix is None:  # a dataset given on the command line wins
                self.fixed_ml_prefix = meta.get("fixed_ml_prefix")
            self.dirty = False
