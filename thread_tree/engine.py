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

MAX_NAME = 64
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
    last_role: str | None = None


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
        self.primary_partition: int | None = None
        self.fixed_ml_prefix = ml_prefix
        self.ml_votes: Counter[int] = Counter()
        # user-given device names, keyed by node id (the extended address: stable across re-parenting
        # and across pruning; a name for an RLOC16-only node is dropped if that node is pruned)
        self.names: dict[str, str] = {}
        self.dirty = False

    # ---- derived properties -------------------------------------------------

    @property
    def ml_prefix(self) -> int | None:
        if self.fixed_ml_prefix is not None:
            return self.fixed_ml_prefix
        if self.ml_votes:
            return self.ml_votes.most_common(1)[0][0]
        return None

    def role_of(self, node: Node) -> str:
        if node.rloc16 is not None:
            if A.is_router_rloc(node.rloc16):
                pid = node.partition_id if node.partition_id is not None else self.primary_partition
                leader = self.leaders.get(pid) if pid is not None else None
                return ROLE_LEADER if leader == A.router_id(node.rloc16) else ROLE_ROUTER
            return end_device_role(node)
        if node.last_role:
            return node.last_role
        return end_device_role(node) if node.ftd is not None else ROLE_UNKNOWN

    # ---- node resolution ----------------------------------------------------

    def node_for(self, ts: float, ext: str | None = None, rloc16: int | None = None,
                 touch: bool = True) -> Node | None:
        if ext is None and rloc16 is None:
            return None
        if ext is not None:
            node = self.nodes.get(ext)
            if node is None:
                node = self.nodes[ext] = Node(id=ext, ext=ext, first_seen=ts, last_seen=ts)
            if rloc16 is not None:
                self._bind(node, rloc16)
        else:
            nid = self.rloc_index.get(rloc16)
            node = self.nodes.get(nid) if nid else None
            if node is None:
                node = Node(id=f"rloc16:{rloc16:04x}", rloc16=rloc16, first_seen=ts, last_seen=ts)
                self.nodes[node.id] = node
                self.rloc_index[rloc16] = node.id
        if touch and ts > node.last_seen:
            node.last_seen = ts
        self.dirty = True
        return node

    def _bind(self, node: Node, rloc16: int) -> None:
        current = self.rloc_index.get(rloc16)
        if current == node.id:
            node.rloc16 = rloc16
            return
        if current is not None and current in self.nodes:
            other = self.nodes[current]
            if other.ext is None:
                self._merge(other, node)
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
        into.polls |= prov.polls
        for attr in ("partition_id", "ftd", "rx_on_idle", "last_role"):
            if getattr(into, attr) is None:
                setattr(into, attr, getattr(prov, attr))
        into.first_seen = min(into.first_seen, prov.first_seen)
        into.last_seen = max(into.last_seen, prov.last_seen)
        into.last_heard = max(into.last_heard, prov.last_heard)
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

    def on_destination(self, ts: float, dst_ext: str | None) -> None:
        """A MAC address seen only as a frame destination: the device exists (not heard directly)."""
        if dst_ext is not None and dst_ext != "ffffffffffffffff":
            self.node_for(ts, ext=dst_ext, touch=False)

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
                       leader_router_id: int) -> None:
        self.leaders[partition_id] = leader_router_id
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
        self.dirty = True

    def on_mode(self, ts: float, node: Node | None, ftd: bool, rx_on_idle: bool) -> None:
        if node is not None:
            node.ftd, node.rx_on_idle = ftd, rx_on_idle
            self.dirty = True

    def on_data_poll(self, ts: float, node: Node | None) -> None:
        if node is not None and not node.polls:
            node.polls = True
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

    def on_network_data(self, ts: float, border_router_rloc16s: set[int]) -> None:
        """Complete Network Data seen: exactly these RLOC16s are border routers."""
        for rloc16 in border_router_rloc16s:
            node = self.node_for(ts, rloc16=rloc16, touch=False)
            if node is not None:
                node.border_router = True
        for node in self.nodes.values():
            if node.rloc16 is not None and node.rloc16 not in border_router_rloc16s:
                node.border_router = False
        self.dirty = True

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
            self.rloc_index.clear()
            self.links.clear()
            self.leaders.clear()
            self.primary_partition = None
            self.ml_votes.clear()  # a prefix from the dataset (fixed_ml_prefix) is kept
            self.dirty = True
            return {"nodes_removed": removed, "names_kept": len(self.names), "names_dropped": len(dropped)}

    # ---- housekeeping / persistence ----------------------------------------

    def prune(self, now: float, max_age: float) -> int:
        with self.lock:
            stale = [n.id for n in self.nodes.values() if n.last_seen < now - max_age]
            for nid in stale:
                del self.nodes[nid]
                if nid.startswith("rloc16:"):  # unstable id: its name cannot be re-attached later
                    self.names.pop(nid, None)
            self.rloc_index = {r: i for r, i in self.rloc_index.items() if i in self.nodes}
            for key in [k for k, v in self.links.items() if v["last_seen"] < now - max_age]:
                del self.links[key]
            if stale:
                self.dirty = True
            return len(stale)

    def export_state(self) -> dict:
        with self.lock:
            for node in self.nodes.values():
                node.last_role = self.role_of(node)
            return {
                "nodes": [
                    {**{k: getattr(n, k) for k in (
                        "id", "ext", "rloc16", "partition_id", "ftd", "rx_on_idle", "polls",
                        "border_router", "first_seen", "last_seen", "last_heard", "last_role")},
                     "addresses": {a: list(t) for a, t in n.addresses.items()}}
                    for n in self.nodes.values()
                ],
                "links": [{"src": s, "dst": d, **v} for (s, d), v in self.links.items()],
                "names": dict(self.names),
                "meta": {
                    "leaders": {str(k): v for k, v in self.leaders.items()},
                    "primary_partition": self.primary_partition,
                    "ml_votes": {str(k): v for k, v in self.ml_votes.items()},
                    "fixed_ml_prefix": self.fixed_ml_prefix,
                },
            }

    def load_state(self, state: dict) -> None:
        with self.lock:
            for d in state.get("nodes", []):
                node = Node(**{**d, "addresses": {a: list(t) for a, t in d.get("addresses", {}).items()}})
                self.nodes[node.id] = node
                if node.rloc16 is not None:
                    self.rloc_index[node.rloc16] = node.id
            for d in state.get("links", []):
                self.links[(d["src"], d["dst"])] = {k: d[k] for k in ("lq_in", "lq_out", "cost", "last_seen")}
            meta = state.get("meta", {})
            self.names = dict(state.get("names", {}))
            self.leaders = {int(k): v for k, v in meta.get("leaders", {}).items()}
            self.primary_partition = meta.get("primary_partition")
            self.ml_votes = Counter({int(k): v for k, v in meta.get("ml_votes", {}).items()})
            if self.fixed_ml_prefix is None:  # a dataset given on the command line wins
                self.fixed_ml_prefix = meta.get("fixed_ml_prefix")
            self.dirty = False
