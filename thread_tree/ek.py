"""Adapter: tshark `-T ek` packets -> Engine observations.

Field names come from the Wireshark display filter reference (mle, wpan,
thread_nwd, thread_address). They are resolved against `tshark -G fields` at
startup, so a field missing in the installed Wireshark version disables only
that feature instead of aborting tshark.
"""

from __future__ import annotations

import logging
from collections import deque

from . import addresses as A
from .engine import Engine

log = logging.getLogger(__name__)

# logical name -> candidate Wireshark field names (first one that exists is used)
FIELDS: dict[str, list[str]] = {
    "src64": ["wpan.src64"],
    "src16": ["wpan.src16"],
    "dst64": ["wpan.dst64"],
    "dst16": ["wpan.dst16"],
    "mle_addr16": ["mle.tlv.addr16"],
    "mac_cmd": ["wpan.cmd"],
    "frame_type": ["wpan.frame_type"],
    "seq": ["wpan.seq_no"],
    "rssi": ["wpan-tap.rss"],  # present with the sniffer's ieee802154-tap metadata
    "lqi": ["wpan-tap.lqi"],
    "frame_len": ["frame.len"],
    "tap_len": ["wpan-tap.length"],
    "ip_src": ["ipv6.src"],
    "ip_dst": ["ipv6.dst"],
    "mle_cmd": ["mle.cmd"],
    "mle_no_key": ["mle.no_key"],
    "mle_decrypt_failed": ["mle.decrypt_failed"],
    "mle_mic_failed": ["mle.mic_check_failed"],
    "mle_src": ["mle.tlv.source_addr"],
    "partition": ["mle.tlv.leader_data.partition_id"],
    "leader_rid": ["mle.tlv.leader_data.router_id"],
    "data_version": ["mle.tlv.leader_data.data_version"],
    "route_mask": ["mle.tlv.route64.id_mask"],
    "route_cost": ["mle.tlv.route64.cost"],
    "route_in": ["mle.tlv.route64.nbr_in"],
    "route_out": ["mle.tlv.route64.nbr_out"],
    "mle_timeout": ["mle.tlv.timeout"],
    "mle_supervision": ["mle.tlv.supervision_interval", "mle.tlv.supervision"],
    "mle_link_margin": ["mle.tlv.link_margin"],
    "frame_counter": ["wpan.aux_sec.frame_counter"],
    "csl_period": ["wpan.header_ie.csl.period"],  # CSL IE: the sender is a CSL receiver (Thread 1.2)
    "csl_timeout": ["mle.tlv.csl_sychronized_timeout", "mle.tlv.csl_synchronized_timeout", "mle.tlv.csl_timeout"],
    "key_index": ["wpan.aux_sec.key_index"],
    "key_id_mode": ["wpan.aux_sec.key_id_mode"],
    # for the live view and the protocol details (missing ones only leave a detail empty)
    "frame_no": ["frame.number"],
    "pending": ["wpan.pending"],
    "ack_req": ["wpan.ack_request"],
    "security": ["wpan.security"],
    "frame_version": ["wpan.version"],
    "sec_level": ["wpan.aux_sec.sec_level"],
    "mesh_orig16": ["6lowpan.mesh.orig16"],
    "mesh_orig64": ["6lowpan.mesh.orig64"],
    "mesh_dest16": ["6lowpan.mesh.dest16"],
    "mesh_dest64": ["6lowpan.mesh.dest64"],
    "mesh_hops": ["6lowpan.mesh.hops"],
    "udp_src": ["udp.srcport"],
    "udp_dst": ["udp.dstport"],
    "udp_len": ["udp.length"],
    "icmp_type": ["icmpv6.type"],
    "coap_uri": ["coap.opt.uri_path"],
    "coap_code": ["coap.code"],
    "mle_tlv": ["mle.tlv.type"],
    "dns_name": ["dns.qry.name"],
    "dns_resp": ["dns.resp.name"],
    "dns_srv": ["dns.srv.target"],
    "mode_ftd": ["mle.tlv.mode.device_type"],
    "mode_idle_rx": ["mle.tlv.mode.idle_rx"],
    "reg_ipv6": ["mle.tlv.addr_reg_ipv6"],
    "reg_iid": ["mle.tlv.addr_reg_iid"],
    "reg_cid": ["mle.tlv.addr_reg_cid"],
    "nwd_prefix": ["thread_nwd.tlv.prefix"],
    "nwd_prefix_len": ["thread_nwd.tlv.prefix.length"],
    "nwd_context_id": ["thread_nwd.tlv.6co.context_id"],
    "nwd_br16": ["thread_nwd.tlv.border_router.16"],
    "nwd_hr16": ["thread_nwd.tlv.has_route.br_16"],
    "addr_target": ["thread_address.tlv.target_eid", "thread_address.target_eid"],
    "addr_rloc": ["thread_address.tlv.rloc16", "thread_address.rloc16"],
    "addr_ml_eid": ["thread_address.tlv.ml_eid", "thread_address.ml_eid"],
}

# MLE command IDs (Thread spec 4.5)
MLE_LINK_REQUEST = 0  # multicast after a router restarted
MLE_ADVERTISEMENT = 4
MLE_PARENT_REQUEST = 9  # a device looks for a parent
MLE_DISCOVERY_REQUEST = 16  # a device looks for networks (before commissioning)
MLE_CHILD_ID_REQUEST = 11  # ... and asks the one it chose (the destination)
MLE_PARENT_RESPONSE = 10  # a router offers itself, with the link margin it measured
MLE_CHILD_ID_RESPONSE = 12  # parent -> child: carries the assigned Address16
MLE_FROM_CHILD = (9, 11, 13)  # Parent Request, Child ID Request, Child Update Request
MLE_CHILD_UPDATE_RESPONSE = 14  # from a child when its parent asked; from the parent otherwise
MAC_DATA_REQUEST = 4
PORTS = {19788: "mle", 61631: "tmf", 5540: "matter", 53: "dns", 53535: "srp", 5683: "coap"}
POLL_ACK = 0.1  # s: the acknowledgement of a data poll follows at once (with "frame pending" if data waits)


# details for the live view only: a missing one is not worth a warning
DETAIL_FIELDS = {"frame_no", "pending", "ack_req", "security", "frame_version", "sec_level", "mesh_orig16", "mesh_orig64",
                 "mesh_dest16", "mesh_dest64", "mesh_hops", "udp_src", "udp_dst", "udp_len", "icmp_type", "coap_uri",
                 "coap_code", "mle_tlv", "dns_name", "dns_resp", "dns_srv"}


def resolve_fields(available: set[str]) -> dict[str, str]:
    """Pick one existing Wireshark field per logical name; log what is missing."""
    chosen: dict[str, str] = {}
    for logical, names in FIELDS.items():
        for name in names:
            if name in available:
                chosen[logical] = name
                break
        else:
            (log.info if logical in DETAIL_FIELDS else log.warning)(
                "Wireshark field for %r not available (%s): feature disabled", logical, names[0])
    return chosen


class Handler:
    def __init__(self, engine: Engine, fields: dict[str, str]):
        self.engine = engine
        self.fields = fields
        # MLE messages seen, and how many could / could not be decrypted
        self.stats = {"frames": 0, "mle_ok": 0, "mle_failed": 0}
        self._last_nwd: tuple | None = None
        self.recent: deque[dict] = deque(maxlen=2000)  # the last frames, for the live view
        self.seq = 0
        self._poll: tuple | None = None  # (sequence number, node, time) of the last data poll: its ack tells "pending"

    def _all(self, layers: dict, logical: str) -> list[str]:
        name = self.fields.get(logical)
        if name is None:
            return []
        flat = name.replace(".", "_")
        value = layers.get(flat)
        if value is None:  # un-filtered ek output repeats the protocol: wpan_wpan_src64
            value = layers.get(f"{name.split('.')[0]}_{flat}")
        if value is None:
            return []
        return [str(v) for v in value] if isinstance(value, list) else [str(value)]

    def _present(self, layers: dict, logical: str) -> bool:
        """Field exists in the packet, whatever its value (label-only fields have none)."""
        name = self.fields.get(logical)
        if name is None:
            return False
        flat = name.replace(".", "_")
        return flat in layers or f"{name.split('.')[0]}_{flat}" in layers

    def _one(self, layers: dict, logical: str) -> str | None:
        values = self._all(layers, logical)
        return values[0] if values else None

    @staticmethod
    def _int(text: str | None, base: int = 0) -> int | None:
        if text is None:
            return None
        try:
            return int(text, base)
        except ValueError:
            return None

    @staticmethod
    def _number(text: str | None) -> float | None:
        if text is None:
            return None
        try:
            return int(text, 0)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return None

    def _frame_bytes(self, layers: dict) -> int | None:
        """Size of the 802.15.4 frame: the captured frame minus the TAP pseudo header, if there is one."""
        total = self._int(self._one(layers, "frame_len"))
        tap = self._int(self._one(layers, "tap_len"))
        if total is None:
            return None
        return total - tap if tap and 0 < tap < total else total

    def _kind(self, layers: dict, mle_cmd: int | None, mac_cmd: int | None, addressed: bool) -> str:
        frame_type = self._int(self._one(layers, "frame_type"))
        if frame_type == 2 or (frame_type is None and not addressed and mle_cmd is None and mac_cmd is None):
            return "ack"  # acknowledgements carry no addresses
        if frame_type == 0:
            return "beacon"
        if mle_cmd is not None:
            return "adv" if mle_cmd == MLE_ADVERTISEMENT else "mle"
        if any(self._present(layers, k) for k in ("mle_no_key", "mle_decrypt_failed", "mle_mic_failed")):
            return "mle"  # an MLE message that could not be decrypted
        if mac_cmd == MAC_DATA_REQUEST:
            return "poll"
        if mac_cmd is not None:
            return "cmd"
        return "data" if frame_type in (None, 1) else "other"

    @staticmethod
    def _bool(text: str | None) -> bool | None:
        if text is None:
            return None
        return text.strip().lower() in ("1", "true")

    def handle(self, packet: dict) -> None:
        layers = packet.get("layers")
        if not layers:
            return
        try:
            ts = float(packet.get("timestamp", 0)) / 1000.0
        except (TypeError, ValueError):
            return
        self.stats["frames"] += 1
        with self.engine.lock:
            self._handle(ts, layers)

    def _handle(self, ts: float, layers: dict) -> None:
        e = self.engine
        src64 = self._one(layers, "src64")
        ext = A.normalize_ext(src64) if src64 else None
        mle_src = self._one(layers, "mle_src")
        src16 = A.parse_rloc16(self._one(layers, "src16") or mle_src or "") if (
            self._one(layers, "src16") or mle_src) else None
        if src16 in (0xFFFE, 0xFFFF):  # "extended address only" / broadcast marker
            src16 = None
        sender = e.on_frame(ts, ext, src16)
        ip_src = self._one(layers, "ip_src")
        if ext is None and src16 is not None:
            # a link-local source is never forwarded: MAC-based link-local + short MAC source = same device
            ll_mac = A.mac_from_link_local(ip_src)
            if ll_mac is not None:
                sender = e.on_frame(ts, ll_mac, src16)
        dst64 = self._one(layers, "dst64")
        dst_ext = A.normalize_ext(dst64) if dst64 else None
        dst16_text = self._one(layers, "dst16")
        dst16 = A.parse_rloc16(dst16_text) if dst16_text else None
        length = self._frame_bytes(layers)
        e.on_destination(ts, dst_ext, dst16, length)

        mac_cmd = self._int(self._one(layers, "mac_cmd"))
        if mac_cmd == MAC_DATA_REQUEST:
            e.on_data_poll(ts, sender)
            e.on_data_request(ts, sender, dst16, dst_ext, sender_by_mac=ext is not None and src16 is None)
        e.on_ip(ts, sender, ip_src, self._one(layers, "ip_dst"))

        csl = self._int(self._one(layers, "csl_period"))
        if csl and sender is not None and not (sender.rloc16 is not None and A.is_router_rloc(sender.rloc16)):
            e.on_csl(ts, sender, csl)
        # one auxiliary security header for the MAC frame and one for an MLE message: told apart by the key id mode
        # (MLE: mode 2 with the key sequence; MAC: mode 1); without it, a frame carrying MLE counts as MLE
        counters, modes, keys = self._all(layers, "frame_counter"), self._all(layers, "key_id_mode"), self._all(layers, "key_index")
        for i, text in enumerate(counters):
            counter = self._int(text)
            if counter is None:
                continue
            mode = self._int(modes[i]) if i < len(modes) else None
            context = ("mle" if mode == 2 else "mac") if mode is not None else (
                "mle" if self._one(layers, "mle_cmd") is not None or len(counters) > 1 and i == 1 else "mac")
            e.on_frame_counter(ts, sender, counter, self._int(keys[i]) if i < len(keys) else None, context)
        mle_cmd = self._int(self._one(layers, "mle_cmd"))
        addressed = any(v is not None for v in (src64, src16, dst64, dst16))
        kind = self._kind(layers, mle_cmd, mac_cmd, addressed)
        rssi = self._number(self._one(layers, "rssi"))
        retry = e.record_frame(ts, sender, kind, length, rssi, self._number(self._one(layers, "lqi")),
                               self._int(self._one(layers, "seq")),
                               dst_ext or (f"{dst16:04x}" if dst16 is not None else None))
        failed = any(self._present(layers, k) for k in ("mle_no_key", "mle_decrypt_failed", "mle_mic_failed"))
        if failed:
            self.stats["mle_failed"] += 1
        elif mle_cmd is not None:
            self.stats["mle_ok"] += 1
        self.seq += 1
        record = {
            "seq": self.seq, "ts": ts, "src": sender.id if sender is not None else None,
            "src16": None if src16 is None else f"0x{src16:04x}", "dst": dst_ext,
            "dst16": None if dst16 is None else f"0x{dst16:04x}", "kind": kind, "mle": mle_cmd,
            "rssi": rssi, "len": length, "retry": retry, "decrypt": "failed" if failed else "ok" if mle_cmd is not None else None}
        record.update(self._details(ts, layers, sender, kind, mac_cmd, ip_src))
        self.recent.append(record)
        if mle_cmd is not None:
            self._handle_mle(ts, layers, sender, src16, mle_cmd)

        targets, rlocs = self._all(layers, "addr_target"), self._all(layers, "addr_rloc")
        if len(targets) == 1 and len(rlocs) == 1:  # Address Notification
            rloc16 = A.parse_rloc16(rlocs[0]) if rlocs[0].lower().startswith("0x") else self._int(rlocs[0], 10)
            if rloc16 is not None:
                e.on_address_notification(ts, targets[0], rloc16)
                ml_iid = self._one(layers, "addr_ml_eid")  # the same device's ML-EID interface ID
                if ml_iid and e.ml_prefix is not None:
                    try:
                        e.on_address_notification(ts, str(A.addr_from(e.ml_prefix, int(ml_iid.replace(":", ""), 16))),
                                                  rloc16)
                    except ValueError:
                        pass

        if self._all(layers, "nwd_prefix"):  # complete Network Data with prefixes
            raw = (tuple(self._all(layers, "nwd_br16")), tuple(self._all(layers, "nwd_hr16")))
            if raw != self._last_nwd:  # log changes only: shows what Wireshark reports as border routers
                self._last_nwd = raw
                log.info("network data: prefixes=%s border_router.16=%s has_route.br_16=%s",
                         self._all(layers, "nwd_prefix"), list(raw[0]), list(raw[1]))
            self._contexts(layers)
            brs = {self._int(v) for v in raw[0] + raw[1]}
            # the stable subset (sent to sleepy children) replaces every RLOC16 with 0xfffe
            complete = 0xFFFE not in brs
            e.on_network_data(ts, {v for v in brs if v is not None and A.is_valid_rloc16(v)}, complete)

    def _details(self, ts: float, layers: dict, sender, kind: str, mac_cmd: int | None, ip_src: str | None) -> dict:
        """What else the frame says, for the live view, and what the engine learns from it: the mesh header of a
        forwarded packet, Matter traffic, router ID requests (TMF), SRP registrations, pending data for sleepy devices."""
        e = self.engine
        out: dict = {"no": self._int(self._one(layers, "frame_no"))}
        flags = {k: self._bool(self._one(layers, k)) for k in ("pending", "ack_req", "security")}
        flags["version"] = self._int(self._one(layers, "frame_version"))
        out["flags"] = {k: v for k, v in flags.items() if v is not None}
        counter, level = self._int(self._one(layers, "frame_counter")), self._int(self._one(layers, "sec_level"))
        if counter is not None or level is not None:
            out["sec"] = {"level": level, "mode": self._int(self._one(layers, "key_id_mode")), "counter": counter,
                          "key": self._int(self._one(layers, "key_index"))}
        seq = self._int(self._one(layers, "seq"))
        if mac_cmd == MAC_DATA_REQUEST and sender is not None:  # data poll: its acknowledgement says whether data waits
            self._poll = (seq, sender, ts)
        elif kind == "ack" and self._poll and seq == self._poll[0] and 0 <= ts - self._poll[2] <= POLL_ACK:
            e.on_poll_answer(ts, self._poll[1], bool(flags.get("pending")))
            out["answers"] = self._poll[1].id
            self._poll = None
        # mesh header: a packet forwarded over several hops names its origin and final destination
        def mesh_node(prefix: str):
            ext = self._one(layers, f"mesh_{prefix}64")
            short = self._one(layers, f"mesh_{prefix}16")
            if ext:
                return e.nodes.get(A.normalize_ext(ext) or ""), A.normalize_ext(ext)
            if short:
                rloc = A.parse_rloc16(short)
                return e.nodes.get(e.rloc_index.get(rloc, "")) if rloc is not None else None, short
            return None, None
        (origin, olabel), (dest, dlabel) = mesh_node("orig"), mesh_node("dest")
        if olabel or dlabel:
            hops = self._int(self._one(layers, "mesh_hops"))
            out["mesh"] = {"orig": origin.id if origin else olabel, "dest": dest.id if dest else dlabel, "hops": hops}
            e.on_relay(ts, sender, origin, dest)
        ip_dst = self._one(layers, "ip_dst")
        if ip_src or ip_dst:
            out["ip"] = {"src": ip_src, "dst": ip_dst}
        sport, dport = self._int(self._one(layers, "udp_src")), self._int(self._one(layers, "udp_dst"))
        proto = PORTS.get(dport) or PORTS.get(sport) or ("icmpv6" if self._one(layers, "icmp_type") else None)
        if sport is not None or dport is not None:
            out["udp"] = {"src": sport, "dst": dport, "len": self._int(self._one(layers, "udp_len"))}
        if proto:
            out["proto"] = proto
        if proto == "icmpv6":
            out["icmp"] = self._int(self._one(layers, "icmp_type"))
        tlvs = [self._int(v) for v in self._all(layers, "mle_tlv")]
        if tlvs:
            out["tlvs"] = [v for v in tlvs if v is not None]
        origin_by_ip = e.node_for_ip(ip_src) or (origin if origin is not None else None)
        if proto == "matter":  # end-to-end encrypted: only who, when and how much
            e.on_matter(ts, origin_by_ip, e.node_for_ip(ip_dst), self._int(self._one(layers, "udp_len")))
        uri = "/".join(self._all(layers, "coap_uri"))
        if uri:
            out["uri"] = "/" + uri
            out["coap"] = self._int(self._one(layers, "coap_code"))
            if proto == "tmf" and uri in ("a/as", "a/ar") and out["coap"] == 2:  # POST: a router ID requested / released
                e.on_router_id(ts, origin_by_ip, "request" if uri == "a/as" else "release")
        names = list(dict.fromkeys(self._all(layers, "dns_name") + self._all(layers, "dns_resp") + self._all(layers, "dns_srv")))
        if names:
            out["dns"] = names[:8]
            if proto == "srp":
                e.on_srp(ts, origin_by_ip or sender, names)
        return out

    def _handle_mle(self, ts: float, layers: dict, sender, src16: int | None, cmd: int) -> None:
        e = self.engine
        pid = self._int(self._one(layers, "partition"))
        lrid = self._int(self._one(layers, "leader_rid"))
        if pid is not None and lrid is not None:
            e.on_leader_data(ts, sender, pid, lrid, self._int(self._one(layers, "data_version")))

        mask = self._one(layers, "route_mask")
        if mask and src16 is not None:
            entries = self._route_entries(layers, mask)
            if entries:
                e.on_route64(ts, src16, entries)

        if cmd == MLE_LINK_REQUEST and (self._one(layers, "ip_dst") or "").lower().startswith("ff02::2"):
            e.on_router_restart(ts, sender)  # to all routers: a router that just restarted
        if cmd == MLE_PARENT_RESPONSE:
            dst64 = self._one(layers, "dst64")
            e.on_parent_response(ts, sender, A.normalize_ext(dst64) if dst64 else None,
                                 self._int(self._one(layers, "mle_link_margin")))
        elif cmd == MLE_PARENT_REQUEST:
            e.on_parent_request(ts, sender)
        elif cmd == MLE_DISCOVERY_REQUEST:
            e.on_discovery_request(ts, sender)
        elif cmd == MLE_CHILD_ID_REQUEST:
            dst64 = self._one(layers, "dst64")
            dst16 = A.parse_rloc16(self._one(layers, "dst16") or "") if self._one(layers, "dst16") else None
            parent = (e.nodes.get(A.normalize_ext(dst64)) if dst64 else None) or (
                e.nodes.get(e.rloc_index.get(dst16, "")) if dst16 is not None else None)
            e.on_attach_request(ts, sender, parent)

        if cmd == MLE_CHILD_ID_RESPONSE:
            addr16 = self._one(layers, "mle_addr16")
            dst64 = self._one(layers, "dst64")
            if addr16 and dst64:
                e.on_address_assignment(ts, A.normalize_ext(dst64), A.parse_rloc16(addr16))

        from_child = cmd in MLE_FROM_CHILD or (
            cmd == MLE_CHILD_UPDATE_RESPONSE and src16 is not None and A.is_valid_rloc16(src16)
            and not A.is_router_rloc(src16))  # the Source Address is a child's: the child answers its parent
        if from_child:
            timeout = self._int(self._one(layers, "mle_timeout"))
            if timeout is not None and cmd in (MLE_CHILD_ID_REQUEST, 13):  # the child announces its timeout
                e.on_child_timeout(ts, sender, timeout)
            if self._present(layers, "csl_timeout"):
                e.on_csl(ts, sender)
            supervision = self._int(self._one(layers, "mle_supervision"))
            if supervision is not None:
                e.on_supervision_interval(ts, sender, supervision)
            ftd = self._bool(self._one(layers, "mode_ftd"))
            idle = self._bool(self._one(layers, "mode_idle_rx"))
            if ftd is not None and idle is not None:
                e.on_mode(ts, sender, ftd, idle)
            addrs = self._all(layers, "reg_ipv6")
            # compressed entries: context 0 is the mesh-local prefix, the others come from the Network Data (OMR)
            for iid_hex, cid in zip(self._all(layers, "reg_iid"), self._all(layers, "reg_cid")):
                try:
                    cid_n = int(cid, 0)
                    prefix = e.ml_prefix if cid_n == 0 else e.contexts.get(cid_n)
                    if prefix is not None:
                        addrs.append(str(A.addr_from(prefix, int(iid_hex.replace(":", ""), 16))))
                except ValueError:
                    pass
            e.on_registered_addresses(ts, sender, addrs)

    def _contexts(self, layers: dict) -> None:
        """6LoWPAN contexts of the Network Data (the context ids devices use to compress their OMR addresses).
        A context is a sub-TLV of its /64 prefix; the flat field lists only line up if every /64 prefix has one."""
        prefixes, lengths = self._all(layers, "nwd_prefix"), self._all(layers, "nwd_prefix_len")
        cids = [self._int(c) for c in self._all(layers, "nwd_context_id")]
        if not cids or len(prefixes) != len(lengths) or None in cids:
            return
        wide = [p for p, n in zip(prefixes, lengths) if self._int(n) == 64]
        if len(wide) != len(cids):
            return  # cannot tell which prefix a context belongs to: rather none than a wrong one
        contexts = {}
        for text, cid in zip(wide, cids):
            addr = A.parse_ip(text if "::" in text or text.count(":") == 7 else text + "::")
            if addr is not None:
                contexts[cid] = A.prefix64(addr)
        if contexts:
            self.engine.on_contexts(contexts)

    def _route_entries(self, layers: dict, mask_text: str) -> list[tuple[int, int, int, int]]:
        try:
            mask = bytes.fromhex(mask_text.replace(":", ""))
        except ValueError:
            return []
        ids = [i for i in range(len(mask) * 8) if mask[i // 8] & (0x80 >> (i % 8))]
        ins = [self._int(v) for v in self._all(layers, "route_in")]
        outs = [self._int(v) for v in self._all(layers, "route_out")]
        costs = [self._int(v) for v in self._all(layers, "route_cost")]
        if not (len(ids) == len(ins) == len(outs) == len(costs)) or None in ins + outs + costs:
            return []  # cannot align entries with router IDs: ignore rather than guess
        return list(zip(ids, ins, outs, costs))
