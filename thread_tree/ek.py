"""Adapter: tshark `-T ek` packets -> Engine observations.

Field names come from the Wireshark display filter reference (mle, wpan,
thread_nwd, thread_address). They are resolved against `tshark -G fields` at
startup, so a field missing in the installed Wireshark version disables only
that feature instead of aborting tshark.
"""

from __future__ import annotations

import logging

from . import addresses as A
from .engine import Engine

log = logging.getLogger(__name__)

# logical name -> candidate Wireshark field names (first one that exists is used)
FIELDS: dict[str, list[str]] = {
    "src64": ["wpan.src64"],
    "src16": ["wpan.src16"],
    "dst64": ["wpan.dst64"],
    "mle_addr16": ["mle.tlv.addr16"],
    "mac_cmd": ["wpan.cmd"],
    "ip_src": ["ipv6.src"],
    "ip_dst": ["ipv6.dst"],
    "mle_cmd": ["mle.cmd"],
    "mle_no_key": ["mle.no_key"],
    "mle_decrypt_failed": ["mle.decrypt_failed"],
    "mle_mic_failed": ["mle.mic_check_failed"],
    "mle_src": ["mle.tlv.source_addr"],
    "partition": ["mle.tlv.leader_data.partition_id"],
    "leader_rid": ["mle.tlv.leader_data.router_id"],
    "route_mask": ["mle.tlv.route64.id_mask"],
    "route_cost": ["mle.tlv.route64.cost"],
    "route_in": ["mle.tlv.route64.nbr_in"],
    "route_out": ["mle.tlv.route64.nbr_out"],
    "mode_ftd": ["mle.tlv.mode.device_type"],
    "mode_idle_rx": ["mle.tlv.mode.idle_rx"],
    "reg_ipv6": ["mle.tlv.addr_reg_ipv6"],
    "reg_iid": ["mle.tlv.addr_reg_iid"],
    "reg_cid": ["mle.tlv.addr_reg_cid"],
    "nwd_prefix": ["thread_nwd.tlv.prefix"],
    "nwd_br16": ["thread_nwd.tlv.border_router.16"],
    "nwd_hr16": ["thread_nwd.tlv.has_route.br_16"],
    "addr_target": ["thread_address.tlv.target_eid", "thread_address.target_eid"],
    "addr_rloc": ["thread_address.tlv.rloc16", "thread_address.rloc16"],
}

# MLE command IDs (Thread spec 4.5)
MLE_ADVERTISEMENT = 4
MLE_CHILD_ID_RESPONSE = 12  # parent -> child: carries the assigned Address16
MLE_FROM_CHILD = (9, 11, 13)  # Parent Request, Child ID Request, Child Update Request
MAC_DATA_REQUEST = 4


def resolve_fields(available: set[str]) -> dict[str, str]:
    """Pick one existing Wireshark field per logical name; log what is missing."""
    chosen: dict[str, str] = {}
    for logical, names in FIELDS.items():
        for name in names:
            if name in available:
                chosen[logical] = name
                break
        else:
            log.warning("Wireshark field for %r not available (%s): feature disabled", logical, names[0])
    return chosen


class Handler:
    def __init__(self, engine: Engine, fields: dict[str, str]):
        self.engine = engine
        self.fields = fields
        # MLE messages seen, and how many could / could not be decrypted
        self.stats = {"frames": 0, "mle_ok": 0, "mle_failed": 0}

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
        dst64 = self._one(layers, "dst64")
        dst_ext = A.normalize_ext(dst64) if dst64 else None
        e.on_destination(ts, dst_ext)

        if self._int(self._one(layers, "mac_cmd")) == MAC_DATA_REQUEST:
            e.on_data_poll(ts, sender)
        e.on_ip(ts, sender, self._one(layers, "ip_src"), self._one(layers, "ip_dst"))

        mle_cmd = self._int(self._one(layers, "mle_cmd"))
        if any(self._present(layers, k) for k in ("mle_no_key", "mle_decrypt_failed", "mle_mic_failed")):
            self.stats["mle_failed"] += 1
        elif mle_cmd is not None:
            self.stats["mle_ok"] += 1
        if mle_cmd is not None:
            self._handle_mle(ts, layers, sender, src16, mle_cmd)

        targets, rlocs = self._all(layers, "addr_target"), self._all(layers, "addr_rloc")
        if len(targets) == 1 and len(rlocs) == 1:  # Address Notification
            rloc16 = A.parse_rloc16(rlocs[0]) if rlocs[0].lower().startswith("0x") else self._int(rlocs[0], 10)
            if rloc16 is not None:
                e.on_address_notification(ts, targets[0], rloc16)

        if self._all(layers, "nwd_prefix"):  # complete Network Data with prefixes
            brs = {self._int(v) for v in self._all(layers, "nwd_br16") + self._all(layers, "nwd_hr16")}
            e.on_network_data(ts, {v for v in brs if v is not None})

    def _handle_mle(self, ts: float, layers: dict, sender, src16: int | None, cmd: int) -> None:
        e = self.engine
        pid = self._int(self._one(layers, "partition"))
        lrid = self._int(self._one(layers, "leader_rid"))
        if pid is not None and lrid is not None:
            e.on_leader_data(ts, sender, pid, lrid)

        mask = self._one(layers, "route_mask")
        if mask and src16 is not None:
            entries = self._route_entries(layers, mask)
            if entries:
                e.on_route64(ts, src16, entries)

        if cmd == MLE_CHILD_ID_RESPONSE:
            addr16 = self._one(layers, "mle_addr16")
            dst64 = self._one(layers, "dst64")
            if addr16 and dst64:
                e.on_address_assignment(ts, A.normalize_ext(dst64), A.parse_rloc16(addr16))

        if cmd in MLE_FROM_CHILD:
            ftd = self._bool(self._one(layers, "mode_ftd"))
            idle = self._bool(self._one(layers, "mode_idle_rx"))
            if ftd is not None and idle is not None:
                e.on_mode(ts, sender, ftd, idle)
            addrs = self._all(layers, "reg_ipv6")
            ml = e.ml_prefix
            if ml is not None:  # context 0 is the mesh-local prefix
                for iid_hex, cid in zip(self._all(layers, "reg_iid"), self._all(layers, "reg_cid")):
                    try:
                        if int(cid, 0) == 0:
                            addrs.append(str(A.addr_from(ml, int(iid_hex.replace(":", ""), 16))))
                    except ValueError:
                        pass
            e.on_registered_addresses(ts, sender, addrs)

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
