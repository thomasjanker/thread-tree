"""Parse a Thread Active Operational Dataset given as hex TLVs
(as copied from the IKEA app, `ot-ctl dataset active -x`, Apple/Google tools)."""

from __future__ import annotations

from dataclasses import dataclass

from .addresses import prefix_str

_CHANNEL, _PANID, _EXTPANID, _NAME, _PSKC, _KEY, _KEYSEQ, _MLPREFIX = 0, 1, 2, 3, 4, 5, 6, 7


@dataclass
class Dataset:
    network_key: str | None = None  # 32 hex chars; secret!
    channel: int | None = None
    pan_id: int | None = None
    ext_pan_id: str | None = None
    network_name: str | None = None
    mesh_local_prefix: int | None = None  # upper 64 bits as integer

    @property
    def mesh_local_prefix_str(self) -> str | None:
        return None if self.mesh_local_prefix is None else prefix_str(self.mesh_local_prefix)


def normalize_hex(hex_tlvs: str) -> str:
    """Hex TLVs without spaces and colons, lower case: the form `dataset set active` takes."""
    return "".join(hex_tlvs.split()).replace(":", "").lower()


def parse_dataset(hex_tlvs: str) -> Dataset:
    raw = bytes.fromhex(normalize_hex(hex_tlvs))
    ds = Dataset()
    pos = 0
    while pos + 2 <= len(raw):
        t, n = raw[pos], raw[pos + 1]
        pos += 2
        if n == 0xFF:  # extended length
            if pos + 2 > len(raw):
                raise ValueError("truncated dataset")
            n = int.from_bytes(raw[pos : pos + 2], "big")
            pos += 2
        value = raw[pos : pos + n]
        if len(value) != n:
            raise ValueError("truncated dataset")
        pos += n
        if t == _CHANNEL and n == 3:
            ds.channel = int.from_bytes(value[1:3], "big")
        elif t == _PANID and n == 2:
            ds.pan_id = int.from_bytes(value, "big")
        elif t == _EXTPANID and n == 8:
            ds.ext_pan_id = value.hex()
        elif t == _NAME:
            ds.network_name = value.decode("utf-8", "replace")
        elif t == _KEY and n == 16:
            ds.network_key = value.hex()
        elif t == _MLPREFIX and n == 8:
            ds.mesh_local_prefix = int.from_bytes(value, "big")
    return ds
