"""IPv6 / EUI-64 / RLOC16 helpers for Thread."""

from __future__ import annotations

import ipaddress

_U64 = (1 << 64) - 1
_UL_BIT = 1 << 57  # universal/local bit of the first IID byte
_RLOC_IID_PREFIX = 0x000000FFFE00  # IID = 0000:00ff:fe00:<rloc16>


def parse_ip(text: str) -> ipaddress.IPv6Address | None:
    try:
        return ipaddress.IPv6Address(text.strip())
    except ValueError:
        return None


def normalize_ext(text: str) -> str | None:
    """'aa:bb:..' / '0xAABB..' / 'aabb..' -> 16 lowercase hex chars."""
    t = text.strip().lower().replace(":", "").replace("-", "")
    if t.startswith("0x"):
        t = t[2:]
    if len(t) != 16 or any(c not in "0123456789abcdef" for c in t):
        return None
    return t


def parse_rloc16(text: str | int) -> int | None:
    if isinstance(text, int):
        return text & 0xFFFF
    t = text.strip().lower().replace(":", "")
    try:
        value = int(t, 16)
    except ValueError:
        return None
    return value if 0 <= value <= 0xFFFF else None


def router_id(rloc16: int) -> int:
    return rloc16 >> 10


def child_id(rloc16: int) -> int:
    return rloc16 & 0x1FF  # 9 bits; bit 9 is reserved


def is_valid_rloc16(rloc16: int) -> bool:
    """Router IDs are 0-62; 0xfc00 and above are ALOCs, the invalid ID 63 and the 0xfffe/0xffff markers."""
    return 0 <= rloc16 < 0xFC00


def is_router_rloc(rloc16: int) -> bool:
    return child_id(rloc16) == 0


def parent_rloc16(rloc16: int) -> int:
    return rloc16 & 0xFC00


def prefix64(addr: ipaddress.IPv6Address) -> int:
    return int(addr) >> 64


def iid(addr: ipaddress.IPv6Address) -> int:
    return int(addr) & _U64


def prefix_str(prefix: int) -> str:
    return str(ipaddress.IPv6Address(prefix << 64)) + "/64"


def addr_from(prefix: int, iid_value: int) -> ipaddress.IPv6Address:
    return ipaddress.IPv6Address((prefix << 64) | iid_value)


def rloc_address(prefix: int, rloc16: int) -> ipaddress.IPv6Address:
    return addr_from(prefix, (_RLOC_IID_PREFIX << 16) | rloc16)


def is_rloc_iid(iid_value: int) -> bool:
    return (iid_value >> 16) == _RLOC_IID_PREFIX


def link_local_from_ext(ext: str) -> ipaddress.IPv6Address:
    return addr_from(0xFE80 << 48, int(ext, 16) ^ _UL_BIT)


def ext_from_link_local(addr: ipaddress.IPv6Address) -> str | None:
    if (int(addr) >> 118) != 0x3FA:  # fe80::/10
        return None
    return f"{iid(addr) ^ _UL_BIT:016x}"


def mac_from_link_local(text: str | None) -> str | None:
    """MAC address (EUI-64) behind a MAC-based link-local address; None for anything else."""
    addr = parse_ip(text) if text else None
    if addr is None or (int(addr) >> 118) != 0x3FA or is_rloc_iid(iid(addr)):
        return None
    return ext_from_link_local(addr)


# Address types, as reported to the UI
LINK_LOCAL = "link-local"
RLOC = "rloc"
ALOC = "aloc"
ML_EID = "ml-eid"
OMR = "omr"
UNCLASSIFIED = "unclassified"
MULTICAST = "multicast"


def classify(addr: ipaddress.IPv6Address, ml_prefix: int | None) -> str:
    if addr.is_multicast:
        return MULTICAST
    if (int(addr) >> 118) == 0x3FA:
        return LINK_LOCAL
    p, i = prefix64(addr), iid(addr)
    if ml_prefix is None or p == ml_prefix:
        if is_rloc_iid(i):
            return ALOC if (i & 0xFFFF) >= 0xFC00 else RLOC
        if ml_prefix is None:
            return UNCLASSIFIED
        return ML_EID
    return OMR
