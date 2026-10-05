"""Find the nRF52840 sticks by their USB identity (Linux sysfs), so nobody has to know which ttyACM is which.

- sniffer: Nordic's nRF Sniffer for 802.15.4 firmware, USB 1915:154b ("nRF 802154 Sniffer")
- diagnostic node: OpenThread CLI firmware, USB 1915:cafe ("nRF528xx OpenThread Device")

A stable /dev/serial/by-id name is preferred when there is one (ttyACM numbers can swap after a reboot).
"""

from __future__ import annotations

import os
from pathlib import Path

NORDIC = "1915"
SNIFFER_PIDS = {"154b"}
DIAG_PIDS = {"cafe"}


def _usb_attrs(device: Path) -> dict[str, str]:
    """idVendor / idProduct / product of the USB device a tty belongs to (a few levels up in sysfs)."""
    cur = device
    for _ in range(5):
        if (cur / "idVendor").is_file():
            out = {}
            for name in ("idVendor", "idProduct", "product", "serial"):
                try:
                    out[name] = (cur / name).read_text().strip().lower() if name != "product" else (cur / name).read_text().strip()
                except OSError:
                    pass
            return out
        cur = cur.parent
    return {}


def classify(attrs: dict[str, str]) -> str | None:
    vendor, product_id, product = attrs.get("idVendor"), attrs.get("idProduct"), attrs.get("product", "").lower()
    if vendor == NORDIC and product_id in SNIFFER_PIDS or "802154 sniffer" in product:
        return "sniffer"
    if vendor == NORDIC and product_id in DIAG_PIDS or "openthread" in product:
        return "diag"
    return None


def find_sticks(sys_root: str | Path = "/sys", dev_root: str | Path = "/dev") -> list[dict]:
    """Every USB serial device: {"kind": "sniffer" | "diag" | None, "path", "tty", "product", "usb"}."""
    sys_root, dev_root = Path(sys_root), Path(dev_root)
    by_id: dict[str, str] = {}
    by_id_dir = dev_root / "serial" / "by-id"
    if by_id_dir.is_dir():
        for link in sorted(by_id_dir.iterdir()):
            by_id.setdefault(os.path.basename(os.path.realpath(link)), str(link))
    out = []
    tty_dir = sys_root / "class" / "tty"
    if not tty_dir.is_dir():
        return out
    for entry in sorted(tty_dir.iterdir()):
        if not entry.name.startswith(("ttyACM", "ttyUSB")):
            continue
        attrs = _usb_attrs(Path(os.path.realpath(entry / "device")))
        out.append({"kind": classify(attrs), "tty": str(dev_root / entry.name),
                    "path": by_id.get(entry.name, str(dev_root / entry.name)), "product": attrs.get("product"),
                    "usb": f"{attrs.get('idVendor', '?')}:{attrs.get('idProduct', '?')}"})
    return out


def find(kind: str, **roots) -> str | None:
    """Path of the first stick of this kind, or None."""
    return next((s["path"] for s in find_sticks(**roots) if s["kind"] == kind), None)
