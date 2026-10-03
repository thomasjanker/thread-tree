"""Is a node online? Shared by the topology snapshot, the event log and the diagnostics."""

from __future__ import annotations

# Seconds without a frame before a node counts as offline, by role.
OFFLINE_AFTER = {"leader": 900, "router": 900, "med": 3600, "fed": 3600, "sed": 6 * 3600,
                 "child": 6 * 3600, "unknown": 6 * 3600}


def presence(last_heard: float, last_seen: float, last_addressed: float, role: str,
             now: float, last_diag: float = 0.0, diag_ttl: float = 0.0, limit: float | None = None) -> tuple[bool, bool]:
    """(online, online_indirect). A device that was ever heard is judged only by its own activity (frames the
    sniffer heard, or an answer in an active diagnostic). A device never heard directly but vouched for by the
    network itself (a diagnostic answer, or its parent's child table) is online. One that is only known from other
    nodes' frames counts as online (indirect) while they keep sending to it."""
    limit = OFFLINE_AFTER.get(role, 3600) if limit is None else limit  # limit: what the device's own rhythm allows
    alive = max(last_seen, last_diag)
    if last_heard > 0:
        return now - alive <= limit, False
    if last_diag > 0 and now - last_diag <= max(limit, diag_ttl):  # rounds can be further apart than the limit
        return True, False
    indirect = now - max(alive, last_addressed) <= limit
    return indirect, indirect
