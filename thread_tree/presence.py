"""Is a node online? Shared by the topology snapshot, the event log and the diagnostics."""

from __future__ import annotations

# Seconds without a frame before a node counts as offline, by role.
OFFLINE_AFTER = {"leader": 900, "router": 900, "med": 3600, "fed": 3600, "sed": 6 * 3600,
                 "child": 6 * 3600, "unknown": 6 * 3600}


def presence(last_heard: float, last_seen: float, last_addressed: float, role: str,
             now: float) -> tuple[bool, bool]:
    """(online, online_indirect). A device that was ever heard is judged only by its own activity. A
    device never heard directly counts as online (indirect) while other nodes keep sending frames to it."""
    limit = OFFLINE_AFTER.get(role, 3600)
    if last_heard > 0:
        return now - last_seen <= limit, False
    indirect = now - max(last_seen, last_addressed) <= limit
    return indirect, indirect
