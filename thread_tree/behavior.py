"""Behaviour of a device over time, as the sniffer hears it: how regularly a sleepy device asks its parent for data
(MAC data requests), gaps in that rhythm, and searches for a new parent (MLE Parent Request).

Thread requires a sleepy end device to contact its parent within its child timeout, or the parent drops it; a
device that searches for a parent while it has one has lost the link to it. Both are what makes a battery device
"stop working" for a while. Everything is measured at the sniffer: a frame it did not receive looks like a frame
that was not sent, so gaps only count while the sniffer kept receiving other frames, and a single short gap is a
note, not a warning.
"""

from __future__ import annotations

from statistics import median

INTERVALS_KEPT = 30          # recent poll intervals that define the usual rhythm
INTERVALS_NEEDED = 5         # ... and how many it takes before gaps are judged
INTERVAL_MIN = 0.5           # s: shorter is a burst (fast polling after sending), not the rhythm
INTERVAL_MAX = 3600.0        # s: longer is a gap, never part of the rhythm
GAP_FACTOR = 4.0             # a gap: at least this many usual intervals ...
GAP_MIN_EXTRA = 30.0         # ... and at least this much longer than one
SEARCH_EPISODE = 120.0       # s: Parent Requests closer together than this belong to one search
SNIFFER_OUTAGE = 60.0        # s without any frame at all: the sniffer (not the device) was silent
OUTAGES_KEPT = 200


def usual_interval(behavior: dict) -> float | None:
    intervals = behavior.get("intervals") or []
    return median(intervals) if len(intervals) >= INTERVALS_NEEDED else None


def gap_threshold(usual: float) -> float:
    return max(GAP_FACTOR * usual, usual + GAP_MIN_EXTRA)


def on_poll(behavior: dict, ts: float, sniffer_was_down) -> dict | None:
    """A data poll (not a retransmission). Returns the gap that just ended, if this poll ended one."""
    last = behavior.get("last_poll")
    behavior["last_poll"] = max(ts, last or 0.0)
    if last is None or ts <= last:
        return None
    interval = ts - last
    usual = usual_interval(behavior)
    if usual is not None and interval >= gap_threshold(usual):
        if sniffer_was_down(last, ts):
            return None  # the sniffer heard nothing at all for a while: no evidence against the device
        return {"seconds": round(interval), "usual": round(usual, 1)}
    if INTERVAL_MIN <= interval <= INTERVAL_MAX:
        intervals = behavior.setdefault("intervals", [])
        intervals.append(round(interval, 2))
        del intervals[:-INTERVALS_KEPT]
    return None


def on_parent_request(behavior: dict, ts: float) -> bool:
    """A Parent Request of this device. True if it starts a new search (the rest of the search is the same one)."""
    search = behavior.get("search")
    if search and ts - search["last"] <= SEARCH_EPISODE:
        search["last"] = max(search["last"], ts)
        search["count"] += 1
        return False
    behavior["search"] = {"start": ts, "last": ts, "count": 1}
    return True


def on_attach_request(behavior: dict, ts: float) -> dict | None:
    """A Child ID Request: the device chose a parent. Ends a search; returns how long it took."""
    search = behavior.pop("search", None)
    if not search or ts - search["last"] > SEARCH_EPISODE:
        return None
    return {"seconds": round(max(0.0, ts - search["start"])), "requests": search["count"]}


def silence(behavior: dict, last_frame: float | None) -> dict | None:
    """The device has not polled for longer than a gap, while the sniffer still hears others (last_frame)."""
    usual, last = usual_interval(behavior), behavior.get("last_poll")
    if usual is None or last is None or last_frame is None:
        return None
    quiet = last_frame - last
    return {"seconds": round(quiet), "usual": round(usual, 1)} if quiet >= gap_threshold(usual) else None
