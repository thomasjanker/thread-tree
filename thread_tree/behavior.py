"""Behaviour of a device over time, as the sniffer hears it: how regularly a sleepy device asks its parent for data
(MAC data requests), gaps in that rhythm, and searches for a new parent (MLE Parent Request).

Thread requires a sleepy end device to contact its parent within its child timeout, or the parent drops it; a
device that searches for a parent while it has one has lost the link to it. Both are what makes a battery device
"stop working" for a while. Everything is measured at the sniffer: a frame it did not receive looks like a frame
that was not sent, so gaps only count while the sniffer kept receiving other frames, and a single short gap is a
note, not a warning.
"""

from __future__ import annotations


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
    """The device's long poll period, not the median of its intervals. Sleepy devices poll fast for a while after
    sending and slowly otherwise; the slow period is the one a gap is judged against."""
    intervals = sorted(behavior.get("intervals") or [])
    if len(intervals) < INTERVALS_NEEDED:
        return None
    slow = [x for x in intervals if x >= 0.5 * intervals[-1]]
    if len(slow) >= 3:  # the slow polls between the bursts, however many fast ones there are
        return slow[len(slow) // 2]
    return intervals[int(0.8 * (len(intervals) - 1))]  # else the 80th percentile: a single long one does not dominate


def gap_threshold(usual: float, timeout: int | None = None) -> float:
    """Silence that counts as a gap: several long poll periods, but never more than the child timeout (beyond it
    the parent drops the device anyway)."""
    threshold = max(GAP_FACTOR * usual, usual + GAP_MIN_EXTRA)
    return min(threshold, float(timeout)) if timeout and timeout > usual else threshold


def on_poll(behavior: dict, ts: float, sniffer_was_down, timeout: int | None = None) -> dict | None:
    """A data poll (not a retransmission). Returns the gap that just ended, if this poll ended one. A CSL device
    (Thread 1.2 synchronized sleepy end device) does not poll in a rhythm: its gaps mean nothing."""
    last = behavior.get("last_poll")
    behavior["last_poll"] = max(ts, last or 0.0)
    if last is None or ts <= last:
        return None
    interval = ts - last
    usual = usual_interval(behavior)
    down = sniffer_was_down(last, ts)
    # every plausible interval shapes the rhythm, also one that looked like a gap: if it recurs it is the slow poll
    # period (a single one does not move the estimate); beyond the child timeout it is a breach, never the rhythm
    if INTERVAL_MIN <= interval <= INTERVAL_MAX and (not timeout or interval <= timeout) and not down:
        intervals = behavior.setdefault("intervals", [])
        intervals.append(round(interval, 2))
        del intervals[:-INTERVALS_KEPT]
    if usual is not None and interval >= gap_threshold(usual, timeout) and not behavior.get("csl") and not down:
        return {"seconds": round(interval), "usual": round(usual, 1)}
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


def silence(behavior: dict, last_frame: float | None, timeout: int | None = None) -> dict | None:
    """The device has not polled for longer than a gap, while the sniffer still hears others (last_frame)."""
    usual, last = usual_interval(behavior), behavior.get("last_poll")
    if usual is None or last is None or last_frame is None or behavior.get("csl"):
        return None
    quiet = last_frame - last
    return {"seconds": round(quiet), "usual": round(usual, 1)} if quiet >= gap_threshold(usual, timeout) else None


# ---- checks against the standard (all from the sniffer) --------------------------------------------------------

MARGIN_SLACK = 10            # dB: a parent this much worse than the best offer is a poor choice
ATTACH_ANSWER = 5.0          # s: a Child ID Request without a Child ID Response within this time was not answered ...
ATTACH_RETRY = 60.0          # ... if the device asks again within this time (later, the sniffer may just have missed it)
COUNTER_AHEAD = 1000         # OpenThread stores the frame counter this far ahead: a restart skips forward by up to that
COUNTER_JUMP_WITHIN = 120.0  # s: ... so a skip of that size in a short time means a restart
ADV_GAP = 100.0              # s without an advertisement of a router (Trickle sends at least every 32 s) ...
ADV_GAP_MAX = 900.0          # ... but longer means it was off (offline), not a timing fault
SUPERVISION_SLACK = 1.5      # a gap in the frames to a child longer than this many supervision intervals breaks it
NETDATA_LAG = 120.0          # s a router may advertise an older Network Data version than its partition


def serial_newer(a: int, b: int) -> bool:
    """a is newer than b (8-bit version numbers wrap around)."""
    return 0 < (a - b) % 256 < 128


def on_parent_response(behavior: dict, router: int, margin: int | None) -> None:
    """A router offered to become the parent (MLE Parent Response with its link margin) during a search."""
    search = behavior.get("search")
    if search is not None and margin is not None:
        search.setdefault("offers", {})[str(router)] = margin


def judge_choice(search: dict | None, chosen: int | None) -> dict | None:
    """The device chose `chosen`; was a clearly better offer ignored? (The device also weighs parent priority and
    connectivity, so only a big difference counts.)"""
    offers = (search or {}).get("offers") or {}
    if chosen is None or str(chosen) not in offers or len(offers) < 2:
        return None
    best = max(offers, key=offers.get)
    if offers[best] - offers[str(chosen)] >= MARGIN_SLACK:
        return {"chosen": chosen, "best": int(best), "chosen_margin": offers[str(chosen)], "best_margin": offers[best]}
    return None


def on_frame_counter(behavior: dict, ts: float, counter: int, key: int | None) -> dict | None:
    """MAC frame counter of a secured frame of this device. Returns a suspected restart."""
    last = behavior.get("fc")
    behavior["fc"] = [counter, key, ts]
    if not last or last[1] != key:
        return None  # first frame, or a key switch: every device starts counting again
    prev, _, prev_ts = last
    if counter < prev - 10:
        return {"how": "reset", "from": prev, "to": counter}
    if counter - prev >= COUNTER_AHEAD and ts - prev_ts <= COUNTER_JUMP_WITHIN:
        return {"how": "skip", "from": prev, "to": counter}
    return None


def on_advertisement(behavior: dict, ts: float, sniffer_was_down) -> dict | None:
    last = behavior.get("adv_last")
    behavior["adv_last"] = max(ts, last or 0.0)
    if last is not None and ADV_GAP <= ts - last < ADV_GAP_MAX and not sniffer_was_down(last, ts):
        return {"seconds": round(ts - last)}
    return None


def on_addressed(behavior: dict, ts: float, sniffer_was_down) -> dict | None:
    """A frame to this child (its parent's data, or a supervision message). Gap longer than its supervision interval?"""
    last, interval = behavior.get("to_last"), behavior.get("supervision")
    behavior["to_last"] = max(ts, last or 0.0)
    if last is None or not interval or ts - last < SUPERVISION_SLACK * interval or sniffer_was_down(last, ts):
        return None
    return {"seconds": round(ts - last), "interval": interval}
