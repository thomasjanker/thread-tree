"""A device the sniffer does not hear, kept alive by the active diagnostics: no offline/online flapping per round."""
import unittest

from thread_tree.engine import Engine
from thread_tree.otdiag import Child

T = 1_800_000_000.0
ROUTER, CHILD = "aa" * 8, "cc" * 8


def run(seconds, child_answers):
    """Every 300 s a round; child_answers(k) -> the age the parent reports, or None when the child is not listed."""
    e = Engine()
    e.diag_ttl, e.diag_interval = 900.0, 300.0
    r = e.on_frame(T, ROUTER, 0x1400)
    e.on_leader_data(T, r, 7, 5)
    c = e.on_frame(T, CHILD, 0x1401)  # heard once
    c.child_timeout = 120              # short timeout: the offline limit is the minimum, 300 s
    for k in range(0, seconds, 3):
        now = T + k
        e.on_frame(now, ROUTER, 0x1400)  # the sniffer keeps hearing the network
        age = child_answers(k) if k and k % 300 == 0 else None
        if age is not None:
            e.on_diag_childtable(now, [Child(rloc16=0x1401, ext=CHILD, age=age, timeout=120)])
        e.tick(now)
    return [(round(ev["ts"] - T), ev["kind"]) for ev in e.nodes[CHILD].events if ev["kind"] in ("online", "offline")]


class DiagnosticPresenceTests(unittest.TestCase):
    def test_no_flapping_between_rounds(self):
        self.assertEqual(run(3600, lambda k: 80), [])

    def test_a_device_that_is_gone_still_goes_offline(self):
        # the parent last heard it at 1200 - 80 s; after that it no longer lists it
        events = run(3600, lambda k: 80 if k <= 1200 else None)
        self.assertEqual(events, [(1120 + 300 + 300, "offline")])  # limit plus one round after its parent last heard it
