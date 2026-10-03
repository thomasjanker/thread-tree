"""OtCli and the diag-probe against a simulated OpenThread CLI behind a pseudo terminal."""
import os
import pty
import re
import select
import threading
import time
import unittest

from thread_tree.diagprobe import redact, run_probe
from thread_tree.otcli import OtCli, OtCliError, OtCliTimeout

KEY = "00112233445566778899aabbccddeeff"
DATASET = "0e0800000000000100000003000011" + KEY + "0708fd00000000000001"

ROUTER_TABLE = [
    "| ID | RLOC16 | Next Hop | Path Cost | LQ In | LQ Out | Age | Extended MAC     | Link |",
    "+----+--------+----------+-----------+-------+--------+-----+------------------+------+",
    "|  0 | 0x0000 |       63 |         0 |     0 |      0 |   0 | 8aa57d2c603fe16c |    0 |",
    "|  5 | 0x1400 |        5 |         1 |     3 |      3 |  17 | 822f560ff1aba1de |    1 |",
]
HELP = ["childmax", "dataset", "eui64", "extaddr", "help", "ifconfig", "ipaddr", "leaderdata", "meshdiag",
        "neighbor", "netdata", "networkdiagnostic", "networkname", "panid", "parent", "rloc16", "router",
        "routereligible", "state", "thread", "version", "channel"]


class FakeCli(threading.Thread):
    """Answers like the OpenThread CLI: echo, output lines, 'Done' or 'Error', prompt."""

    def __init__(self, master: int, commands=HELP, joins_as="child", noisy=False):
        super().__init__(daemon=True)
        self.master, self.commands, self.joins_as, self.noisy = master, list(commands), joins_as, noisy
        self.received: list[str] = []
        self.state, self.polls = "disabled", 0
        self.router_eligible = True
        self._stop = threading.Event()

    def reply(self, cmd: str):
        head = cmd.split()[0]
        if head not in self.commands and cmd != "help":
            return ["Error 35: InvalidCommand"]
        if cmd == "help":
            return self.commands
        if cmd == "version":
            return ["OPENTHREAD/c34311f; NRF52840; Aug 28 2026 14:45:32"]
        if cmd == "state":
            if self.state == "detached" and self.joins_as != "detached":
                self.polls += 1
                if self.polls >= 2:  # attaches on the second poll
                    self.state = self.joins_as
            return [self.state]
        if cmd == "thread start":
            self.state, self.polls = "detached", 0
        elif cmd == "thread stop":
            self.state = "disabled"
        elif cmd == "routereligible disable":
            self.router_eligible = False
        elif cmd.startswith("dataset set active"):
            pass
        elif cmd in ("router table",):
            return ROUTER_TABLE
        elif cmd == "ipaddr rloc":
            return ["fdae:fba2:cf3f:f1d3:0:ff:fe00:5801"]
        elif cmd == "meshdiag topology":
            return ["id:00 rloc16:0x0000 ext-addr:8aa57d2c603fe16c ver:4 - leader",
                    "id:05 rloc16:0x1400 ext-addr:822f560ff1aba1de ver:4", "id:09 rloc16:0x2400 ext-addr:aabbccddeeff0011 ver:4"]
        elif cmd.startswith("meshdiag childtable"):
            return ["rloc16:0x1401 ext-addr:a4c138fffe100001 timeout:240"]
        elif cmd.startswith("networkdiagnostic get"):
            return ["Extended MAC Address: 822f560ff1aba1de"]
        elif cmd == "eui64":
            return ["a4c138fffe109999"]
        return []

    def run(self):
        buf = b""
        while not self._stop.is_set():
            ready, _, _ = select.select([self.master], [], [], 0.05)
            if not ready:
                continue
            try:
                buf += os.read(self.master, 4096)
            except OSError:
                return
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                cmd = raw.decode().strip()
                if not cmd:
                    continue
                self.received.append(cmd)
                lines = self.reply(cmd)
                text = f"{cmd}\r\n"                       # echo
                if self.noisy:
                    text += "[N] Mle-----------: Role detached -> child\r\n"  # log line in between
                for line in lines:
                    text += f"{line}\r\n"
                if not (lines and lines[0].startswith("Error")):
                    text += "Done\r\n"
                text += "> "
                os.write(self.master, text.encode())

    def stop(self):
        self._stop.set()


class Device:
    def __init__(self, **kw):
        self.master, self.slave = pty.openpty()
        self.port = os.ttyname(self.slave)
        self.fake = FakeCli(self.master, **kw)

    def __enter__(self):
        self.fake.start()
        self.cli = OtCli(self.port, timeout=2.0).open()
        return self

    def __exit__(self, *exc):
        self.cli.close()
        self.fake.stop()
        self.fake.join(timeout=2)
        os.close(self.master)
        os.close(self.slave)


def probe(device, dataset=DATASET, **kw):
    lines = []
    summary = run_probe(device.cli, dataset, emit=lines.append, poll_interval=0.01, attach_timeout=5.0,
                        long_timeout=2.0, **kw)
    return summary, "\n".join(lines)


class OtCliTests(unittest.TestCase):
    def test_output_without_echo_prompt_and_done(self):
        with Device() as d:
            self.assertEqual(d.cli.command("version"), ["OPENTHREAD/c34311f; NRF52840; Aug 28 2026 14:45:32"])
            self.assertEqual(d.cli.command("thread start"), [])

    def test_error_is_raised_with_code_and_message(self):
        with Device() as d:
            with self.assertRaises(OtCliError) as ctx:
                d.cli.command("bogus")
            self.assertEqual((ctx.exception.code, ctx.exception.message), (35, "InvalidCommand"))

    def test_timeout_when_the_device_stays_silent(self):
        with Device() as d:
            d.fake.stop()
            d.fake.join(timeout=2)
            started = time.monotonic()
            with self.assertRaises(OtCliTimeout):
                d.cli.command("state", timeout=0.4)
            self.assertLess(time.monotonic() - started, 2.0)

    def test_log_lines_are_ignored(self):
        with Device(noisy=True) as d:
            self.assertEqual(d.cli.command("eui64"), ["a4c138fffe109999"])

    def test_a_secret_never_appears_in_error_messages(self):
        with Device() as d:
            with self.assertRaises(OtCliError) as ctx:
                d.cli.command("bogus " + KEY, secret=True)             # the device answers 'Error 35'
            self.assertNotIn(KEY, str(ctx.exception))
            self.assertNotIn(KEY, ctx.exception.command)
            d.fake.stop()
            d.fake.join(timeout=2)
            with self.assertRaises(OtCliTimeout) as timed_out:
                d.cli.command("dataset set active " + KEY, timeout=0.3, secret=True)
            self.assertNotIn(KEY, str(timed_out.exception))
            with self.assertRaises(OtCliTimeout) as plain:               # without the flag the command is shown
                d.cli.command("state", timeout=0.3)
            self.assertIn("state", str(plain.exception))

    def test_commands_come_from_help(self):
        with Device(commands=["help", "state", "version"]) as d:
            self.assertEqual(d.cli.commands(), {"help", "state", "version"})


class ProbeTests(unittest.TestCase):
    def test_full_probe_with_meshdiag(self):
        with Device() as d:
            summary, text = probe(d)
            received = d.fake.received
        self.assertTrue(summary["joined"])
        self.assertEqual(summary["state"], "child")
        self.assertEqual(summary["routers"], [0x0000, 0x1400, 0x2400])
        self.assertTrue(all(summary["capabilities"][c] for c in ("meshdiag", "networkdiagnostic", "routereligible")))
        # the node must be an end device: router role off before the stack starts
        self.assertLess(received.index("routereligible disable"), received.index("thread start"))
        dataset_cmd = [c for c in received if c.startswith("dataset set active")][0]
        self.assertLess(received.index(dataset_cmd), received.index("thread start"))
        for rloc in ("0x0000", "0x1400", "0x2400"):
            self.assertIn(f"meshdiag childtable {rloc}", received)
            self.assertIn(f"meshdiag childip6 {rloc}", received)
            self.assertIn(f"meshdiag routerneighbortable {rloc}", received)
        self.assertIn("meshdiag topology ip6-addrs children", received)
        self.assertIn("# command meshdiag: yes", text)

    def test_transcript_never_contains_the_key_or_dataset(self):
        with Device() as d:
            _, text = probe(d)
        self.assertNotIn(KEY, text)
        self.assertNotIn(DATASET, text)
        self.assertIn("$ dataset set active <dataset>", text)

    def test_firmware_without_diagnostics_is_reported(self):
        plain = [c for c in HELP if c not in ("meshdiag", "networkdiagnostic")]
        with Device(commands=plain) as d:
            summary, text = probe(d)
        self.assertTrue(summary["joined"])
        self.assertFalse(summary["capabilities"]["meshdiag"])
        self.assertIn("NO DIAGNOSTIC COMMANDS", text)
        self.assertIn("# command meshdiag: NO", text)

    def test_meshdiag_firmware_also_asks_a_few_routers_for_vendor_data(self):
        with Device() as d:
            d.fake.reply_orig = d.fake.reply
            d.fake.reply = lambda cmd: (["fdae:fba2:cf3f:f1d3:0:ff:fe00:5801", "fe80:0:0:0:1:2:3:4"] if cmd == "ipaddr"
                                        else ["5801"] if cmd == "rloc16" else d.fake.reply_orig(cmd))
            summary, text = probe(d)
            received = d.fake.received
        self.assertIn("networkdiagnostic get fdae:fba2:cf3f:f1d3:0:ff:fe00:1400 23 24 25 26 27 28", received)
        self.assertIn("# --- vendor information (networkdiagnostic) ---", text)
        self.assertLessEqual(len([c for c in received if c.startswith("networkdiagnostic get")]), 4)  # a few, not all

    def test_mesh_prefix_comes_from_the_own_rloc_address(self):
        from thread_tree.diagprobe import _mesh_prefix
        lines = ["fdc2:f44c:29d0:1:c111:2068:82c7:a8b4", "fdae:fba2:cf3f:f1d3:0:ff:fe00:a804", "fe80:0:0:0:8cfb:728:fcee:b114"]
        self.assertEqual(_mesh_prefix(lines, 0xA804), 0xFDAEFBA2CF3FF1D3)
        self.assertIsNone(_mesh_prefix(lines, 0x1234))              # an RLOC of someone else
        self.assertIsNone(_mesh_prefix(["fe80::1"], None))
        self.assertIsNone(_mesh_prefix(None, None))

    def test_networkdiagnostic_only_firmware_queries_each_router_by_rloc_address(self):
        cmds = [c for c in HELP if c != "meshdiag"]
        with Device(commands=cmds) as d:
            summary, _ = probe(d)
            received = d.fake.received
        self.assertTrue(summary["joined"])
        self.assertIn("networkdiagnostic get fdae:fba2:cf3f:f1d3:0:ff:fe00:1400 0 1 2 8 16", received)
        self.assertIn("networkdiagnostic get fdae:fba2:cf3f:f1d3:0:ff:fe00:1400 23 24 25 26 27 28", received)

    def test_without_routereligible_the_probe_warns(self):
        with Device(commands=[c for c in HELP if c != "routereligible"]) as d:
            _, text = probe(d)
        self.assertIn("WARNING", text)

    def test_attaching_as_router_aborts_and_stops_the_stack(self):
        with Device(joins_as="router") as d:
            # a firmware that ignores 'routereligible disable' (stays eligible)
            original = d.fake.reply
            d.fake.reply = lambda cmd: [] if cmd == "routereligible disable" else original(cmd)
            summary, text = probe(d)
            received = d.fake.received
        self.assertFalse(summary["joined"])
        self.assertEqual(summary["state"], "router")
        self.assertIn("attached as router, not as end device", text)
        self.assertEqual(received[-1], "thread stop")
        self.assertNotIn("meshdiag topology", received)

    def test_no_join_probes_an_attached_node(self):
        with Device() as d:
            d.fake.state = "child"
            lines = []
            summary = run_probe(d.cli, None, join=False, emit=lines.append, long_timeout=2.0)
            received = d.fake.received
        self.assertTrue(summary["joined"])
        self.assertNotIn("thread start", received)
        self.assertFalse(any(c.startswith("dataset set active") for c in received))

    def test_join_without_dataset_is_refused(self):
        with Device() as d:
            with self.assertRaises(ValueError):
                run_probe(d.cli, None, emit=lambda _: None)

    def test_node_that_never_attaches(self):
        with Device() as d:
            d.fake.joins_as = "detached"  # stays detached
            summary, text = probe(d)
        self.assertFalse(summary["joined"])
        self.assertIn("did not attach", text)


class RedactTests(unittest.TestCase):
    def test_long_hex_runs_and_given_secrets_are_masked(self):
        self.assertEqual(redact("key " + KEY + " end"), "key <redacted> end")
        self.assertEqual(redact("abc123 secret456", ("secret456",)), "abc123 <redacted>")
        self.assertEqual(redact("ext 822f560ff1aba1de"), "ext 822f560ff1aba1de")  # a MAC address is not secret
        self.assertEqual(redact("fdae:fba2:cf3f:f1d3:0:ff:fe00:5801"), "fdae:fba2:cf3f:f1d3:0:ff:fe00:5801")


if __name__ == "__main__":
    unittest.main()
