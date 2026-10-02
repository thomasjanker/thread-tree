"""Tests for web/search.js. Runs the file with gjs (GNOME's JavaScript shell) if it is installed."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

SEARCH_JS = Path(__file__).resolve().parent.parent / "thread_tree" / "web" / "search.js"

HARNESS = r"""
const {GLib} = imports.gi;
const [ok, bytes] = GLib.file_get_contents(ARGV[0]);
const lib = new Function(new TextDecoder().decode(bytes) +
  '; return {hexOnly, ipv6Hex, macToIid, matchesQuery};')();
const cases = JSON.parse(ARGV[1]);
const out = cases.map(([fn, ...args]) => lib[fn](...args));
print(JSON.stringify(out));
"""


def run(cases):
    res = subprocess.run(["gjs", "-c", HARNESS, str(SEARCH_JS), json.dumps(cases)],
                         capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


@unittest.skipUnless(shutil.which("gjs"), "gjs not installed")
class SearchJsTests(unittest.TestCase):
    def test_ipv6_normalisation(self):
        expect = "fe80" + "0000" * 3 + "df99" + "0ab1" + "dd7d" + "6358"
        got = run([["ipv6Hex", "fe80::df99:ab1:dd7d:6358"], ["ipv6Hex", "FE80:0:0:0:DF99:0AB1:DD7D:6358"],
                   ["ipv6Hex", "[fe80::df99:ab1:dd7d:6358%eth0]"], ["ipv6Hex", "::1"], ["ipv6Hex", "1::"],
                   ["ipv6Hex", "1::2::3"], ["ipv6Hex", "zz"], ["ipv6Hex", "1:2:3"], ["ipv6Hex", "192.168.7.12"]])
        self.assertEqual(got[0], expect)
        self.assertEqual(got[1], expect)
        self.assertEqual(got[2], expect)
        self.assertEqual(got[3], "0" * 31 + "1")
        self.assertEqual(got[4], "0001" + "0" * 28)
        self.assertEqual(got[5:], [None] * 4)

    def test_mac_to_modified_eui64(self):
        self.assertEqual(run([["macToIid", "68ec8a010c24"]])[0], "6aec8afffe010c24")  # Home Assistant example

    def test_matching(self):
        eth_node = {"ext": None, "addresses": [{"addr": "fdd6:ac3f:f30:4fad:6aec:8aff:fe01:c24"}]}
        thread_node = {"ext": "8ab4bd1a4c188cf1", "addresses": [{"addr": "fe80::88b4:bd1a:4c18:8cf1"}]}
        cases = [
            ["matchesQuery", eth_node, "68:EC:8A:01:0C:24", ""],        # 48-bit MAC -> SLAAC address on the node
            ["matchesQuery", eth_node, "68-ec-8a-01-0c-25", ""],        # different MAC
            ["matchesQuery", eth_node, "FDD6:AC3F:0F30:4FAD:6AEC:8AFF:FE01:0C24", ""],  # same address, other notation
            ["matchesQuery", thread_node, "8a-b4-bd-1a-4c-18-8c-f1", ""],  # EUI-64 with dashes
            ["matchesQuery", thread_node, "8ab4bd1a4c188cf1", ""],
            ["matchesQuery", thread_node, "8A:B4:BD:1A:4C:18:8C:F2", ""],
            ["matchesQuery", thread_node, "", ""],                        # empty query matches everything
            ["matchesQuery", thread_node, "wohnzimmer", "sensor wohnzimmer"],  # plain text search still works
            ["matchesQuery", thread_node, "keller", "sensor wohnzimmer"],
            ["matchesQuery", thread_node, "fe80::88b4:bd1a:4c18:8cf1", ""],
        ]
        self.assertEqual(run(cases), [True, False, True, True, True, False, True, True, False, True])


if __name__ == "__main__":
    unittest.main()
