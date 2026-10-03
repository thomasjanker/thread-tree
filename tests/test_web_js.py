"""The pure JavaScript helpers (format.js, charts.js geometry), run with gjs if it is installed."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "thread_tree" / "web"
NAMES = ("fmtDuration, fmtBytes, fmtPct, fmtDbm, fmtDb, fmtPercentValue, fmtThreadVersion, fmtCost, fillTemplate, "
         "niceMax, scaleLinear, hourTicks, rssiRange")

HARNESS = r"""
const {GLib} = imports.gi;
const read = f => new TextDecoder().decode(GLib.file_get_contents(ARGV[0] + '/' + f)[1]);
const lib = new Function(read('format.js') + read('charts.js') + '; return {%s};')();
const out = JSON.parse(ARGV[1]).map(([fn, ...args]) => {
  if (fn === 'scale') { const f = lib.scaleLinear(...args.slice(0, 4)); return args.slice(4).map(f); }
  if (fn === 'template') return lib.fillTemplate(args[0], args[1], (k, v) => String(v));
  return lib[fn](...args);
});
print(JSON.stringify(out));
""" % NAMES


def run(cases):
    res = subprocess.run(["gjs", "-c", HARNESS, str(WEB), json.dumps(cases)], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


@unittest.skipUnless(shutil.which("gjs"), "gjs not installed")
class FormatTests(unittest.TestCase):
    def test_duration(self):
        got = run([["fmtDuration", v] for v in (0, 59, 60, 90, 600, 3599, 5400, 7200, 172800, None)])
        self.assertEqual(got, ["0 s", "59 s", "1 min", "1.5 min", "10 min", "60 min", "1.5 h", "2 h", "2 d", "–"])

    def test_bytes_percent_dbm(self):
        got = run([["fmtBytes", 500], ["fmtBytes", 1536], ["fmtBytes", 1048576], ["fmtBytes", None],
                   ["fmtPct", 0.153], ["fmtPct", 0.153, 1], ["fmtPct", None], ["fmtDbm", -70.4], ["fmtDbm", None]])
        self.assertEqual(got, ["500 B", "1.5 KB", "1 MB", "–", "15 %", "15.3 %", "–", "-70 dBm", "–"])

    def test_measurements_of_the_routers(self):
        got = run([["fmtDb", 27.4], ["fmtDb", None], ["fmtPercentValue", 0], ["fmtPercentValue", 0.69], ["fmtPercentValue", 3.29],
                   ["fmtPercentValue", 9.96], ["fmtPercentValue", 25.45], ["fmtPercentValue", 53.93], ["fmtPercentValue", 0.04],
                   ["fmtPercentValue", None]])
        self.assertEqual(got, ["27 dB", "–", "0 %", "0.7 %", "3.3 %", "10 %", "25 %", "54 %", "0 %", "–"])

    def test_route_cost_may_be_unknown(self):
        self.assertEqual(run([["fmtCost", 1], ["fmtCost", 0], ["fmtCost", None]]), ["1", "0", "–"])

    def test_thread_versions(self):
        got = run([["fmtThreadVersion", v] for v in (3, 4, 5, 6, None)])
        self.assertEqual(got, ["1.2", "1.3", "1.4", "v6", "–"])

    def test_templates_and_plurals(self):
        got = run([
            ["template", "{a} of {b}", {"a": 1, "b": 2}],
            ["template", "{a} and {missing}", {"a": 1}],
            ["template", "{n:device|devices}", {"n": 1}],
            ["template", "{n:device|devices}", {"n": 0}],
            ["template", "{n:device is|devices are} attached", {"n": 3}],
            ["template", "{n:Gerät|Geräte}", {"n": 2}],
        ])
        self.assertEqual(got, ["1 of 2", "1 and {missing}", "1 device", "0 devices", "3 devices are attached", "2 Geräte"])


@unittest.skipUnless(shutil.which("gjs"), "gjs not installed")
class ChartGeometryTests(unittest.TestCase):
    def test_nice_max(self):
        got = run([["niceMax", v] for v in (0, -3, 0.3, 1, 2, 4.9, 5, 5.1, 7, 12, 140, 1000, 1001)])
        self.assertEqual(got, [1, 1, 0.5, 1, 2, 5, 5, 10, 10, 20, 200, 1000, 2000])

    def test_scale(self):
        got = run([["scale", 0, 10, 100, 0, 0, 5, 10], ["scale", 3, 3, 0, 100, 3]])
        self.assertEqual(got, [[100, 50, 0], [50]])  # a flat domain maps to the middle

    def test_rssi_range_follows_the_data(self):
        got = run([["rssiRange", v] for v in ([-100, -78], [-62, -60], [-90], [-45, -40], [-100, -30], [])])
        self.assertEqual(got, [
            {"lo": -100, "hi": -70, "step": 10},   # weak node: the lower part of the scale
            {"lo": -70, "hi": -40, "step": 10},    # a tight range grows to at least 30 dB
            {"lo": -100, "hi": -70, "step": 10},
            {"lo": -50, "hi": -20, "step": 10},    # strong node: grows up to the top of the scale
            {"lo": -100, "hi": -20, "step": 20},   # a wide range uses 20 dB grid lines
            {"lo": -100, "hi": -20, "step": 20},   # no data at all: the whole scale
        ])

    def test_hour_ticks_follow_the_local_time(self):
        start_utc_05 = 20 * 86400 + 5 * 3600
        ticks = run([["hourTicks", start_utc_05, 600, 144, 3, 0]])[0]
        self.assertEqual([t["label"] for t in ticks][:3], ["06:00", "09:00", "12:00"])
        self.assertEqual([t["i"] for t in ticks][:3], [6, 24, 42])
        self.assertEqual(len(ticks), 8)
        local = run([["hourTicks", start_utc_05, 600, 144, 3, -300]])[0]  # UTC-5: the first bucket is midnight
        self.assertEqual((local[0]["i"], local[0]["label"]), (0, "00:00"))
        east = run([["hourTicks", start_utc_05, 600, 144, 3, 570]])[0]    # UTC+9:30, a half-hour zone
        self.assertEqual([(t["i"], t["label"]) for t in east][:2], [(3, "15:00"), (21, "18:00")])  # 05:00 UTC = 14:30 local


if __name__ == "__main__":
    unittest.main()
