"""Reads tests/fixtures/probe_real.txt: an anonymized transcript of a real diag-probe run."""
from pathlib import Path

PATH = Path(__file__).resolve().parent / "fixtures" / "probe_real.txt"


class Fixture:
    def __init__(self, path=PATH):
        self.runs: dict[str, list[dict]] = {}
        cur = None
        for raw in path.read_text().splitlines():
            if raw.startswith("$ "):
                cur = {"out": [], "error": None}
                self.runs.setdefault(raw[2:], []).append(cur)
            elif raw.startswith("  ! ") and cur is not None:
                cur["error"] = raw[4:]
            elif raw.startswith("  ") and cur is not None:
                cur["out"].append(raw[2:])      # what the device printed, without the transcript's indent
            else:
                cur = None                      # a "# ..." comment line ends the output

    def lines(self, command: str, nth: int = 0) -> list[str]:
        return self.runs[command][nth]["out"]

    def error(self, command: str, nth: int = 0) -> str | None:
        return self.runs[command][nth]["error"]
