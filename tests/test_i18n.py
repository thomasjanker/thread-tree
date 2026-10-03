"""The UI texts: both languages complete and in step with what the server can produce."""
import ast
import json
import re
import unittest
from pathlib import Path

from thread_tree.diagnose import FINDING_CODES

I18N = Path(__file__).resolve().parent.parent / "thread_tree" / "web" / "i18n"
WEB = I18N.parent
PLACEHOLDER = r"\{(\w+)(?::[^|}]*\|[^}]*)?\}"  # {name} or {name:singular|plural}
EN, DE = (json.loads((I18N / f"{lang}.json").read_text(encoding="utf-8")) for lang in ("en", "de"))


class I18nTests(unittest.TestCase):
    def test_both_languages_have_the_same_keys(self):
        self.assertEqual(sorted(set(EN) ^ set(DE)), [])
        self.assertEqual(sorted(set(EN["abbr"]) ^ set(DE["abbr"])), [])

    def test_every_finding_has_title_text_and_hint(self):
        for lang, d in (("en", EN), ("de", DE)):
            for code in FINDING_CODES:
                for part in ("title", "text", "hint"):
                    self.assertTrue(d.get(f"finding.{code}.{part}"), f"{lang}: finding.{code}.{part}")

    def test_placeholders_match_between_languages(self):
        for key in EN:
            if isinstance(EN[key], str):
                self.assertEqual(sorted(re.findall(PLACEHOLDER, EN[key])), sorted(re.findall(PLACEHOLDER, DE[key])), key)

    def test_finding_placeholders_are_parameters_the_server_sends(self):
        """Every {name} in a finding text must be a parameter that diagnose.py passes for that finding."""
        tree = ast.parse((WEB.parent / "diagnose.py").read_text(encoding="utf-8"))
        sent: dict[str, set[str]] = {}
        for call in ast.walk(tree):
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "finding"
                    and call.args and isinstance(call.args[0], ast.Constant)):
                sent.setdefault(call.args[0].value, set()).update(k.arg for k in call.keywords)
        self.assertEqual(sorted(sent), sorted(FINDING_CODES))  # no code without a call, no call without a code
        for code in FINDING_CODES:
            for part in ("text", "hint"):
                for name in re.findall(PLACEHOLDER, EN[f"finding.{code}.{part}"]):
                    self.assertIn(name, sent[code], f"finding.{code}.{part} uses {{{name}}}, the server sends {sorted(sent[code])}")

    def test_every_translation_key_used_in_the_javascript_exists(self):
        used = set()
        for js in ("app.js", "diag.js", "charts.js"):
            used |= set(re.findall(r"""\bt\(\s*['"]([\w.\-]+)['"]""", (WEB / js).read_text(encoding="utf-8")))
        # a key ending in '.' is a prefix completed at run time (t('role.' + role)): some key must start with it
        missing = sorted(k for k in used if (not any(e.startswith(k) for e in EN) if k.endswith(".") else k not in EN))
        self.assertEqual(missing, [])

if __name__ == "__main__":
    unittest.main()
