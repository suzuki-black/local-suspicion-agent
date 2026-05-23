"""Unit tests for scripts/eval.py metric logic (Issue #9)."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from scripts import eval as ev  # noqa: E402

EVAL_CLI = REPO_ROOT / "scripts" / "eval.py"


def _case(category: str, label_expected: str, smin: int, smax: int, cid: str = "x"):
    return {
        "id": cid,
        "category": category,
        "subcategory": "delivery_sms" if category == "phishing" else "casual_chat",
        "input": "x",
        "expected": {
            "score_min": smin,
            "score_max": smax,
            "label": label_expected,
        },
        "must_contain_reason_keywords": None,
        "must_not_contain_reason_keywords": None,
        "notes": "",
        "source": "claude",
        "added_at": "2026-05-22",
        "schema_version": 1,
    }


class PassLogicTest(unittest.TestCase):
    def test_phishing_pass(self) -> None:
        case = _case("phishing", "phishing", 60, 100)
        passed, fails = ev._check_pass(
            case, {"score": 85, "label": "phishing", "reasons": ["URL"]}
        )
        self.assertTrue(passed)
        self.assertEqual(fails, [])

    def test_phishing_score_out_of_range(self) -> None:
        case = _case("phishing", "phishing", 60, 100)
        passed, fails = ev._check_pass(
            case, {"score": 10, "label": "phishing", "reasons": []}
        )
        self.assertFalse(passed)
        self.assertTrue(any("outside" in f for f in fails))

    def test_phishing_label_mismatch(self) -> None:
        case = _case("phishing", "phishing", 60, 100)
        passed, fails = ev._check_pass(
            case, {"score": 80, "label": "fraud", "reasons": []}
        )
        self.assertFalse(passed)
        self.assertTrue(any("label" in f for f in fails))

    def test_legit_but_suspicious_passes_with_other_label(self) -> None:
        case = _case("legit_but_suspicious", "harmless", 0, 50)
        passed, _ = ev._check_pass(
            case, {"score": 30, "label": "other", "reasons": ["unusual pattern"]}
        )
        self.assertTrue(passed)  # any non-attack label OK

    def test_legit_but_suspicious_fails_on_attack_label(self) -> None:
        case = _case("legit_but_suspicious", "harmless", 0, 50)
        passed, fails = ev._check_pass(
            case, {"score": 30, "label": "phishing", "reasons": []}
        )
        self.assertFalse(passed)
        self.assertTrue(any("FP" in f for f in fails))

    def test_must_contain_enforced(self) -> None:
        case = _case("phishing", "phishing", 60, 100)
        case["must_contain_reason_keywords"] = ["URL"]
        passed, fails = ev._check_pass(
            case, {"score": 80, "label": "phishing", "reasons": ["something else"]}
        )
        self.assertFalse(passed)
        self.assertTrue(any("missing" in f for f in fails))

    def test_must_not_contain_enforced(self) -> None:
        case = _case("harmless", "harmless", 0, 20)
        case["must_not_contain_reason_keywords"] = ["金銭"]
        passed, fails = ev._check_pass(
            case, {"score": 5, "label": "harmless", "reasons": ["金銭の話"]}
        )
        self.assertFalse(passed)


class MetricsTest(unittest.TestCase):
    def test_hand_computed_fixture(self) -> None:
        # 6 cases hand-rolled:
        # phishing-1 PASS (label=phishing) -> TP
        # phishing-2 FAIL (label=harmless) -> FN
        # harmless-1 PASS (label=harmless)
        # harmless-2 FAIL (label=phishing) -> FP
        # legit-1 PASS (label=other, score=20)
        # legit-2 FAIL (label=fraud) -> FP
        results = [
            {"case": _case("phishing", "phishing", 60, 100, "p1"),
             "decision": {"score": 80, "label": "phishing", "reasons": []},
             "pass": True},
            {"case": _case("phishing", "phishing", 60, 100, "p2"),
             "decision": {"score": 10, "label": "harmless", "reasons": []},
             "pass": False},
            {"case": _case("harmless", "harmless", 0, 20, "h1"),
             "decision": {"score": 5, "label": "harmless", "reasons": []},
             "pass": True},
            {"case": _case("harmless", "harmless", 0, 20, "h2"),
             "decision": {"score": 5, "label": "phishing", "reasons": []},
             "pass": False},
            {"case": _case("legit_but_suspicious", "harmless", 0, 50, "l1"),
             "decision": {"score": 20, "label": "other", "reasons": []},
             "pass": True},
            {"case": _case("legit_but_suspicious", "harmless", 0, 50, "l2"),
             "decision": {"score": 30, "label": "fraud", "reasons": []},
             "pass": False},
        ]
        m = ev._compute_metrics(results)

        # Overall: TP=1, FP=2, FN=1
        self.assertEqual(m["overall"]["tp_count"], 1)
        self.assertEqual(m["overall"]["fp_count"], 2)
        self.assertEqual(m["overall"]["fn_count"], 1)
        # precision = 1/(1+2) = 0.333
        self.assertAlmostEqual(m["overall"]["precision"], 1 / 3, places=3)
        # recall = 1/(1+1) = 0.5
        self.assertAlmostEqual(m["overall"]["recall"], 0.5, places=3)
        # fp_rate over (harmless+legit) = 2/4 = 0.5
        self.assertAlmostEqual(m["overall"]["fp_rate"], 0.5, places=3)
        # phishing recall = 1/(1+1) = 0.5
        self.assertAlmostEqual(m["by_category"]["phishing"]["recall"], 0.5, places=3)


class CliTest(unittest.TestCase):
    def test_validate_subcommand_via_cli(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as f:
            f.write(json.dumps(_case("phishing", "phishing", 60, 100, "x"), ensure_ascii=False) + "\n")
            path = f.name
        try:
            proc = subprocess.run(
                [sys.executable, str(EVAL_CLI), "validate", "--cases", path],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
        finally:
            Path(path).unlink()


if __name__ == "__main__":
    unittest.main()
