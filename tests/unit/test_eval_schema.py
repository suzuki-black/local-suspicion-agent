"""Unit tests for app/eval_schema.py and scripts/validate_cases.py (Issue #4)."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app.eval_schema import (
    SCHEMA_VERSION,
    TARGET_COUNTS,
    count_by_subcategory,
    count_diff_warnings,
    validate_record,
    validate_uniqueness,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "scripts" / "validate_cases.py"


def _valid_case(**overrides) -> dict:
    base = {
        "id": "phish-001",
        "category": "phishing",
        "subcategory": "delivery_sms",
        "input": "ヤマト不在通知サンプル http://example.example/r/1",
        "expected": {"score_min": 60, "score_max": 100, "label": "phishing"},
        "must_contain_reason_keywords": ["URL"],
        "must_not_contain_reason_keywords": None,
        "notes": "test",
        "source": "claude",
        "added_at": "2026-05-22",
        "schema_version": SCHEMA_VERSION,
    }
    base.update(overrides)
    return base


class ValidateRecordTest(unittest.TestCase):
    def test_valid_record_no_errors(self) -> None:
        self.assertEqual(validate_record(_valid_case()), [])

    def test_missing_required_field(self) -> None:
        rec = _valid_case()
        del rec["category"]
        errs = validate_record(rec)
        self.assertEqual(len(errs), 1)
        self.assertIn("category", errs[0].message)

    def test_invalid_category(self) -> None:
        errs = validate_record(_valid_case(category="bogus"))
        self.assertTrue(any("invalid category" in e.message for e in errs))

    def test_subcategory_must_belong_to_category(self) -> None:
        errs = validate_record(
            _valid_case(category="harmless", subcategory="delivery_sms")
        )
        self.assertTrue(any("subcategory" in e.message for e in errs))

    def test_score_range(self) -> None:
        rec = _valid_case()
        rec["expected"]["score_min"] = 90
        rec["expected"]["score_max"] = 50
        errs = validate_record(rec)
        self.assertTrue(any("score_min" in e.message for e in errs))

    def test_score_out_of_range(self) -> None:
        rec = _valid_case()
        rec["expected"]["score_min"] = -5
        errs = validate_record(rec)
        self.assertTrue(any("score_min" in e.message for e in errs))

    def test_invalid_label(self) -> None:
        rec = _valid_case()
        rec["expected"]["label"] = "bogus"
        errs = validate_record(rec)
        self.assertTrue(any("expected.label" in e.message for e in errs))

    def test_invalid_source(self) -> None:
        errs = validate_record(_valid_case(source="random"))
        self.assertTrue(any("invalid source" in e.message for e in errs))

    def test_input_too_long(self) -> None:
        errs = validate_record(_valid_case(input="x" * 5000))
        self.assertTrue(any("input length" in e.message for e in errs))

    def test_input_empty(self) -> None:
        errs = validate_record(_valid_case(input=""))
        self.assertTrue(any("input length" in e.message for e in errs))

    def test_reason_keywords_type(self) -> None:
        rec = _valid_case()
        rec["must_contain_reason_keywords"] = "not a list"
        errs = validate_record(rec)
        self.assertTrue(any("reason_keywords" in e.message for e in errs))


class UniquenessTest(unittest.TestCase):
    def test_duplicate_ids_detected(self) -> None:
        a = _valid_case(id="dup-001")
        b = _valid_case(id="dup-001")
        errs = validate_uniqueness([a, b])
        self.assertEqual(len(errs), 1)
        self.assertIn("duplicate id", errs[0].message)


class CountingTest(unittest.TestCase):
    def test_target_counts_sum_to_100(self) -> None:
        self.assertEqual(sum(TARGET_COUNTS.values()), 100)

    def test_count_by_subcategory(self) -> None:
        recs = [
            _valid_case(),
            _valid_case(id="phish-002", subcategory="bank_alert"),
            _valid_case(id="phish-003", subcategory="bank_alert"),
        ]
        counts = count_by_subcategory(recs)
        self.assertEqual(counts[("phishing", "delivery_sms")], 1)
        self.assertEqual(counts[("phishing", "bank_alert")], 2)

    def test_count_diff_warnings_include_under_and_unexpected(self) -> None:
        warnings = count_diff_warnings({("phishing", "delivery_sms"): 0})
        # All other targets will be "have 0, target N"; one expected.
        self.assertTrue(any("delivery_sms" in w for w in warnings))


class ValidatorCliTest(unittest.TestCase):
    """End-to-end test of scripts/validate_cases.py exit codes."""

    def test_empty_file_passes(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write("")
            path = f.name
        try:
            proc = subprocess.run(
                [sys.executable, str(VALIDATOR), "--cases", path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
        finally:
            Path(path).unlink()

    def test_valid_record_passes(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as f:
            f.write(json.dumps(_valid_case(), ensure_ascii=False) + "\n")
            path = f.name
        try:
            proc = subprocess.run(
                [sys.executable, str(VALIDATOR), "--cases", path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
        finally:
            Path(path).unlink()

    def test_invalid_record_fails_with_helpful_message(self) -> None:
        bad = _valid_case(category="bogus")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as f:
            f.write(json.dumps(bad, ensure_ascii=False) + "\n")
            path = f.name
        try:
            proc = subprocess.run(
                [sys.executable, str(VALIDATOR), "--cases", path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("invalid category", proc.stderr)
        finally:
            Path(path).unlink()


if __name__ == "__main__":
    unittest.main()
