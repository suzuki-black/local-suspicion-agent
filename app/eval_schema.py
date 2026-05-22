"""Single source of truth for the eval case schema.

Used by:
  - scripts/validate_cases.py (Issue #4)
  - scripts/eval.py            (Issues #8, #9)

Schema reference doc: tests/schema.md
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

CATEGORIES = (
    "phishing",
    "fraud",
    "manipulation",
    "prompt_injection",
    "harmless",
    "legit_but_suspicious",
)

LABELS = (
    "phishing",
    "fraud",
    "manipulation",
    "prompt_injection",
    "harmless",
    "other",
)

ATTACK_LABELS = ("phishing", "fraud", "manipulation", "prompt_injection")

SOURCES = ("synthetic", "real_anonymized", "claude", "copilot", "human")

# (category, subcategory): target count
TARGET_COUNTS: dict[tuple[str, str], int] = {
    # phishing (30)
    ("phishing", "delivery_sms"): 8,
    ("phishing", "bank_alert"): 8,
    ("phishing", "prize_lottery"): 4,
    ("phishing", "credential_reset"): 5,
    ("phishing", "tax_govt"): 5,
    # fraud (15)
    ("fraud", "investment"): 5,
    ("fraud", "romance"): 3,
    ("fraud", "refund"): 3,
    ("fraud", "invoice"): 4,
    # manipulation (10)
    ("manipulation", "urgency"): 3,
    ("manipulation", "authority"): 3,
    ("manipulation", "reciprocity"): 2,
    ("manipulation", "fear"): 2,
    # prompt_injection (15)
    ("prompt_injection", "instruction"): 3,
    ("prompt_injection", "system_spoof"): 2,
    ("prompt_injection", "ignore_previous"): 3,
    ("prompt_injection", "tag_escape"): 2,
    ("prompt_injection", "jailbreak"): 2,
    ("prompt_injection", "persona_hijack"): 3,
    # harmless (15)
    ("harmless", "meeting_notice"): 5,
    ("harmless", "casual_chat"): 5,
    ("harmless", "product_announce"): 5,
    # legit_but_suspicious (15)
    ("legit_but_suspicious", "boss_urgency"): 3,
    ("legit_but_suspicious", "intro_referral"): 2,
    ("legit_but_suspicious", "real_password_reset"): 2,
    ("legit_but_suspicious", "internal_irregular"): 2,
    ("legit_but_suspicious", "govt_legit"): 3,
    ("legit_but_suspicious", "vendor_invoice_legit"): 3,
}

VALID_SUBCATEGORIES_BY_CATEGORY: dict[str, set[str]] = {}
for (cat, sub), _n in TARGET_COUNTS.items():
    VALID_SUBCATEGORIES_BY_CATEGORY.setdefault(cat, set()).add(sub)

REQUIRED_FIELDS = (
    "id",
    "category",
    "subcategory",
    "input",
    "expected",
    "must_contain_reason_keywords",
    "must_not_contain_reason_keywords",
    "notes",
    "source",
    "added_at",
    "schema_version",
)

REQUIRED_EXPECTED_FIELDS = ("score_min", "score_max", "label")

SCHEMA_VERSION = 1
INPUT_MIN_LEN = 1
INPUT_MAX_LEN = 4000


@dataclass
class ValidationError:
    line_number: int
    case_id: str | None
    message: str

    def format(self) -> str:
        cid = self.case_id or "<unknown>"
        return f"line {self.line_number} [{cid}]: {self.message}"


def validate_record(rec: Any, line_number: int = 0) -> list[ValidationError]:
    """Validate a single case dict. Returns empty list if valid."""
    errors: list[ValidationError] = []

    def err(msg: str, cid: Any = None) -> None:
        errors.append(
            ValidationError(
                line_number=line_number,
                case_id=str(cid) if cid is not None else None,
                message=msg,
            )
        )

    if not isinstance(rec, dict):
        err("record is not a JSON object")
        return errors

    cid = rec.get("id")
    for f in REQUIRED_FIELDS:
        if f not in rec:
            err(f"missing required field '{f}'", cid)

    if errors:
        return errors  # don't pile on if structurally broken

    category = rec["category"]
    subcategory = rec["subcategory"]

    if category not in CATEGORIES:
        err(f"invalid category {category!r}", cid)
    elif subcategory not in VALID_SUBCATEGORIES_BY_CATEGORY.get(category, set()):
        err(
            f"subcategory {subcategory!r} is not valid for category {category!r}",
            cid,
        )

    if rec["source"] not in SOURCES:
        err(f"invalid source {rec['source']!r}", cid)

    if rec["schema_version"] != SCHEMA_VERSION:
        err(
            f"unsupported schema_version {rec['schema_version']!r} (expected {SCHEMA_VERSION})",
            cid,
        )

    if not isinstance(rec["input"], str):
        err("input must be a string", cid)
    else:
        length = len(rec["input"])
        if length < INPUT_MIN_LEN or length > INPUT_MAX_LEN:
            err(
                f"input length {length} outside [{INPUT_MIN_LEN}, {INPUT_MAX_LEN}]",
                cid,
            )

    expected = rec.get("expected")
    if not isinstance(expected, dict):
        err("expected must be a JSON object", cid)
    else:
        for f in REQUIRED_EXPECTED_FIELDS:
            if f not in expected:
                err(f"expected.{f} missing", cid)
        if all(f in expected for f in REQUIRED_EXPECTED_FIELDS):
            smin = expected["score_min"]
            smax = expected["score_max"]
            label = expected["label"]
            if not (isinstance(smin, int) and 0 <= smin <= 100):
                err(f"expected.score_min {smin!r} not in [0,100]", cid)
            if not (isinstance(smax, int) and 0 <= smax <= 100):
                err(f"expected.score_max {smax!r} not in [0,100]", cid)
            if (
                isinstance(smin, int)
                and isinstance(smax, int)
                and smin > smax
            ):
                err(f"expected.score_min ({smin}) > score_max ({smax})", cid)
            if label not in LABELS:
                err(f"expected.label {label!r} not in {LABELS}", cid)

    for f in ("must_contain_reason_keywords", "must_not_contain_reason_keywords"):
        v = rec.get(f)
        if v is not None and not (
            isinstance(v, list) and all(isinstance(x, str) for x in v)
        ):
            err(f"{f} must be null or list[str]", cid)

    return errors


def validate_uniqueness(records: Iterable[dict]) -> list[ValidationError]:
    """Detect duplicate ids across the whole file."""
    seen: dict[str, int] = {}
    errors: list[ValidationError] = []
    for i, rec in enumerate(records, start=1):
        if not isinstance(rec, dict):
            continue
        cid = rec.get("id")
        if not isinstance(cid, str):
            continue
        if cid in seen:
            errors.append(
                ValidationError(
                    line_number=i,
                    case_id=cid,
                    message=f"duplicate id (first seen on line {seen[cid]})",
                )
            )
        else:
            seen[cid] = i
    return errors


def count_by_subcategory(records: Iterable[dict]) -> dict[tuple[str, str], int]:
    counts: dict[tuple[str, str], int] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        cat = rec.get("category")
        sub = rec.get("subcategory")
        if isinstance(cat, str) and isinstance(sub, str):
            counts[(cat, sub)] = counts.get((cat, sub), 0) + 1
    return counts


def count_diff_warnings(actual: dict[tuple[str, str], int]) -> list[str]:
    """Emit human-readable warnings where actual counts differ from targets."""
    warnings: list[str] = []
    for key, target in TARGET_COUNTS.items():
        got = actual.get(key, 0)
        if got != target:
            cat, sub = key
            warnings.append(
                f"{cat}/{sub}: have {got}, target {target} ({got - target:+d})"
            )
    for key, got in actual.items():
        if key not in TARGET_COUNTS:
            cat, sub = key
            warnings.append(
                f"{cat}/{sub}: unexpected (count {got}, not in target table)"
            )
    return warnings
