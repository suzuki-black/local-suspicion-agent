"""Standalone validator for tests/cases.jsonl.

Equivalent to ``python scripts/eval.py validate`` (Issue #4).
No dependency on Ollama / FastAPI / cryptography — safe in CI / pre-commit.

Usage:
    python scripts/validate_cases.py [--cases tests/cases.jsonl] [--strict-counts]

Exit codes:
    0   all records valid
    1   one or more validation errors
    2   I/O or argument error
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make ``app`` importable when run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.eval_schema import (  # noqa: E402
    count_by_subcategory,
    count_diff_warnings,
    validate_record,
    validate_uniqueness,
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    p.add_argument("--cases", default="tests/cases.jsonl", type=Path)
    p.add_argument(
        "--strict-counts",
        action="store_true",
        help="Treat count-mismatch warnings as errors (exit 1)",
    )
    args = p.parse_args(argv)

    if not args.cases.exists():
        print(f"error: file not found: {args.cases}", file=sys.stderr)
        return 2

    records: list[dict] = []
    errors = []
    with args.cases.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                rec = json.loads(stripped)
            except json.JSONDecodeError as e:
                errors.append(f"line {line_no}: invalid JSON ({e.msg})")
                continue
            records.append(rec)
            for verr in validate_record(rec, line_number=line_no):
                errors.append(verr.format())

    for verr in validate_uniqueness(records):
        errors.append(verr.format())

    actual_counts = count_by_subcategory(records)
    warnings = count_diff_warnings(actual_counts)

    # ---- Report ----
    total = len(records)
    print(f"validated {total} record(s) from {args.cases}")

    if warnings:
        print(f"\n{len(warnings)} count warning(s):")
        for w in warnings:
            print(f"  - {w}")

    if errors:
        print(f"\n{len(errors)} validation error(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    if args.strict_counts and warnings:
        print("\n--strict-counts: treating warnings as errors", file=sys.stderr)
        return 1

    print("\nOK: all records valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
