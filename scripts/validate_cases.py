"""Standalone case-file validator (thin wrapper).

Equivalent to `python scripts/eval.py validate`. Kept as a separate entry
point for use in pre-commit hooks / CI without loading the full eval deps.
P0 task #4 — implementation pending.
"""
from __future__ import annotations

# TODO(P0-4): implement JSONL schema validation matching tests/schema.md.
