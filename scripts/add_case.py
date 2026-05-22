"""Interactive / CLI helper to append a new case to tests/cases.jsonl.

P0 — implementation pending (not on critical path; can be done after #1-9).

Target usage:
  python scripts/add_case.py \
    --category phishing --subcategory delivery_sms \
    --input "..." --label phishing \
    --score-min 60 --score-max 100 \
    --source claude --notes "..."
"""
from __future__ import annotations

# TODO(P0-misc): implement CLI append helper.
