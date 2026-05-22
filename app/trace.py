"""Three-layer trace logging.

P0 task #2 — interface frozen, implementation pending.

Layers:
  1. raw_input          — opt-in, AES-GCM encrypted (default: not stored)
  2. tool_observations  — always stored, safe
  3. llm_calls          — sanitized; prompts stored by version reference

Public API (target):

    t = Trace.open(seed=..., agent_version=..., model=...)
    t.observe("extract_urls", {"urls": [...]})
    t.llm_call("initial", prompt_ref="v3:initial", input_hash="...",
               output_json={...}, latency_ms=...)
    t.seal(decision={...}, disagreement_flag=False)
    # -> traces/<trace_id>.json

See README ("P0 spec") for the full schema.
"""
from __future__ import annotations

# TODO(P0-2): implement Trace class, ULID generation, file writer.
