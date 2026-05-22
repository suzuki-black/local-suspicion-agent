"""Meta prompt-injection defense.

P0 task #1 — interface frozen, implementation pending.

When complete, exposes:

    wrap_input(text: str) -> WrappedInput

where ``WrappedInput`` carries:
    - ``wrapped``: the input enclosed in ``<SUSPECT_INPUT id="...">`` tags
    - ``injection_signals``: list of pattern matches found in the input
    - ``pre_score``: 0..40 lower-bound score driven by injection signals

See README ("P0 spec") for the full design.
"""
from __future__ import annotations

# TODO(P0-1): implement wrap_input, INJECTION_PATTERNS, pre_score derivation.
