"""Version constants for agent / prompt / tools.

These are embedded in every trace and participate in the deterministic
seed (see ``make_seed``). Bump them when changing behavior — a version
change automatically invalidates cached seeds and forces re-evaluation
against the eval set.
"""
from __future__ import annotations

import hashlib

# Scaffold values for P0. Replaced as tasks land.
AGENT_VERSION = "0.5.0-p0-scaffold"
PROMPT_VERSION = "v3-scaffold"

TOOL_VERSIONS: dict[str, str] = {
    # Populated during P0 implementation.
    # e.g. "defense": "1.0", "extract_urls": "1.0"
}


def make_seed(input_text: str) -> int:
    """Deterministic seed from input + agent/prompt versions.

    Same (input, agent_version, prompt_version) -> same seed -> same
    LLM output (modulo Ollama's per-model determinism guarantees).
    Bumping a version automatically forces re-evaluation.
    """
    h = hashlib.sha256(
        f"{input_text}|{AGENT_VERSION}|{PROMPT_VERSION}".encode("utf-8")
    ).digest()
    return int.from_bytes(h[:8], "big") % (2**31)
