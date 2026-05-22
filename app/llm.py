"""Ollama-backed analyze() with defense wrapping, seed-based reproducibility,
and three-layer trace logging.

Wired by Issue #3. The only "agent backend" entry point is :func:`analyze`.
Replacing the backend (llama.cpp, vLLM, …) means replacing this module.

External network: none. Only contacts the local Ollama HTTP endpoint.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, is_dataclass
from typing import Any

import httpx

from . import defense, prompts, trace, versions
from .schemas import AnalyzeResponse

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.environ.get("SUSPICION_MODEL", "qwen2.5:7b")
TIMEOUT_SEC = 120
TEMPERATURE = 0.3
DISAGREEMENT_DELTA = 30  # |llm_score - heuristic_pre_score|

# Sentinel value used in the model "fingerprint" recorded in traces.
# We avoid querying Ollama for the manifest digest on the hot path; instead
# we record "name@unknown" unless an explicit digest is supplied via env.
MODEL_DIGEST = os.environ.get("SUSPICION_MODEL_DIGEST", "unknown")


class LLMError(RuntimeError):
    pass


def _model_fingerprint() -> str:
    return f"{MODEL}@{MODEL_DIGEST}"


async def _call_ollama(wrapped_input: str, seed: int) -> tuple[str, int]:
    """POST to /api/chat. Returns (raw_content, latency_ms).

    Forces JSON output, temperature 0.3, and a deterministic seed.
    """
    payload: dict[str, Any] = {
        "model": MODEL,
        "stream": False,
        "format": "json",
        "options": {"temperature": TEMPERATURE, "seed": seed},
        "messages": [
            {"role": "system", "content": prompts.SYSTEM_PROMPT},
            {
                "role": "user",
                "content": prompts.USER_TEMPLATE.format(wrapped_input=wrapped_input),
            },
        ],
    }
    t0 = time.monotonic()
    async with httpx.AsyncClient(timeout=TIMEOUT_SEC) as client:
        try:
            r = await client.post(f"{OLLAMA_HOST}/api/chat", json=payload)
        except httpx.HTTPError as e:
            raise LLMError(f"Ollama に接続できません ({OLLAMA_HOST}): {e}") from e
    latency_ms = int((time.monotonic() - t0) * 1000)
    if r.status_code != 200:
        raise LLMError(f"Ollama returned {r.status_code}: {r.text[:200]}")
    content = r.json().get("message", {}).get("content", "")
    return content, latency_ms


def _extract_json(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        raise LLMError(f"LLM 応答に JSON が含まれていません: {raw[:200]}")
    return json.loads(m.group(0))


def _sanitize_decision(obj: dict[str, Any]) -> tuple[int, str, list[str]]:
    score = int(obj.get("score", 0))
    score = max(0, min(100, score))
    label = obj.get("label", "other")
    if label not in {
        "phishing", "fraud", "manipulation", "prompt_injection", "harmless", "other"
    }:
        label = "other"
    reasons = obj.get("reasons", [])
    if not isinstance(reasons, list):
        reasons = [str(reasons)]
    reasons = [str(x) for x in reasons][:20]
    return score, label, reasons


def _serialize_signals(signals: list) -> list[dict]:
    out: list[dict] = []
    for s in signals:
        if is_dataclass(s):
            out.append(asdict(s))
        elif isinstance(s, dict):
            out.append(s)
        else:
            out.append({"repr": str(s)})
    return out


async def analyze(text: str) -> AnalyzeResponse:
    """Analyze ``text`` end-to-end with defense wrapping and full tracing."""
    # 1. Defense wrap (always runs; observed into trace)
    # Deterministic nonce ensures the wrapped prompt is identical for the
    # same (text, agent_version, prompt_version) tuple — required for
    # reproducibility (Issue #3 DoD).
    nonce = defense.derive_nonce(
        text, salt=f"{versions.AGENT_VERSION}|{versions.PROMPT_VERSION}"
    )
    wrapped = defense.wrap_input(text, nonce=nonce)

    # 2. Open trace with version/seed stamps
    seed = versions.make_seed(text)
    t = trace.Trace.open(
        seed=seed,
        agent_version=versions.AGENT_VERSION,
        prompt_version=versions.PROMPT_VERSION,
        model=_model_fingerprint(),
        tool_versions=dict(versions.TOOL_VERSIONS),
    )
    t.record_raw_input(text)
    t.observe(
        "defense.wrap_input",
        {
            "pre_score": wrapped.pre_score,
            "injection_signals": _serialize_signals(wrapped.injection_signals),
        },
    )

    # 3. LLM call
    raw, latency_ms = await _call_ollama(wrapped.wrapped, seed)
    obj = _extract_json(raw)
    score, label, reasons = _sanitize_decision(obj)

    t.llm_call(
        step="initial",
        prompt_ref=prompts.INITIAL_PROMPT_REF,
        input_hash=t.raw_input_sha256 or "",
        output_json={"score": score, "label": label, "reasons": reasons},
        latency_ms=latency_ms,
    )

    # 4. Aggregate: max() of heuristic pre_score and LLM score; flag disagreement
    final_score = max(score, wrapped.pre_score)

    # disagreement only when the heuristic actually fired AND the LLM
    # significantly under-rated. Heuristic silence (pre_score == 0) on a
    # phishing-style input is expected: the heuristic only covers injection.
    disagreement = (
        wrapped.pre_score >= 20 and (wrapped.pre_score - score) >= DISAGREEMENT_DELTA
    )

    # If the heuristic-only signal dominated, promote label to prompt_injection
    # when LLM under-rated obvious injections.
    if wrapped.pre_score > score and wrapped.injection_signals and label == "harmless":
        label = "prompt_injection"
        if not any("インジェクション" in r or "injection" in r.lower() for r in reasons):
            reasons = ["プロンプトインジェクションの兆候を検出"] + reasons

    decision = {"score": final_score, "label": label, "reasons": reasons}
    path = t.seal(decision=decision, disagreement_flag=disagreement)
    _ = path  # path returned by seal; not used here

    return AnalyzeResponse(
        score=final_score,
        label=label,
        reasons=reasons,
        trace_id=t.trace_id,
        disagreement_flag=disagreement,
    )
