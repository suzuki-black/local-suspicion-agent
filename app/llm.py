"""ローカル LLM (Ollama) 呼び出しモジュール。

外部 API は使用しない。Ollama がローカル (127.0.0.1:11434) で動作している前提。
将来別バックエンド (llama.cpp など) に差し替えやすいよう、analyze() のみを公開する。
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx

from .prompts import SYSTEM_PROMPT, USER_TEMPLATE
from .schemas import AnalyzeResponse

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.environ.get("SUSPICION_MODEL", "llama3.2:3b")
TIMEOUT_SEC = 120


class LLMError(RuntimeError):
    pass


async def _call_ollama(text: str) -> str:
    payload: dict[str, Any] = {
        "model": MODEL,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.2},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_TEMPLATE.format(text=text)},
        ],
    }
    async with httpx.AsyncClient(timeout=TIMEOUT_SEC) as client:
        try:
            r = await client.post(f"{OLLAMA_HOST}/api/chat", json=payload)
        except httpx.HTTPError as e:
            raise LLMError(f"Ollama に接続できません ({OLLAMA_HOST}): {e}") from e
    if r.status_code != 200:
        raise LLMError(f"Ollama returned {r.status_code}: {r.text[:200]}")
    data = r.json()
    return data.get("message", {}).get("content", "")


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


async def analyze(text: str) -> AnalyzeResponse:
    raw = await _call_ollama(text)
    obj = _extract_json(raw)

    score = int(obj.get("score", 0))
    score = max(0, min(100, score))
    label = obj.get("label", "other")
    if label not in {"phishing", "fraud", "manipulation", "prompt_injection", "harmless", "other"}:
        label = "other"
    reasons = obj.get("reasons", [])
    if not isinstance(reasons, list):
        reasons = [str(reasons)]
    reasons = [str(x) for x in reasons][:20]

    return AnalyzeResponse(score=score, label=label, reasons=reasons)
