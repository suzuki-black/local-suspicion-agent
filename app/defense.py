"""Meta prompt-injection defense.

The agent's input is *suspect text*, not instructions. Real-world callers
may submit text that contains "ignore previous instructions", forged
``system:`` blocks, or attempts to close our ``<SUSPECT_INPUT>`` wrapper.

This module's job is to:

1. Wrap any input in nonce-tagged ``<SUSPECT_INPUT id="...">`` ... ``</SUSPECT_INPUT id="...">``
   so the LLM can be told (via system prompt) that tag content is data, not
   instruction.
2. Neutralize attempts to close the wrapper from inside (``</SUSPECT_INPUT``).
3. Detect known injection patterns and emit signals + a 0..40 lower-bound
   pre-score that the final aggregator can ``max()`` against the LLM score.

No network. No file I/O. Pure-stdlib.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import List, Pattern, Tuple

MAX_PRE_SCORE = 40

# (pattern_id, compiled regex, severity 0..30).
# Severity reflects how strongly a hit implies injection intent in isolation.
_PATTERNS: List[Tuple[str, Pattern[str], int]] = [
    (
        "ignore_previous_en",
        re.compile(
            r"(?i)ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions?|prompts?|rules?|context|messages?)"
        ),
        25,
    ),
    (
        "ignore_previous_ja",
        re.compile(
            r"(以前|これまで|上記|先ほど|今までの?)の?"
            r"(指示|プロンプト|命令|ルール|コンテキスト)(は|を)?"
            r"(全て|すべて)?(無視|忘れ|破棄)"
        ),
        25,
    ),
    (
        "system_spoof",
        # Line beginning with system:/assistant:/user: (English or fullwidth colon).
        re.compile(r"(?im)^\s*(system|assistant|user)\s*[:：]\s*\S"),
        20,
    ),
    (
        "persona_hijack_ja",
        re.compile(
            r"あなたは(これから|今から|以降|本当は|実は)?"
            r"[^\n]{0,40}(です|になり|となり|として(振る舞|動作|応答))"
        ),
        15,
    ),
    (
        "persona_hijack_en",
        re.compile(
            r"(?i)you\s+are\s+(now\s+|actually\s+)?"
            r"(an?|the)?\s*[^.\n]{0,40}\b(assistant|ai|model|agent|bot)\b"
        ),
        15,
    ),
    (
        "tag_escape",
        re.compile(r"</?\s*SUSPECT_INPUT", re.IGNORECASE),
        20,
    ),
    (
        "safe_claim_ja",
        re.compile(
            r"(無害|安全|問題な[いし]|害がな[いし])"
            r"(と|だと|として)?"
            r"(評価|判定|分類|扱|返[しせ]|出力)"
        ),
        20,
    ),
    (
        "safe_claim_en",
        re.compile(
            r"(?i)\b(classify|rate|mark|treat|consider)\s+(this|it|the\s+\w+|"
            r"following)?\s*as\s+(harmless|safe|benign|trusted)"
        ),
        20,
    ),
    (
        "jailbreak",
        re.compile(
            r"(?i)\b(DAN|do\s+anything\s+now|jailbreak|unrestricted|"
            r"uncensored|developer\s+mode)\b|(制限のない|無制限|脱獄)"
        ),
        20,
    ),
    (
        "role_override",
        re.compile(
            r"(?i)(new|updated?|別の|新しい)\s*"
            r"(instructions?|system\s+prompt|システムプロンプト|指示)\s*[:：]"
        ),
        25,
    ),
    (
        "prompt_exfil_ja",
        # Japanese is verb-final: NOUN ... VERB, so match either order.
        re.compile(
            r"(プロンプト|システム(?:プロンプト)?|指示|ルール)"
            r"[^\n]{0,30}"
            r"(出力|表示|教え|見せ|公開|教えて|送って)"
            r"(してください|して|ください)?"
        ),
        15,
    ),
    (
        "prompt_exfil_en",
        re.compile(
            r"(?i)(print|reveal|show|output|tell\s+me)\s+"
            r"(your|the)\s+(system\s+)?(prompt|instructions?|rules?)"
        ),
        15,
    ),
]


@dataclass(frozen=True)
class InjectionSignal:
    """A single pattern match against the input."""

    pattern_id: str
    matched_text: str  # truncated to <=50 chars for log safety
    severity: int


@dataclass
class WrappedInput:
    """Result of wrap_input().

    Attributes:
        wrapped: The full string to feed to the LLM (with SUSPECT_INPUT tags).
        nonce: 8-hex-char id stamped into both opening and closing tags.
        injection_signals: All detected injection patterns (may be empty).
        pre_score: 0..MAX_PRE_SCORE lower-bound risk score from signals alone.
    """

    wrapped: str
    nonce: str
    injection_signals: List[InjectionSignal] = field(default_factory=list)
    pre_score: int = 0


def _new_nonce() -> str:
    return uuid.uuid4().hex[:8]


def _escape_close_tag(text: str) -> str:
    """Neutralize any attempt to close the SUSPECT_INPUT wrapper from inside."""
    return re.sub(
        r"</\s*SUSPECT_INPUT", "&lt;/SUSPECT_INPUT", text, flags=re.IGNORECASE
    )


def _detect(text: str) -> List[InjectionSignal]:
    signals: List[InjectionSignal] = []
    for pid, pat, sev in _PATTERNS:
        for m in pat.finditer(text):
            snippet = m.group(0)
            if len(snippet) > 50:
                snippet = snippet[:50] + "…"
            signals.append(InjectionSignal(pid, snippet, sev))
    return signals


def _derive_pre_score(signals: List[InjectionSignal]) -> int:
    """Highest-severity pattern dominates; each additional unique pattern +5.

    Capped at MAX_PRE_SCORE. Multiple hits of the same pattern_id do not
    compound (de-duplicated first).
    """
    if not signals:
        return 0
    best_per_pattern: dict[str, int] = {}
    for s in signals:
        prev = best_per_pattern.get(s.pattern_id, 0)
        if s.severity > prev:
            best_per_pattern[s.pattern_id] = s.severity
    severities = sorted(best_per_pattern.values(), reverse=True)
    score = severities[0] + 5 * (len(severities) - 1)
    return min(score, MAX_PRE_SCORE)


def wrap_input(text: str) -> WrappedInput:
    """Wrap input in nonce-tagged ``<SUSPECT_INPUT>`` block and detect injections.

    The returned ``wrapped`` string is safe to embed in a user-role LLM message.
    The system prompt (see ``app/prompts.py``) instructs the model that tag
    content is data, not instructions.
    """
    if not isinstance(text, str):
        raise TypeError("wrap_input expects str")
    nonce = _new_nonce()
    signals = _detect(text)
    safe = _escape_close_tag(text)
    open_tag = f'<SUSPECT_INPUT id="{nonce}">'
    close_tag = f'</SUSPECT_INPUT id="{nonce}">'
    wrapped = f"{open_tag}\n{safe}\n{close_tag}"
    pre_score = _derive_pre_score(signals)
    return WrappedInput(
        wrapped=wrapped,
        nonce=nonce,
        injection_signals=signals,
        pre_score=pre_score,
    )
