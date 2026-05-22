"""Three-layer trace logging for audit & replay.

Layers
------
1. ``raw_input``       — opt-in only. AES-GCM encrypted with a key kept
                          under ``~/.suspicion/trace.key`` (mode 0600).
                          Default: not persisted (only its SHA-256 + length).
2. ``observations``    — tool calls and their (safe) outputs. Always stored.
3. ``llm_calls``       — sanitized: stores prompt_ref (version id), input
                          hash, output JSON, latency. Never stores raw prompt.

Files are written atomically to ``traces/<trace_id>.json`` (gitignored).

Public API
----------
    t = Trace.open(seed=..., agent_version=..., prompt_version=...,
                   model=..., tool_versions={...})
    t.record_raw_input(text)
    t.observe("extract_urls", {"urls": [...]})
    t.llm_call("initial", prompt_ref="v4-defense:initial",
               input_hash="...", output_json={...}, latency_ms=...)
    path = t.seal(decision={...}, disagreement_flag=False)

    decrypt_raw_input(blob_hex)   # only if opt-in was enabled
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Defaults (overridable via env or Trace.open kwargs) ----------

DEFAULT_TRACES_DIR = Path(os.environ.get("SUSPICION_TRACES_DIR", "traces"))
STORE_RAW = os.environ.get("SUSPICION_STORE_RAW", "")  # "" | "encrypted"
DEFAULT_KEYRING_DIR = Path(
    os.path.expanduser(os.environ.get("SUSPICION_KEYRING_DIR", "~/.suspicion"))
)
KEY_FILENAME = "trace.key"

# ---------- ULID-like id ----------

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid() -> str:
    """26-char Crockford-base32 id: 48-bit ms timestamp + 80-bit randomness."""
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand = int.from_bytes(secrets.token_bytes(10), "big")
    val = (ts_ms << 80) | rand
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[val & 0x1F])
        val >>= 5
    return "".join(reversed(chars))


# ---------- Helpers ----------


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _ensure_key(path: Path) -> bytes:
    """Return AES-GCM key bytes; create the file with 0600 perms if absent."""
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    key = AESGCM.generate_key(bit_length=256)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "wb") as fh:
        fh.write(key)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return key


def _encrypt(text: str, key: bytes) -> str:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)
    return (nonce + ct).hex()


def _decrypt(blob_hex: str, key: bytes) -> str:
    blob = bytes.fromhex(blob_hex)
    nonce, ct = blob[:12], blob[12:]
    pt = AESGCM(key).decrypt(nonce, ct, None)
    return pt.decode("utf-8")


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write JSON via temp file + rename, ensuring fsync."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=".trace-",
        suffix=".tmp",
        delete=False,
    )
    try:
        json.dump(payload, tmp, ensure_ascii=False, indent=2, sort_keys=True)
        tmp.flush()
        os.fsync(tmp.fileno())
    finally:
        tmp.close()
    os.replace(tmp.name, path)


# ---------- Trace ----------


@dataclass
class Trace:
    trace_id: str
    started_at: str
    agent_version: str
    prompt_version: str
    model: str
    tool_versions: dict[str, str]
    seed: int

    raw_input: Optional[str] = None
    raw_input_sha256: Optional[str] = None
    raw_input_length: Optional[int] = None

    observations: list[dict[str, Any]] = field(default_factory=list)
    llm_calls: list[dict[str, Any]] = field(default_factory=list)

    decision: Optional[dict[str, Any]] = None
    disagreement_flag: bool = False
    sealed_at: Optional[str] = None

    # Non-serialized config (set at open()).
    _traces_dir: Path = field(default_factory=lambda: DEFAULT_TRACES_DIR, repr=False)
    _store_raw_mode: str = field(default=STORE_RAW, repr=False)
    _keyring_dir: Path = field(default_factory=lambda: DEFAULT_KEYRING_DIR, repr=False)

    @classmethod
    def open(
        cls,
        *,
        seed: int,
        agent_version: str,
        prompt_version: str,
        model: str,
        tool_versions: Optional[dict[str, str]] = None,
        traces_dir: Optional[Path] = None,
        store_raw_mode: Optional[str] = None,
        keyring_dir: Optional[Path] = None,
    ) -> "Trace":
        return cls(
            trace_id=_ulid(),
            started_at=_now_iso(),
            agent_version=agent_version,
            prompt_version=prompt_version,
            model=model,
            tool_versions=dict(tool_versions or {}),
            seed=seed,
            _traces_dir=Path(traces_dir) if traces_dir else DEFAULT_TRACES_DIR,
            _store_raw_mode=(
                store_raw_mode if store_raw_mode is not None else STORE_RAW
            ),
            _keyring_dir=Path(keyring_dir) if keyring_dir else DEFAULT_KEYRING_DIR,
        )

    def record_raw_input(self, text: str) -> None:
        """Always store SHA-256 + length; store encrypted text only if opt-in."""
        self.raw_input_sha256 = _sha256_hex(text)
        self.raw_input_length = len(text)
        if self._store_raw_mode == "encrypted":
            key = _ensure_key(self._keyring_dir / KEY_FILENAME)
            self.raw_input = _encrypt(text, key)
        # else: raw_input remains None

    def observe(self, tool: str, out: Any) -> None:
        self.observations.append({"tool": tool, "out": out})

    def llm_call(
        self,
        step: str,
        prompt_ref: str,
        input_hash: str,
        output_json: Any,
        latency_ms: int,
    ) -> None:
        self.llm_calls.append(
            {
                "step": step,
                "prompt_ref": prompt_ref,
                "input_hash": input_hash,
                "output_json": output_json,
                "latency_ms": int(latency_ms),
            }
        )

    def seal(
        self,
        decision: dict[str, Any],
        disagreement_flag: bool = False,
    ) -> Path:
        self.decision = decision
        self.disagreement_flag = disagreement_flag
        self.sealed_at = _now_iso()
        path = self._traces_dir / f"{self.trace_id}.json"
        payload = {
            "trace_id": self.trace_id,
            "started_at": self.started_at,
            "agent_version": self.agent_version,
            "prompt_version": self.prompt_version,
            "model": self.model,
            "tool_versions": self.tool_versions,
            "seed": self.seed,
            "raw_input": self.raw_input,
            "raw_input_sha256": self.raw_input_sha256,
            "raw_input_length": self.raw_input_length,
            "observations": self.observations,
            "llm_calls": self.llm_calls,
            "decision": self.decision,
            "disagreement_flag": self.disagreement_flag,
            "sealed_at": self.sealed_at,
        }
        _atomic_write_json(path, payload)
        return path


# ---------- Public helpers ----------


def decrypt_raw_input(blob_hex: str, keyring_dir: Optional[Path] = None) -> str:
    """Decrypt a previously-encrypted raw_input blob using the local keyring."""
    key_path = (keyring_dir or DEFAULT_KEYRING_DIR) / KEY_FILENAME
    if not key_path.exists():
        raise FileNotFoundError(f"keyring not found at {key_path}")
    return _decrypt(blob_hex, key_path.read_bytes())
