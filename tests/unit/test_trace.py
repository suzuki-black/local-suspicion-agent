"""Unit tests for app/trace.py — Issue #2 DoD."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from app.trace import (
    KEY_FILENAME,
    Trace,
    _ulid,
    decrypt_raw_input,
)


def _make_trace(traces_dir: Path, keyring_dir: Path, store_raw_mode: str = "") -> Trace:
    return Trace.open(
        seed=12345,
        agent_version="0.5.0-test",
        prompt_version="v4-defense",
        model="qwen2.5:7b@deadbeef",
        tool_versions={"defense": "1.0"},
        traces_dir=traces_dir,
        keyring_dir=keyring_dir,
        store_raw_mode=store_raw_mode,
    )


class UlidTest(unittest.TestCase):
    def test_length_and_charset(self) -> None:
        u = _ulid()
        self.assertEqual(len(u), 26)
        for ch in u:
            self.assertIn(ch, "0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    def test_uniqueness(self) -> None:
        ids = {_ulid() for _ in range(2000)}
        self.assertEqual(len(ids), 2000)


class TraceRoundtripTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.traces_dir = Path(self.tmp.name) / "traces"
        self.keyring_dir = Path(self.tmp.name) / "keyring"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_full_roundtrip(self) -> None:
        t = _make_trace(self.traces_dir, self.keyring_dir)
        t.record_raw_input("hello world")
        t.observe("defense.wrap_input", {"pre_score": 0, "injection_signals": []})
        t.llm_call(
            step="initial",
            prompt_ref="v4-defense:initial",
            input_hash="abc123",
            output_json={"score": 12, "label": "harmless", "reasons": []},
            latency_ms=1234,
        )
        path = t.seal(
            decision={"score": 12, "label": "harmless", "reasons": []},
            disagreement_flag=False,
        )
        self.assertTrue(path.exists())
        data = json.loads(path.read_text(encoding="utf-8"))

        # Required fields populated
        for key in (
            "trace_id", "started_at", "agent_version", "prompt_version",
            "model", "tool_versions", "seed", "raw_input_sha256",
            "raw_input_length", "observations", "llm_calls",
            "decision", "disagreement_flag", "sealed_at",
        ):
            self.assertIn(key, data, f"missing key {key}")

        self.assertEqual(data["seed"], 12345)
        self.assertEqual(data["raw_input_length"], len("hello world"))
        self.assertEqual(len(data["raw_input_sha256"]), 64)
        self.assertEqual(len(data["observations"]), 1)
        self.assertEqual(len(data["llm_calls"]), 1)
        self.assertEqual(data["decision"]["score"], 12)
        self.assertFalse(data["disagreement_flag"])


class RawInputOptInTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.traces_dir = Path(self.tmp.name) / "traces"
        self.keyring_dir = Path(self.tmp.name) / "keyring"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_raw_input_not_persisted_by_default(self) -> None:
        t = _make_trace(self.traces_dir, self.keyring_dir, store_raw_mode="")
        t.record_raw_input("super secret message")
        path = t.seal(decision={"score": 0, "label": "harmless", "reasons": []})
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsNone(data["raw_input"])
        # But the hash and length are always stored
        self.assertIsNotNone(data["raw_input_sha256"])
        self.assertEqual(data["raw_input_length"], len("super secret message"))
        # Keyring was NOT created since opt-in disabled
        self.assertFalse((self.keyring_dir / KEY_FILENAME).exists())

    def test_raw_input_opt_in_is_encrypted_and_recoverable(self) -> None:
        t = _make_trace(
            self.traces_dir, self.keyring_dir, store_raw_mode="encrypted"
        )
        secret = "顧客への請求情報: 山田 太郎"
        t.record_raw_input(secret)
        path = t.seal(decision={"score": 0, "label": "harmless", "reasons": []})
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsNotNone(data["raw_input"])
        # Encrypted blob must NOT contain plaintext
        self.assertNotIn(secret, data["raw_input"])
        # Recoverable using the same keyring
        recovered = decrypt_raw_input(data["raw_input"], keyring_dir=self.keyring_dir)
        self.assertEqual(recovered, secret)

    def test_keyring_file_has_0600_perms(self) -> None:
        t = _make_trace(
            self.traces_dir, self.keyring_dir, store_raw_mode="encrypted"
        )
        t.record_raw_input("trigger key creation")
        t.seal(decision={"score": 0, "label": "harmless", "reasons": []})
        keyfile = self.keyring_dir / KEY_FILENAME
        self.assertTrue(keyfile.exists())
        mode = stat.S_IMODE(os.stat(keyfile).st_mode)
        self.assertEqual(mode, 0o600, f"unexpected perms: {oct(mode)}")


class AtomicWriteTest(unittest.TestCase):
    """Validate the .tmp -> rename pattern leaves no garbage on success."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.traces_dir = Path(self.tmp.name) / "traces"
        self.keyring_dir = Path(self.tmp.name) / "keyring"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_no_tmp_files_remain(self) -> None:
        t = _make_trace(self.traces_dir, self.keyring_dir)
        t.record_raw_input("x")
        t.seal(decision={"score": 0, "label": "harmless", "reasons": []})
        leftovers = list(self.traces_dir.glob(".trace-*.tmp"))
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
