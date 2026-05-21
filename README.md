# 🕵️ local-suspicion-agent

> **Trust nothing. Analyze everything. 100% offline.**
> A paranoid-by-design LLM agent that treats *every* input as a potential attack — and tells you why.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Local-only](https://img.shields.io/badge/network-offline-success)](#-security-by-design)
[![Powered by Ollama](https://img.shields.io/badge/LLM-Ollama-black)](https://ollama.com)

---

## ✨ Why this exists

Most LLM safety tools assume good faith. `local-suspicion-agent` does the opposite.
It is a **"guilty-until-proven-innocent"** agent that scans any text — emails, DMs, prompts pasted by users, scraped web content — and returns a **risk score (0–100)**, a **threat label**, and a **bulleted list of red flags**.

Everything runs on your machine. No API keys. No telemetry. No data leaves your laptop.

Perfect for:

- 🛡️ **Phishing / social-engineering triage** before clicking that link
- 🧪 **Prompt-injection detection** for LLM apps you're building
- 🔍 **Security research & red-team training data labeling**
- 🤐 **Privacy-sensitive workflows** where cloud LLMs are off the table

## 🎯 Features

- 🔒 **Fully local** — bound to `127.0.0.1`, zero outbound calls, audited dependency tree
- ⚡ **Tiny footprint** — runs on 3B–7B models via [Ollama](https://ollama.com) (works on a MacBook Air)
- 🧠 **Structured JSON output** — `score`, `label`, `reasons[]` — easy to pipe into anything
- 🏷️ **Threat taxonomy** — `phishing` / `fraud` / `manipulation` / `prompt_injection` / `harmless` / `other`
- 🧩 **One-file LLM backend** — swap Ollama for `llama.cpp`, `vLLM`, etc. by editing a single module
- 🪶 **~300 lines of code** — read it, audit it, fork it in an afternoon

## 🚀 Quickstart

```bash
# 1. Get a local model running
brew install ollama
ollama serve &
ollama pull qwen2.5:7b   # strong Japanese / multilingual; ~4.7GB

# 2. Install
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. Launch
./run.sh
# → open http://127.0.0.1:8765/
```

Paste any text, hit **解析する**, and watch the agent dissect it.

## 📡 API

```bash
curl -X POST http://127.0.0.1:8765/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"Urgent! Click here to verify your bank account before 24h..."}'
```

```json
{
  "score": 92,
  "label": "phishing",
  "reasons": [
    "Creates artificial urgency ('24h deadline')",
    "Requests sensitive financial action via a link",
    "No verifiable sender identity"
  ]
}
```

## 🔐 Security by design

| Guarantee | How |
|---|---|
| No external network calls | Server binds `127.0.0.1` only; LLM is local Ollama |
| No input data leaves the machine | Logs record length only, never content |
| Auditable dependencies | 4 direct deps, all permissive (MIT / BSD / Apache-2.0); CI-friendly `pip-audit` clean |
| Replaceable LLM backend | All model I/O lives in [`app/llm.py`](app/llm.py) |

## 🧱 Project layout

```
app/
  main.py       # FastAPI entry
  llm.py        # Local LLM call (swap me)
  prompts.py    # The "assume everything is hostile" system prompt
  schemas.py    # Pydantic I/O
static/
  index.html    # Minimal UI
```

## ⚙️ Configuration

| Env var | Default | Purpose |
|---|---|---|
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Local Ollama endpoint |
| `SUSPICION_MODEL` | `qwen2.5:7b` | Any Ollama-pulled model. For weaker hardware try `llama3.2:3b` (lower recall on JP phishing) |

## 🗺️ Roadmap

- [ ] Batch / file-drop analysis
- [ ] CLI mode (`suspicion < message.txt`)
- [ ] llama.cpp backend out of the box
- [ ] Browser extension that scans selected text
- [ ] Optional Tauri desktop bundle

PRs welcome — especially adversarial prompt examples for the eval set.

## 🤝 Contributing

Open an issue with a tricky input the agent misclassifies. Adversarial examples are the best contribution.

## 📜 License

MIT © 2026 **suzuki-black** — see [LICENSE](LICENSE).

---

<a id="ja"></a>

# 🕵️ local-suspicion-agent (日本語)

> **何も信用しない。すべてを解析する。完全オフライン。**
> あらゆる入力を「攻撃かもしれない」と仮定して解析する、性悪説 LLM エージェント。

## ✨ なぜ作ったか

世の中の LLM 安全装置はだいたい「性善説」で動いています。本プロジェクトはその逆 — **「攻撃と証明されるまで攻撃とみなす」** エージェントです。
任意のテキスト（メール、DM、ユーザー入力、スクレイピング結果など）を解析し、**危険度スコア (0〜100)**、**分類ラベル**、**疑わしい点のリスト**を返します。

すべてローカルで動作。API キー不要。テレメトリなし。データはマシンから出ません。

こんな用途に：

- 🛡️ クリック前のフィッシング / ソーシャルエンジニアリング検知
- 🧪 自作 LLM アプリのプロンプトインジェクション対策
- 🔍 セキュリティ研究・レッドチーム用ラベリング
- 🤐 クラウド LLM が使えない機密ワークフロー

## 🎯 特長

- 🔒 **完全ローカル** — `127.0.0.1` バインド、外部通信ゼロ、依存ツリー監査済み
- ⚡ **軽量** — [Ollama](https://ollama.com) の 3B〜7B モデルで動作（MacBook Air で動く）
- 🧠 **構造化 JSON 出力** — `score` / `label` / `reasons[]` でパイプ加工が容易
- 🏷️ **脅威タクソノミ** — `phishing` / `fraud` / `manipulation` / `prompt_injection` / `harmless` / `other`
- 🧩 **1 ファイルの LLM バックエンド** — `llama.cpp` / `vLLM` 等への差し替えは 1 モジュールのみ
- 🪶 **約 300 行** — 読める、監査できる、午後の半日でフォークできる

## 🚀 クイックスタート

```bash
# 1. ローカルモデル準備
brew install ollama
ollama serve &
ollama pull qwen2.5:7b   # strong Japanese / multilingual; ~4.7GB

# 2. インストール
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. 起動
./run.sh
# → http://127.0.0.1:8765/ をブラウザで開く
```

## 📡 API 例

```bash
curl -X POST http://127.0.0.1:8765/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"【緊急】24時間以内に銀行口座をご確認ください..."}'
```

```json
{
  "score": 92,
  "label": "phishing",
  "reasons": [
    "人為的な緊急性の演出（24時間以内）",
    "リンク経由での金融操作を要求",
    "送信者の検証可能な身元情報なし"
  ]
}
```

## 🔐 セキュリティ設計

| 保証 | 実装 |
|---|---|
| 外部通信なし | サーバを `127.0.0.1` バインド、LLM はローカル Ollama |
| 入力本文を外に出さない | ログは長さのみ記録、本文は保存しない |
| 依存の監査 | 直接依存 4 個、全て寛容ライセンス、`pip-audit` クリーン |
| LLM バックエンド差し替え可能 | モデル I/O は [`app/llm.py`](app/llm.py) に集約 |

## ⚙️ 環境変数

| 変数 | 既定値 | 用途 |
|---|---|---|
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama エンドポイント |
| `SUSPICION_MODEL` | `qwen2.5:7b` | 使用モデル。軽量化したい場合は `llama3.2:3b`（ただし日本語フィッシング検出の再現率は下がる） |

## 🗺️ ロードマップ

- [ ] バッチ / ファイル解析
- [ ] CLI モード (`suspicion < message.txt`)
- [ ] llama.cpp バックエンド標準対応
- [ ] 選択テキストをスキャンするブラウザ拡張
- [ ] Tauri デスクトップ版

## 🤝 コントリビュート

「誤判定するトリッキーな入力」を Issue で投げてください。敵対的サンプルが一番ありがたい貢献です。

## 📜 ライセンス

MIT © 2026 **suzuki-black** — [LICENSE](LICENSE) を参照。
