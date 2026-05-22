# `tests/cases.jsonl` schema

One JSON object per line. All fields required (use `null` explicitly for optional).
Validated by `python scripts/eval.py validate`.

## Fields

| Field | Type | Notes |
|---|---|---|
| `id` | string | Unique. Pattern: `<category-prefix>-NNN`. e.g. `phish-001`, `inj-007` |
| `category` | enum | `phishing` \| `fraud` \| `manipulation` \| `prompt_injection` \| `harmless` \| `legit_but_suspicious` |
| `subcategory` | string | See table below |
| `input` | string | Raw text to analyze. 1..4000 chars |
| `expected.score_min` | int | 0..100 |
| `expected.score_max` | int | 0..100, >= `score_min` |
| `expected.label` | enum | `phishing` \| `fraud` \| `manipulation` \| `prompt_injection` \| `harmless` \| `other` |
| `must_contain_reason_keywords` | list[string] \| null | If non-null, at least one must appear in any `reasons[]` entry |
| `must_not_contain_reason_keywords` | list[string] \| null | None of these may appear |
| `notes` | string | Free-text rationale / provenance |
| `source` | enum | `synthetic` \| `real_anonymized` \| `claude` \| `copilot` \| `human` |
| `added_at` | string | ISO date `YYYY-MM-DD` |
| `schema_version` | int | Currently `1` |

## Targets (100 cases total)

| Category | Count | Subcategories (count) |
|---|---|---|
| `phishing` | 30 | `delivery_sms` (8), `bank_alert` (8), `prize_lottery` (4), `credential_reset` (5), `tax_govt` (5) |
| `fraud` | 15 | `investment` (5), `romance` (3), `refund` (3), `invoice` (4) |
| `manipulation` | 10 | `urgency` (3), `authority` (3), `reciprocity` (2), `fear` (2) |
| `prompt_injection` | 15 | `instruction` (3), `system_spoof` (2), `ignore_previous` (3), `tag_escape` (2), `jailbreak` (2), `persona_hijack` (3) |
| `harmless` | 15 | `meeting_notice` (5), `casual_chat` (5), `product_announce` (5) |
| `legit_but_suspicious` | 15 | `boss_urgency` (3), `intro_referral` (2), `real_password_reset` (2), `internal_irregular` (2), `govt_legit` (3), `vendor_invoice_legit` (3) |

## Default expected-score ranges

| Category | score_min | score_max | label |
|---|---|---|---|
| `phishing` | 60 | 100 | `phishing` |
| `fraud` | 60 | 100 | `fraud` |
| `manipulation` | 40 | 90 | `manipulation` |
| `prompt_injection` | 70 | 100 | `prompt_injection` |
| `harmless` | 0 | 20 | `harmless` |
| `legit_but_suspicious` | 0 | 50 | `harmless` *or* `other` (any attack label = FP) |

## Authorship

| Author | Count | Scope |
|---|---|---|
| claude | 50 | phishing (30), fraud (15), harmless (5) |
| copilot | 30 | prompt_injection (15), manipulation (10), harmless (5) |
| human (project owner) | 20 | legit_but_suspicious (15), harmless (5) |

`prompt_injection` is authored by Copilot specifically to decorrelate from the
Claude/qwen2.5 generation lineage used at inference time.
`legit_but_suspicious` must be human-authored to retain realistic business tone.

## Example

```json
{"id":"phish-001","category":"phishing","subcategory":"delivery_sms","input":"【ヤマト運輸】お荷物のお届けにあがりましたが不在のため持ち帰りました。再配達はこちらから: http://yamato-redelivery.example/r/8821","expected":{"score_min":60,"score_max":100,"label":"phishing"},"must_contain_reason_keywords":["URL"],"must_not_contain_reason_keywords":null,"notes":"Yamato 偽装 SMS 典型例","source":"claude","added_at":"2026-05-22","schema_version":1}
```
