"""Eval CLI — Issues #8 and #9.

Subcommands:
  validate  Validate tests/cases.jsonl against the schema
  run       Run the agent over every case, record outcomes + metrics
  diff      Compare two .eval/run-*.json files

Run output is written to ``.eval/run-<ISO-ts>.json`` and a human-readable
table is printed to stdout. Disagreement-flagged cases are also written
to ``.eval/disagreement.jsonl`` for review queueing.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# Make ``app`` importable when run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import llm, versions  # noqa: E402
from app.eval_schema import (  # noqa: E402
    ATTACK_LABELS,
    CATEGORIES,
    count_by_subcategory,
    count_diff_warnings,
    validate_record,
    validate_uniqueness,
)

EVAL_DIR = Path(".eval")


# ---------- shared helpers ----------


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _load_cases(path: Path) -> list[dict]:
    records: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            stripped = raw.strip()
            if not stripped:
                continue
            records.append(json.loads(stripped))
    return records


# ---------- pass logic ----------


def _check_pass(case: dict, decision: dict) -> tuple[bool, list[str]]:
    """Return (pass, failure_reasons)."""
    failures: list[str] = []
    score = decision["score"]
    label = decision["label"]
    reasons_text = " ".join(decision.get("reasons", []))
    exp = case["expected"]
    smin, smax = exp["score_min"], exp["score_max"]
    expected_label = exp["label"]
    category = case["category"]

    # legit_but_suspicious uses relaxed pass rule (any attack label = FP)
    if category == "legit_but_suspicious":
        if score > smax:
            failures.append(f"score {score} > max {smax}")
        if label in ATTACK_LABELS:
            failures.append(f"label {label!r} treated as attack (FP)")
    else:
        if not (smin <= score <= smax):
            failures.append(f"score {score} outside [{smin},{smax}]")
        if label != expected_label:
            failures.append(f"label {label!r} != expected {expected_label!r}")

    must = case.get("must_contain_reason_keywords") or []
    if must:
        if not any(kw in reasons_text for kw in must):
            failures.append(f"reasons missing any of {must}")

    must_not = case.get("must_not_contain_reason_keywords") or []
    for kw in must_not:
        if kw in reasons_text:
            failures.append(f"reasons unexpectedly contain {kw!r}")

    return (not failures), failures


# ---------- metrics ----------


def _is_attack_expected(case: dict) -> bool:
    cat = case["category"]
    return cat in {"phishing", "fraud", "manipulation", "prompt_injection"}


def _compute_metrics(per_case: list[dict]) -> dict:
    by_cat_total: dict[str, int] = defaultdict(int)
    by_cat_pass: dict[str, int] = defaultdict(int)
    by_cat_tp: dict[str, int] = defaultdict(int)
    by_cat_fn: dict[str, int] = defaultdict(int)
    fp_total = 0
    fp_eligible_total = 0  # cases that COULD be FP (expected harmless/legit_but_suspicious)
    overall_tp = 0
    overall_fp = 0
    overall_fn = 0

    for r in per_case:
        case = r["case"]
        decision = r["decision"]
        cat = case["category"]
        by_cat_total[cat] += 1
        if r["pass"]:
            by_cat_pass[cat] += 1

        # FP tracking (only on harmless / legit_but_suspicious)
        if cat in {"harmless", "legit_but_suspicious"}:
            fp_eligible_total += 1
            if decision["label"] in ATTACK_LABELS:
                fp_total += 1
                overall_fp += 1
        # TP / FN on attack-expected categories
        elif _is_attack_expected(case):
            expected_label = case["expected"]["label"]
            if decision["label"] == expected_label:
                by_cat_tp[cat] += 1
                overall_tp += 1
            else:
                by_cat_fn[cat] += 1
                overall_fn += 1

    by_category = {}
    for cat in CATEGORIES:
        total = by_cat_total.get(cat, 0)
        passed = by_cat_pass.get(cat, 0)
        entry = {
            "n": total,
            "pass": passed,
            "pass_rate": (passed / total) if total else None,
        }
        if cat in {"phishing", "fraud", "manipulation", "prompt_injection"}:
            tp = by_cat_tp.get(cat, 0)
            fn = by_cat_fn.get(cat, 0)
            # Per-category recall: TP / (TP + FN)
            entry["recall"] = (tp / (tp + fn)) if (tp + fn) else None
        by_category[cat] = entry

    overall_precision = (
        overall_tp / (overall_tp + overall_fp) if (overall_tp + overall_fp) else None
    )
    overall_recall = (
        overall_tp / (overall_tp + overall_fn) if (overall_tp + overall_fn) else None
    )
    fp_rate = (fp_total / fp_eligible_total) if fp_eligible_total else None

    return {
        "by_category": by_category,
        "overall": {
            "n": len(per_case),
            "pass": sum(1 for r in per_case if r["pass"]),
            "precision": overall_precision,
            "recall": overall_recall,
            "fp_rate": fp_rate,
            "fp_count": fp_total,
            "tp_count": overall_tp,
            "fn_count": overall_fn,
        },
    }


# ---------- subcommands ----------


def cmd_validate(args: argparse.Namespace) -> int:
    if not args.cases.exists():
        print(f"error: file not found: {args.cases}", file=sys.stderr)
        return 2
    records: list[dict] = []
    errors: list[str] = []
    with args.cases.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                rec = json.loads(stripped)
            except json.JSONDecodeError as e:
                errors.append(f"line {line_no}: invalid JSON ({e.msg})")
                continue
            records.append(rec)
            for verr in validate_record(rec, line_number=line_no):
                errors.append(verr.format())
    for verr in validate_uniqueness(records):
        errors.append(verr.format())

    warnings = count_diff_warnings(count_by_subcategory(records))
    print(f"validated {len(records)} record(s) from {args.cases}")
    if warnings:
        print(f"\n{len(warnings)} count warning(s):")
        for w in warnings:
            print(f"  - {w}")
    if errors:
        print(f"\n{len(errors)} validation error(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("\nOK: all records valid")
    return 0


async def _run_async(args: argparse.Namespace) -> int:
    cases = _load_cases(args.cases)
    if args.category:
        wanted = {c.strip() for c in args.category.split(",") if c.strip()}
        cases = [c for c in cases if c["category"] in wanted]
    if args.limit:
        cases = cases[: args.limit]
    if not cases:
        print("error: no cases match the filter", file=sys.stderr)
        return 2

    print(
        f"Running eval: {len(cases)} case(s) | agent={versions.AGENT_VERSION} "
        f"prompt={versions.PROMPT_VERSION} model={llm.MODEL}"
    )

    sem = asyncio.Semaphore(max(1, args.parallel))

    async def _one(case: dict) -> dict:
        async with sem:
            t0 = time.monotonic()
            try:
                resp = await llm.analyze(case["input"])
                decision = {
                    "score": resp.score,
                    "label": resp.label,
                    "reasons": resp.reasons,
                }
                trace_id = resp.trace_id
                disagreement = resp.disagreement_flag
                err = None
            except llm.LLMError as e:
                decision = {"score": 0, "label": "other", "reasons": [f"LLMError: {e}"]}
                trace_id = ""
                disagreement = False
                err = str(e)
            latency_ms = int((time.monotonic() - t0) * 1000)
            passed, failures = _check_pass(case, decision)
            return {
                "case_id": case["id"],
                "category": case["category"],
                "subcategory": case["subcategory"],
                "case": case,
                "decision": decision,
                "trace_id": trace_id,
                "disagreement_flag": disagreement,
                "latency_ms": latency_ms,
                "pass": passed,
                "failure_reasons": failures,
                "error": err,
            }

    per_case: list[dict] = []
    completed = 0
    tasks = [asyncio.create_task(_one(c)) for c in cases]
    for fut in asyncio.as_completed(tasks):
        r = await fut
        per_case.append(r)
        completed += 1
        marker = "PASS" if r["pass"] else "FAIL"
        print(
            f"  [{completed:>3}/{len(cases)}] {marker} {r['case_id']:<14} "
            f"score={r['decision']['score']:>3} label={r['decision']['label']:<20} "
            f"({r['latency_ms']:>5}ms)"
        )
    per_case.sort(key=lambda r: r["case_id"])

    metrics = _compute_metrics(per_case)

    run_id = _now_iso().replace(":", "").replace("-", "")
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVAL_DIR / f"run-{run_id}.json"
    payload = {
        "run_id": run_id,
        "started_at": _now_iso(),
        "agent_version": versions.AGENT_VERSION,
        "prompt_version": versions.PROMPT_VERSION,
        "model": llm.MODEL,
        "results": per_case,
        "summary": metrics,
    }
    out_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    disagreements = [r for r in per_case if r["disagreement_flag"]]
    if disagreements:
        dq_path = EVAL_DIR / "disagreement.jsonl"
        with dq_path.open("a", encoding="utf-8") as fh:
            for r in disagreements:
                fh.write(json.dumps({
                    "run_id": run_id, "case_id": r["case_id"],
                    "decision": r["decision"], "trace_id": r["trace_id"],
                }, ensure_ascii=False) + "\n")

    _print_summary(metrics, run_id, out_path, len(disagreements))
    return 0


def _print_summary(metrics: dict, run_id: str, out_path: Path, disagree_n: int) -> None:
    print(
        f"\nRun: {run_id}  agent={versions.AGENT_VERSION}  "
        f"prompt={versions.PROMPT_VERSION}  model={llm.MODEL}"
    )
    print("─" * 72)
    print(f"{'Category':<22} {'N':>4} {'Pass':>5} {'Rate':>7} {'Recall':>8}")
    print("─" * 72)
    for cat, e in metrics["by_category"].items():
        if e["n"] == 0:
            continue
        rate = f"{e['pass_rate']:.0%}" if e["pass_rate"] is not None else "—"
        recall = (
            f"{e['recall']:.0%}" if e.get("recall") is not None else "—"
        )
        print(f"{cat:<22} {e['n']:>4} {e['pass']:>5} {rate:>7} {recall:>8}")
    print("─" * 72)
    o = metrics["overall"]
    prec = f"{o['precision']:.0%}" if o["precision"] is not None else "—"
    rec = f"{o['recall']:.0%}" if o["recall"] is not None else "—"
    fp_rate = f"{o['fp_rate']:.1%}" if o["fp_rate"] is not None else "—"
    print(
        f"{'Overall':<22} {o['n']:>4} {o['pass']:>5}  "
        f"precision={prec} recall={rec} fp_rate={fp_rate} "
        f"(TP={o['tp_count']} FP={o['fp_count']} FN={o['fn_count']})"
    )
    print(f"\nDisagreement flagged: {disagree_n} case(s)")
    print(f"Run written: {out_path}")


def cmd_run(args: argparse.Namespace) -> int:
    if not args.cases.exists():
        print(f"error: file not found: {args.cases}", file=sys.stderr)
        return 2
    return asyncio.run(_run_async(args))


def cmd_diff(args: argparse.Namespace) -> int:
    a = json.loads(args.run_a.read_text(encoding="utf-8"))
    b = json.loads(args.run_b.read_text(encoding="utf-8"))
    by_id_a = {r["case_id"]: r for r in a["results"]}
    by_id_b = {r["case_id"]: r for r in b["results"]}
    common = sorted(set(by_id_a) & set(by_id_b))
    flipped_to_fail = []
    flipped_to_pass = []
    for cid in common:
        if by_id_a[cid]["pass"] and not by_id_b[cid]["pass"]:
            flipped_to_fail.append(cid)
        elif not by_id_a[cid]["pass"] and by_id_b[cid]["pass"]:
            flipped_to_pass.append(cid)
    print(f"A: {args.run_a}  (n={len(by_id_a)})")
    print(f"B: {args.run_b}  (n={len(by_id_b)})")
    print(f"pass→fail: {len(flipped_to_fail)}  fail→pass: {len(flipped_to_pass)}")
    if flipped_to_fail:
        print("  regressed:")
        for cid in flipped_to_fail:
            print(f"    - {cid}: {by_id_b[cid]['failure_reasons']}")
    if flipped_to_pass:
        print("  fixed:")
        for cid in flipped_to_pass:
            print(f"    + {cid}")

    oa, ob = a["summary"]["overall"], b["summary"]["overall"]

    def _fmt(v):
        return f"{v:.1%}" if isinstance(v, float) else str(v)

    def _delta(va, vb):
        if va is None or vb is None:
            return "—"
        return f"{vb - va:+.1%}" if isinstance(va, float) else f"{vb - va:+d}"

    print("\nOverall delta:")
    for k in ("pass", "precision", "recall", "fp_rate"):
        print(f"  {k:<10} {_fmt(oa.get(k))} -> {_fmt(ob.get(k))} ({_delta(oa.get(k), ob.get(k))})")
    return 0


# ---------- argparse ----------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    sub = p.add_subparsers(dest="cmd", required=True)

    vp = sub.add_parser("validate", help="Validate case file schema")
    vp.add_argument("--cases", type=Path, default=Path("tests/cases.jsonl"))
    vp.set_defaults(func=cmd_validate)

    rp = sub.add_parser("run", help="Run the agent over every case")
    rp.add_argument("--cases", type=Path, default=Path("tests/cases.jsonl"))
    rp.add_argument("--category", default="", help="Comma-separated category filter")
    rp.add_argument("--parallel", type=int, default=1)
    rp.add_argument("--limit", type=int, default=0)
    rp.set_defaults(func=cmd_run)

    dp = sub.add_parser("diff", help="Compare two run files")
    dp.add_argument("run_a", type=Path)
    dp.add_argument("run_b", type=Path)
    dp.set_defaults(func=cmd_diff)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
