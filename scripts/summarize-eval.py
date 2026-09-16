#!/usr/bin/env python3
"""Summarize synthetic TestDiagnosticCorpus records using the existing Go grader log.

Raw records contain synthetic credentials and stay in the explicitly chosen
artifact path. This summary contains counts, timings, hashes and case names only.
"""
import argparse
import collections
import hashlib
import json
import math
import re
import statistics
from pathlib import Path


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else 0


def summarize(records, log):
    states = {name: state.lower() for state, name in re.findall(
        r"^    --- (PASS|FAIL): TestDiagnosticCorpus/(\S+)", log, re.M)}
    # Legacy single-run assertions use an aggregate agreement gate in Go.
    # A subtest can therefore say PASS despite a wrong verdict. Count every
    # disagreement as a case failure here, using exact counts (not rounded %).
    for name, hits, total in re.findall(
            r"(\S+): agreement \d+% \((\d+)/(\d+)\) over \d+ run", log):
        if int(hits) != int(total):
            states[name] = "fail"
    names = {r["name"] for r in records}
    if names != set(states):
        raise ValueError("Diagnostic records and grader outcomes disagree; check incomplete runs")
    calls = [c for r in records for c in r["calls"] or []]
    latencies = [r["latency_ms"] for r in records]
    finishes = collections.Counter(
        choice.get("finish_reason", "")
        for c in calls for choice in c["response"].get("choices", []) or [])
    reasoning_calls = sum(any(
        x["message"].get("reasoning") or x["message"].get("reasoning_content")
        for x in c["response"].get("choices", []) or []) for c in calls)
    totals = {key: sum(c["response"].get("usage", {}).get(key, 0) for c in calls)
              for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
    errors = sum(bool(r["response"].get("stats", {}).get("deep_scan", {}).get("error"))
                 for r in records if isinstance(r["response"], dict))
    result = {
        "cases": len(names), "cases_passed_all_runs": sum(s == "pass" for s in states.values()),
        "requests": len(records), "model_calls": len(calls), "calls_with_reasoning": reasoning_calls,
        "recovery_calls": sum(any(
            m.get("role") == "user" and m.get("content", "").startswith(
                "The previous response was incomplete or invalid.")
            for m in c.get("request", {}).get("messages", [])) for c in calls),
        "http_errors": sum(r.get("http_status", 200) != 200 for r in records),
        "request_latency_ms": {"median": statistics.median(latencies) if latencies else 0,
                               "p95": percentile(latencies, .95),
                               "max": max(latencies, default=0)},
        "model_call_latency_ms": {"median": statistics.median([c["latency_ms"] for c in calls]) if calls else 0,
                                  "p95": percentile([c["latency_ms"] for c in calls], .95),
                                  "max": max((c["latency_ms"] for c in calls), default=0)},
        "usage": totals, "finish_reasons": dict(finishes), "deep_errors": errors,
        "failed_cases": sorted(n for n, s in states.items() if s == "fail"),
        "runs_per_case": dict(sorted(collections.Counter(r["name"] for r in records).items())),
        "model": sorted({r["model"] for r in records}),
        "thinking": sorted({r["thinking"] for r in records}),
        "prompt": sorted({r["prompt"] for r in records}),
        "prompt_deep": sorted({r["prompt_deep"] for r in records}),
        "fixture_hashes": {r["name"]: {"diff": r["diff_sha256"], "expectation": r["expectation_sha256"]}
                           for r in records},
    }
    result["stages"] = {}
    for stage in sorted({c["stage"] for c in calls}):
        group = [c for c in calls if c["stage"] == stage]
        result["stages"][stage] = {
            "calls": len(group),
            "latency_ms": {
                "median": statistics.median(c["latency_ms"] for c in group),
                "p95": percentile([c["latency_ms"] for c in group], .95),
                "max": max(c["latency_ms"] for c in group)},
            "usage": {key: sum(c["response"].get("usage", {}).get(key, 0) for c in group)
                      for key in totals},
            "transport_errors": sum(bool(c.get("error")) for c in group),
            "finish_reasons": dict(collections.Counter(
                x.get("finish_reason", "") for c in group
                for x in c["response"].get("choices", []) or [])),
        }
    for label, key in [("expanded secret recall", "credentials_found"), ("expanded clean scans", "clean_scans")]:
        match = re.search(label + r": (\d+)/(\d+)", log)
        if match:
            result[key] = {"passed": int(match[1]), "total": int(match[2])}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", type=Path)
    parser.add_argument("log", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raw = args.records.read_bytes()
    result = summarize([json.loads(line) for line in raw.splitlines()], args.log.read_text())
    result["records_sha256"] = hashlib.sha256(raw).hexdigest()
    result["log_sha256"] = hashlib.sha256(args.log.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("fixture_hashes", "runs_per_case")}, indent=2))


if __name__ == "__main__":
    main()
