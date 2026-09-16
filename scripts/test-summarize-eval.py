"""Offline checks for strict diagnostic summary scoring."""
import importlib.util
import unittest
import sys
from pathlib import Path

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location(
    "summary", Path(__file__).with_name("summarize-eval.py"))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


def record(name="fixture", run=1):
    return {"name": name, "run": run, "calls": [], "latency_ms": 10,
            "response": {}, "model": "synthetic", "thinking": "off",
            "prompt": "a", "prompt_deep": "b", "diff_sha256": "c",
            "expectation_sha256": "d"}


class SummaryTest(unittest.TestCase):
    def test_rounded_agreement_does_not_hide_legacy_error(self):
        log = """    integration_test.go:1: fixture: agreement 100% (999/1000) over 20 run(s)
    --- PASS: TestDiagnosticCorpus/fixture (0.1s)
"""
        result = summary.summarize([record(run=n) for n in range(1, 21)], log)
        self.assertEqual(result["cases_passed_all_runs"], 0)
        self.assertEqual(result["failed_cases"], ["fixture"])
        self.assertEqual(result["requests"], 20)

    def test_hard_error_stays_failed_despite_agreement(self):
        log = """    integration_test.go:1: fixture: agreement 100% (4/4) over 1 run(s)
    --- FAIL: TestDiagnosticCorpus/fixture (0.1s)
"""
        self.assertEqual(summary.summarize([record()], log)["failed_cases"], ["fixture"])

    def test_incomplete_grader_log_is_rejected(self):
        with self.assertRaises(ValueError):
            summary.summarize([record()], "=== RUN TestDiagnosticCorpus/fixture")

    def test_stage_totals_and_tail_latency(self):
        row = record()
        row["calls"] = [
            {"stage": "adjudication", "latency_ms": 12, "response": {
                "choices": [{"finish_reason": "stop", "message": {"reasoning": "synthetic"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13}}},
            {"stage": "deep", "latency_ms": 24, "response": {
                "choices": [{"finish_reason": "length", "message": {}}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 7, "total_tokens": 27}}}]
        result = summary.summarize([row], "    --- PASS: TestDiagnosticCorpus/fixture (0.1s)")
        self.assertEqual(result["usage"]["total_tokens"], 40)
        self.assertEqual(result["calls_with_reasoning"], 1)
        self.assertEqual(result["model_call_latency_ms"]["max"], 24)
        self.assertEqual(result["stages"]["deep"]["usage"]["completion_tokens"], 7)
        self.assertEqual(result["stages"]["adjudication"]["finish_reasons"], {"stop": 1})

    def test_clean_run_passes(self):
        log = """    integration_test.go:1: fixture: agreement 100% (4/4) over 1 run(s)
    --- PASS: TestDiagnosticCorpus/fixture (0.1s)
"""
        self.assertEqual(summary.summarize([record()], log)["cases_passed_all_runs"], 1)


if __name__ == "__main__":
    unittest.main()
