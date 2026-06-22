"""
Unit tests for evaluation/metrics.py

Verifies that the matching logic, TP/FP/FN classification, and derived
metrics (precision, recall, F1, duplicate reduction rate) are computed
correctly across a range of controlled inputs.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.metrics import evaluate, matches_ground_truth

SAMPLE_GT = [
    {
        "id": "GT-01",
        "path": "routes/search.ts",
        "line": 42,
        "cwe": "CWE-89",
        "severity": "HIGH",
        "description": "SQL injection",
    },
    {
        "id": "GT-02",
        "path": "routes/fileServer.ts",
        "line": 30,
        "cwe": "CWE-22",
        "severity": "HIGH",
        "description": "Path traversal",
    },
    {
        "id": "GT-03",
        "path": "lib/insecurity.ts",
        "line": 8,
        "cwe": "CWE-326",
        "severity": "HIGH",
        "description": "Weak JWT secret",
    },
]


def _finding(path, line, cwe, severity="HIGH", tool=None):
    return {
        "path": path,
        "line": line,
        "rule_id": cwe,
        "severity": severity,
        "tool": tool or ["Semgrep"],
        "message": "test finding",
        "confidence": 0.7,
    }


class TestMatchesGroundTruth:
    def test_exact_match(self):
        f = _finding("routes/search.ts", 42, "CWE-89")
        assert matches_ground_truth(f, SAMPLE_GT[0]) is True

    def test_match_within_positive_tolerance(self):
        f = _finding("routes/search.ts", 50, "CWE-89")
        assert matches_ground_truth(f, SAMPLE_GT[0]) is True

    def test_match_within_negative_tolerance(self):
        f = _finding("routes/search.ts", 34, "CWE-89")
        assert matches_ground_truth(f, SAMPLE_GT[0]) is True

    def test_no_match_beyond_tolerance(self):
        f = _finding("routes/search.ts", 53, "CWE-89")
        assert matches_ground_truth(f, SAMPLE_GT[0]) is False

    def test_no_match_different_file(self):
        f = _finding("routes/other.ts", 42, "CWE-89")
        assert matches_ground_truth(f, SAMPLE_GT[0]) is False

    def test_no_match_different_cwe(self):
        f = _finding("routes/search.ts", 42, "CWE-22")
        assert matches_ground_truth(f, SAMPLE_GT[0]) is False

    def test_basename_comparison_ignores_absolute_path(self):
        f = _finding("/home/user/juice-shop/routes/search.ts", 42, "CWE-89")
        assert matches_ground_truth(f, SAMPLE_GT[0]) is True

    def test_none_line_does_not_crash(self):
        f = _finding("routes/search.ts", None, "CWE-89")
        result = matches_ground_truth(f, SAMPLE_GT[0])
        assert isinstance(result, bool)


class TestEvaluateClassification:
    def test_all_true_positives(self):
        findings = [
            _finding("routes/search.ts", 42, "CWE-89"),
            _finding("routes/fileServer.ts", 30, "CWE-22"),
            _finding("lib/insecurity.ts", 8, "CWE-326"),
        ]
        m = evaluate(findings, SAMPLE_GT, raw_count=3)
        assert m["true_positives"] == 3
        assert m["false_positives"] == 0
        assert m["false_negatives"] == 0

    def test_all_false_positives(self):
        findings = [
            _finding("routes/fake1.ts", 10, "CWE-79"),
            _finding("routes/fake2.ts", 20, "CWE-200"),
        ]
        m = evaluate(findings, SAMPLE_GT, raw_count=2)
        assert m["true_positives"] == 0
        assert m["false_positives"] == 2
        assert m["false_negatives"] == 3

    def test_all_false_negatives(self):
        m = evaluate([], SAMPLE_GT, raw_count=0)
        assert m["true_positives"] == 0
        assert m["false_positives"] == 0
        assert m["false_negatives"] == 3

    def test_mixed_classification(self):
        findings = [
            _finding("routes/search.ts", 42, "CWE-89"),
            _finding("routes/fake.ts", 5, "CWE-79"),
        ]
        m = evaluate(findings, SAMPLE_GT, raw_count=3)
        assert m["true_positives"] == 1
        assert m["false_positives"] == 1
        assert m["false_negatives"] == 2

    def test_same_gt_entry_not_counted_twice(self):
        findings = [
            _finding("routes/search.ts", 42, "CWE-89"),
            _finding("routes/search.ts", 43, "CWE-89"),
        ]
        m = evaluate(findings, SAMPLE_GT, raw_count=2)
        assert m["true_positives"] == 1
        assert m["false_positives"] == 1


class TestEvaluateDerivedMetrics:
    def test_perfect_precision_and_recall(self):
        findings = [
            _finding("routes/search.ts", 42, "CWE-89"),
            _finding("routes/fileServer.ts", 30, "CWE-22"),
            _finding("lib/insecurity.ts", 8, "CWE-326"),
        ]
        m = evaluate(findings, SAMPLE_GT, raw_count=3)
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["f1_score"] == 1.0

    def test_precision_calculation(self):
        findings = [
            _finding("routes/search.ts", 42, "CWE-89"),
            _finding("routes/fake.ts", 5, "CWE-79"),
        ]
        m = evaluate(findings, SAMPLE_GT, raw_count=3)
        assert abs(m["precision"] - 0.5) < 0.01

    def test_recall_calculation(self):
        findings = [_finding("routes/search.ts", 42, "CWE-89")]
        m = evaluate(findings, SAMPLE_GT, raw_count=3)
        assert abs(m["recall"] - (1 / 3)) < 0.01

    def test_f1_is_harmonic_mean(self):
        findings = [
            _finding("routes/search.ts", 42, "CWE-89"),
            _finding("routes/fake.ts", 5, "CWE-79"),
        ]
        m = evaluate(findings, SAMPLE_GT, raw_count=3)
        p, r = m["precision"], m["recall"]
        expected_f1 = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0
        assert abs(m["f1_score"] - expected_f1) < 0.001

    def test_zero_division_safe_when_no_findings(self):
        m = evaluate([], SAMPLE_GT, raw_count=0)
        assert m["precision"] == 0.0
        assert m["recall"] == 0.0
        assert m["f1_score"] == 0.0


class TestDuplicateReductionRate:
    def test_thirty_percent_reduction(self):
        findings = [_finding("routes/search.ts", 42, "CWE-89")]
        m = evaluate(findings, SAMPLE_GT, raw_count=10)
        assert m["raw_count"] == 10
        assert m["processed_count"] == 1
        assert m["duplicates_removed"] == 9
        assert abs(m["duplicate_reduction_rate"] - 0.9) < 0.001

    def test_no_reduction_when_counts_equal(self):
        findings = [
            _finding("routes/search.ts", 42, "CWE-89"),
            _finding("routes/fileServer.ts", 30, "CWE-22"),
        ]
        m = evaluate(findings, SAMPLE_GT, raw_count=2)
        assert m["duplicate_reduction_rate"] == 0.0

    def test_reduction_rate_meets_project_target(self):
        """Simulate the Juice Shop scenario: 25 raw → 17 processed = 32% reduction."""
        findings = [_finding(f"routes/file{i}.ts", i * 5, "CWE-89") for i in range(17)]
        m = evaluate(findings, [], raw_count=25)
        assert m["duplicate_reduction_rate"] >= 0.30

    def test_zero_raw_count_does_not_crash(self):
        m = evaluate([], [], raw_count=0)
        assert m["duplicate_reduction_rate"] == 0.0


class TestEvaluateOutputStructure:
    def test_all_expected_keys_present(self):
        m = evaluate([], SAMPLE_GT, raw_count=0)
        expected_keys = {
            "raw_count", "processed_count", "duplicates_removed",
            "duplicate_reduction_rate", "true_positives", "false_positives",
            "false_negatives", "precision", "recall", "f1_score",
            "tp_findings", "fp_findings", "fn_ground_truth",
        }
        assert expected_keys.issubset(m.keys())

    def test_fn_ids_are_strings(self):
        m = evaluate([], SAMPLE_GT, raw_count=0)
        assert all(isinstance(i, str) for i in m["fn_ground_truth"])

    def test_tp_ids_match_ground_truth_ids(self):
        findings = [_finding("routes/search.ts", 42, "CWE-89")]
        m = evaluate(findings, SAMPLE_GT, raw_count=1)
        assert "GT-01" in m["tp_findings"]
