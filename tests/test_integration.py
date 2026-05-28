"""
Integration tests for the full deduplication pipeline.

Uses a pre-normalized fixture derived from running Semgrep and ESLint
against OWASP Juice Shop v15.0.0 (see output/raw/ for the raw scan files).
The fixture contains 25 findings across both tools, with deliberate overlaps
to exercise the deduplicator.

Expected outcomes (based on the ground truth in evaluation/ground_truth.json):
  - Raw input       : 25 normalized findings
  - After dedup     : ~17 unique findings
  - Reduction rate  : >= 30%
  - Confidence range: [0.0, 1.0] for every finding
  - Multi-tool hits : higher avg confidence than single-tool hits
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from deduplicator import deduplicate_and_score

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "normalized_findings.json"
RAW_TOTAL = 26


@pytest.fixture(scope="module")
def raw_normalized():
    with open(FIXTURE_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def dedup_result(raw_normalized):
    processed, stats = deduplicate_and_score(raw_normalized)
    return processed, stats


def test_fixture_loads(raw_normalized):
    assert len(raw_normalized) == RAW_TOTAL, (
        f"Fixture should have {RAW_TOTAL} findings, got {len(raw_normalized)}"
    )


def test_duplicate_reduction_meets_target(dedup_result):
    """Must remove at least 30% of raw findings (project requirement)."""
    _, stats = dedup_result
    reduction_rate = stats["duplicates_removed"] / RAW_TOTAL
    assert reduction_rate >= 0.30, (
        f"Reduction rate {reduction_rate:.1%} is below the 30% target. "
        f"Duplicates removed: {stats['duplicates_removed']} / {RAW_TOTAL}"
    )


def test_output_smaller_than_input(dedup_result, raw_normalized):
    processed, stats = dedup_result
    assert len(processed) < len(raw_normalized), (
        "Processed list should be smaller than the raw input — duplicates exist in the fixture."
    )


def test_stats_count_is_consistent(dedup_result, raw_normalized):
    processed, stats = dedup_result
    assert stats["duplicates_removed"] == len(raw_normalized) - len(processed), (
        "stats['duplicates_removed'] does not match the actual difference in list lengths."
    )


def test_all_confidence_scores_in_range(dedup_result):
    processed, _ = dedup_result
    for finding in processed:
        score = finding.get("confidence", -1)
        assert 0.0 <= score <= 1.0, (
            f"Confidence score {score} out of [0, 1] range for finding: {finding.get('path')}"
        )


def test_all_required_schema_fields_present(dedup_result):
    """Every output finding must conform to the unified schema."""
    required = {"path", "line", "tool", "rule_id", "severity", "message", "confidence"}
    processed, _ = dedup_result
    for finding in processed:
        missing = required - finding.keys()
        assert not missing, (
            f"Finding at {finding.get('path')} is missing schema fields: {missing}"
        )


def test_multi_tool_findings_have_higher_avg_confidence(dedup_result):
    """
    The confidence formula weights tool agreement at 0.4, so findings
    detected by more than one tool must average higher than single-tool findings.
    """
    processed, _ = dedup_result
    single = [f for f in processed if len(f["tool"]) == 1]
    multi = [f for f in processed if len(f["tool"]) > 1]

    if not single or not multi:
        pytest.skip("Not enough data to compare single vs multi-tool confidence.")

    avg_single = sum(f["confidence"] for f in single) / len(single)
    avg_multi = sum(f["confidence"] for f in multi) / len(multi)

    assert avg_multi > avg_single, (
        f"Expected multi-tool avg confidence ({avg_multi:.3f}) > "
        f"single-tool avg confidence ({avg_single:.3f})"
    )


def test_severity_is_always_highest_after_merge(dedup_result, raw_normalized):
    """
    When two findings are merged, the merged severity must be the higher of the two.
    Checks this by inspecting merged findings (tool list length > 1).
    """
    from config.settings import SEVERITY_ORDER

    processed, _ = dedup_result
    merged = [f for f in processed if len(f["tool"]) > 1]

    raw_by_path_cwe = {}
    for r in raw_normalized:
        key = (r["path"], r["rule_id"])
        raw_by_path_cwe.setdefault(key, []).append(r["severity"])

    for finding in merged:
        key = (finding["path"], finding["rule_id"])
        if key not in raw_by_path_cwe:
            continue
        severities = raw_by_path_cwe[key]
        expected_max = max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))
        assert SEVERITY_ORDER.get(finding["severity"], 0) >= SEVERITY_ORDER.get(
            expected_max, 0
        ), (
            f"Merged finding at {finding['path']} has severity {finding['severity']} "
            f"but raw inputs had {severities}"
        )


def test_no_duplicate_path_cwe_pairs_in_output(dedup_result):
    """
    After deduplication, no two findings should share the same (path, rule_id)
    combination — that would mean a duplicate slipped through.
    """
    processed, _ = dedup_result
    seen = set()
    for finding in processed:
        key = (finding["path"], finding["rule_id"])
        assert key not in seen, (
            f"Duplicate (path, CWE) found in output: {key}"
        )
        seen.add(key)


def test_high_severity_findings_not_lost(dedup_result, raw_normalized):
    """
    HIGH severity findings from the raw input must all be represented in the output
    (possibly merged, but never silently dropped).
    """
    processed, _ = dedup_result
    raw_high = {
        (f["path"], f["rule_id"])
        for f in raw_normalized
        if f["severity"] == "HIGH"
    }
    output_cwes_by_path = {
        (f["path"], f["rule_id"]) for f in processed
    }
    for path_cwe in raw_high:
        assert path_cwe in output_cwes_by_path, (
            f"HIGH severity finding {path_cwe} was dropped from the output entirely."
        )
