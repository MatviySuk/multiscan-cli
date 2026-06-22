import pytest

from deduplicator import location_match, is_duplicate, deduplicate_and_score


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ({"path": "app.py", "line": 10}, {"path": "app.py", "line": 14}, True),
        ({"path": "app.py", "line": 10}, {"path": "app.py", "line": 15}, True),
        ({"path": "app.py", "line": 10}, {"path": "app.py", "line": 20}, False),
        ({"path": "utils.py", "line": 10}, {"path": "db.py", "line": 12}, False),
    ],
)
def test_location_match(a, b, expected):
    assert location_match(a, b) == expected


def _finding(tool, path, line, rule_id, severity, message):
    return {
        "path": path,
        "line": line,
        "tool": [tool],
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "confidence": 0.0,
    }


def test_bandit_and_semgrep_subprocess_findings_merge():
    """Bandit B602 and Semgrep subprocess-shell-true at the same spot should collapse."""
    bandit = _finding(
        "Bandit", "app/utils.py", 42, "CWE-78", "HIGH",
        "subprocess call with shell=True identified",
    )
    semgrep = _finding(
        "Semgrep", "app/utils.py", 42, "CWE-78", "HIGH",
        "subprocess call with shell=True is dangerous",
    )

    processed, stats = deduplicate_and_score([bandit, semgrep])

    assert len(processed) == 1
    assert stats["duplicates_removed"] == 1
    assert set(processed[0]["tool"]) == {"Bandit", "Semgrep"}


def test_cross_tool_merge_lifts_confidence():
    semgrep_solo = _finding(
        "Semgrep", "lone.py", 5, "CWE-22", "HIGH",
        "path traversal via open() call on user-controlled string",
    )
    pair_a = _finding("Semgrep", "x.py", 10, "CWE-89", "HIGH", "sql injection here")
    pair_b = _finding("Bandit", "x.py", 11, "CWE-89", "HIGH", "sql injection-like here")

    processed, _ = deduplicate_and_score([semgrep_solo, pair_a, pair_b])

    merged = [f for f in processed if len(f["tool"]) > 1]
    solo = [f for f in processed if len(f["tool"]) == 1]
    assert merged, "expected at least one merged finding"
    assert solo, "expected at least one single-tool finding"
    assert max(f["confidence"] for f in merged) > max(f["confidence"] for f in solo)


def test_different_cwe_same_line_not_a_duplicate():
    a = _finding("Semgrep", "f.py", 10, "CWE-89", "HIGH", "SQL injection")
    b = _finding("Semgrep", "f.py", 10, "CWE-22", "HIGH", "path traversal")
    processed, _ = deduplicate_and_score([a, b])
    assert len(processed) == 2
