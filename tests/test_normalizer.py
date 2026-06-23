"""Tests for the Bandit/Semgrep/ESLint parsers in normalizer.py."""

import pytest
from normalizer import (
    parse_bandit,
    parse_semgrep,
    parse_eslint,
    normalize_all,
    _normalize_severity_bandit,
    _normalize_severity_semgrep,
    _normalize_severity_eslint,
    _extract_cwe_semgrep,
    _make_path_relative,
)


def bandit_result(**overrides):
    """Return a minimal valid Bandit result dict, with optional overrides."""
    base = {
        "filename": "app/utils.py",
        "line_number": 42,
        "test_id": "B602",
        "issue_severity": "HIGH",
        "issue_text": "subprocess call with shell=True identified.",
    }
    base.update(overrides)
    return base


def semgrep_result(**overrides):
    """Return a minimal valid Semgrep result dict, with optional overrides."""
    base = {
        "path": "app/db.py",
        "start": {"line": 17},
        "check_id": "python.django.security.injection.sql",
        "extra": {
            "message": "Possible SQL injection via string formatting",
            "severity": "ERROR",
            "metadata": {"cwe": ["CWE-89: SQL Injection"]},
        },
    }
    base.update(overrides)
    return base


def eslint_file_entry(filepath="/home/user/myapp/routes/login.js", messages=None):
    """Return a minimal valid ESLint file entry."""
    if messages is None:
        messages = [
            {
                "ruleId": "security/detect-sql-injection",
                "severity": 2,
                "message": "Found potential SQL injection",
                "line": 34,
            }
        ]
    return {"filePath": filepath, "messages": messages}


class TestParseBandit:

    # --- 1.1 Happy path ---
    def test_happy_path_returns_one_finding(self):
        raw = {"results": [bandit_result()]}
        findings = parse_bandit(raw)
        assert len(findings) == 1

    def test_happy_path_correct_fields(self):
        raw = {"results": [bandit_result()]}
        f = parse_bandit(raw)[0]
        assert f["path"]     == "app/utils.py"
        assert f["line"]     == 42
        assert f["tool"]     == ["Bandit"]
        assert f["rule_id"]  == "CWE-78"        # B602 → CWE-78
        assert f["severity"] == "HIGH"
        assert f["message"]  == "subprocess call with shell=True identified."
        assert isinstance(f["confidence"], float)

    # --- 1.2 Missing / null fields ---
    def test_missing_line_number_returns_none(self):
        raw = {"results": [bandit_result(line_number=None)]}
        f = parse_bandit(raw)[0]
        assert f["line"] is None

    def test_missing_line_number_key_returns_none(self):
        result = bandit_result()
        del result["line_number"]
        f = parse_bandit({"results": [result]})[0]
        assert f["line"] is None

    def test_missing_message_returns_empty_string(self):
        result = bandit_result()
        del result["issue_text"]
        f = parse_bandit({"results": [result]})[0]
        assert f["message"] == ""

    def test_missing_filename_returns_unknown(self):
        result = bandit_result()
        del result["filename"]
        f = parse_bandit({"results": [result]})[0]
        assert f["path"] == "UNKNOWN"

    # --- 1.3 Severity mapping ---
    def test_severity_high(self):
        raw = {"results": [bandit_result(issue_severity="HIGH")]}
        assert parse_bandit(raw)[0]["severity"] == "HIGH"

    def test_severity_medium(self):
        raw = {"results": [bandit_result(issue_severity="MEDIUM")]}
        assert parse_bandit(raw)[0]["severity"] == "MEDIUM"

    def test_severity_low(self):
        raw = {"results": [bandit_result(issue_severity="LOW")]}
        assert parse_bandit(raw)[0]["severity"] == "LOW"

    def test_severity_unknown_defaults_to_low(self):
        raw = {"results": [bandit_result(issue_severity="CRITICAL")]}
        assert parse_bandit(raw)[0]["severity"] == "LOW"

    def test_severity_lowercase_handled(self):
        raw = {"results": [bandit_result(issue_severity="high")]}
        assert parse_bandit(raw)[0]["severity"] == "HIGH"

    # --- 1.4 CWE mapping ---
    def test_known_rule_maps_to_cwe(self):
        raw = {"results": [bandit_result(test_id="B608")]}
        assert parse_bandit(raw)[0]["rule_id"] == "CWE-89"

    def test_unknown_rule_maps_to_cwe_unknown(self):
        raw = {"results": [bandit_result(test_id="B999")]}
        assert parse_bandit(raw)[0]["rule_id"] == "CWE-UNKNOWN"

    def test_missing_test_id_maps_to_cwe_unknown(self):
        result = bandit_result()
        del result["test_id"]
        f = parse_bandit({"results": [result]})[0]
        assert f["rule_id"] == "CWE-UNKNOWN"

    # --- 1.5 Empty input ---
    def test_empty_results_returns_empty_list(self):
        assert parse_bandit({"results": []}) == []

    def test_missing_results_key_returns_empty_list(self):
        assert parse_bandit({}) == []

    # --- 1.6 Multiple findings ---
    def test_multiple_findings_all_parsed(self):
        raw = {
            "results": [
                bandit_result(test_id="B602", line_number=10),
                bandit_result(test_id="B303", line_number=20),
                bandit_result(test_id="B608", line_number=30),
            ]
        }
        findings = parse_bandit(raw)
        assert len(findings) == 3
        assert findings[0]["rule_id"] == "CWE-78"
        assert findings[1]["rule_id"] == "CWE-327"
        assert findings[2]["rule_id"] == "CWE-89"

    # --- 1.7 Confidence score ---
    def test_high_severity_confidence_is_07(self):
        raw = {"results": [bandit_result(issue_severity="HIGH")]}
        assert parse_bandit(raw)[0]["confidence"] == 0.7

    def test_medium_severity_confidence_is_05(self):
        raw = {"results": [bandit_result(issue_severity="MEDIUM")]}
        assert parse_bandit(raw)[0]["confidence"] == 0.5

    def test_low_severity_confidence_is_03(self):
        raw = {"results": [bandit_result(issue_severity="LOW")]}
        assert parse_bandit(raw)[0]["confidence"] == 0.3


class TestParseSemgrep:

    # --- 2.1 Happy path ---
    def test_happy_path_returns_one_finding(self):
        raw = {"results": [semgrep_result()]}
        findings = parse_semgrep(raw)
        assert len(findings) == 1

    def test_happy_path_correct_fields(self):
        raw = {"results": [semgrep_result()]}
        f = parse_semgrep(raw)[0]
        assert f["path"]     == "app/db.py"
        assert f["line"]     == 17
        assert f["tool"]     == ["Semgrep"]
        assert f["rule_id"]  == "CWE-89"
        assert f["severity"] == "HIGH"
        assert f["message"]  == "Possible SQL injection via string formatting"

    # --- 2.2 Severity mapping ---
    def test_severity_error_maps_to_high(self):
        r = semgrep_result()
        r["extra"]["severity"] = "ERROR"
        assert parse_semgrep({"results": [r]})[0]["severity"] == "HIGH"

    def test_severity_warning_maps_to_medium(self):
        r = semgrep_result()
        r["extra"]["severity"] = "WARNING"
        assert parse_semgrep({"results": [r]})[0]["severity"] == "MEDIUM"

    def test_severity_info_maps_to_low(self):
        r = semgrep_result()
        r["extra"]["severity"] = "INFO"
        assert parse_semgrep({"results": [r]})[0]["severity"] == "LOW"

    def test_severity_unknown_defaults_to_low(self):
        r = semgrep_result()
        r["extra"]["severity"] = "UNKNOWN_LEVEL"
        assert parse_semgrep({"results": [r]})[0]["severity"] == "LOW"

    # --- 2.3 CWE extraction ---
    def test_cwe_as_list_extracts_first(self):
        r = semgrep_result()
        r["extra"]["metadata"]["cwe"] = ["CWE-89: SQL Injection", "CWE-20"]
        assert parse_semgrep({"results": [r]})[0]["rule_id"] == "CWE-89"

    def test_cwe_as_string_extracted(self):
        r = semgrep_result()
        r["extra"]["metadata"]["cwe"] = "CWE-78: OS Command Injection"
        assert parse_semgrep({"results": [r]})[0]["rule_id"] == "CWE-78"

    def test_cwe_strips_description(self):
        r = semgrep_result()
        r["extra"]["metadata"]["cwe"] = ["CWE-22: Path Traversal"]
        assert parse_semgrep({"results": [r]})[0]["rule_id"] == "CWE-22"

    def test_missing_cwe_falls_back_to_check_id(self):
        r = semgrep_result()
        r["extra"]["metadata"] = {}  # no cwe key
        f = parse_semgrep({"results": [r]})[0]
        # Should fall back to check_id
        assert f["rule_id"] == "python.django.security.injection.sql"

    def test_missing_metadata_entirely_falls_back(self):
        r = semgrep_result()
        del r["extra"]["metadata"]
        f = parse_semgrep({"results": [r]})[0]
        assert f["rule_id"] == "python.django.security.injection.sql"

    # --- 2.4 Missing fields ---
    def test_missing_line_returns_none(self):
        r = semgrep_result()
        del r["start"]
        f = parse_semgrep({"results": [r]})[0]
        assert f["line"] is None

    def test_missing_message_returns_empty_string(self):
        r = semgrep_result()
        del r["extra"]["message"]
        f = parse_semgrep({"results": [r]})[0]
        assert f["message"] == ""

    # --- 2.5 Empty input ---
    def test_empty_results_returns_empty_list(self):
        assert parse_semgrep({"results": []}) == []

    def test_missing_results_key_returns_empty_list(self):
        assert parse_semgrep({}) == []

    # --- 2.6 SARIF format ---
    def test_sarif_format_detected_and_parsed(self):
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "python.django.security.sql",
                                    "properties": {
                                        "cwe": ["CWE-89: SQL Injection"]
                                    },
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "python.django.security.sql",
                            "level": "error",
                            "message": {"text": "SQL injection detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app/db.py"},
                                        "region": {"startLine": 17},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        findings = parse_semgrep(sarif)
        assert len(findings) == 1
        f = findings[0]
        assert f["path"]     == "app/db.py"
        assert f["line"]     == 17
        assert f["rule_id"]  == "CWE-89"
        assert f["severity"] == "HIGH"
        assert f["tool"]     == ["Semgrep"]

    def test_sarif_empty_runs_returns_empty_list(self):
        assert parse_semgrep({"runs": []}) == []


class TestParseEslint:

    # --- 3.1 Happy path ---
    def test_happy_path_returns_one_finding(self):
        raw = [eslint_file_entry()]
        assert len(parse_eslint(raw)) == 1

    def test_happy_path_correct_fields(self):
        raw = [eslint_file_entry()]
        f = parse_eslint(raw, base_dir="/home/user/myapp")[0]
        assert f["path"]     == "routes/login.js"
        assert f["line"]     == 34
        assert f["tool"]     == ["ESLint"]
        assert f["rule_id"]  == "CWE-89"
        assert f["severity"] == "HIGH"
        assert f["message"]  == "Found potential SQL injection"

    # --- 3.2 Severity mapping ---
    def test_severity_2_maps_to_high(self):
        raw = [eslint_file_entry(messages=[{"ruleId": "security/detect-eval-with-expression", "severity": 2, "message": "eval", "line": 1}])]
        assert parse_eslint(raw)[0]["severity"] == "HIGH"

    def test_severity_1_maps_to_medium(self):
        raw = [eslint_file_entry(messages=[{"ruleId": "security/detect-eval-with-expression", "severity": 1, "message": "eval", "line": 1}])]
        assert parse_eslint(raw)[0]["severity"] == "MEDIUM"

    def test_severity_0_maps_to_low(self):
        raw = [eslint_file_entry(messages=[{"ruleId": "security/detect-eval-with-expression", "severity": 0, "message": "eval", "line": 1}])]
        assert parse_eslint(raw)[0]["severity"] == "LOW"

    # --- 3.3 CWE mapping ---
    def test_known_rule_maps_to_cwe(self):
        raw = [eslint_file_entry(messages=[{"ruleId": "security/detect-child-process", "severity": 2, "message": "x", "line": 1}])]
        assert parse_eslint(raw)[0]["rule_id"] == "CWE-78"

    def test_unknown_rule_maps_to_cwe_unknown(self):
        raw = [eslint_file_entry(messages=[{"ruleId": "some-unknown-rule", "severity": 2, "message": "x", "line": 1}])]
        assert parse_eslint(raw)[0]["rule_id"] == "CWE-UNKNOWN"

    def test_null_rule_id_maps_to_cwe_unknown(self):
        raw = [eslint_file_entry(messages=[{"ruleId": None, "severity": 2, "message": "x", "line": 1}])]
        assert parse_eslint(raw)[0]["rule_id"] == "CWE-UNKNOWN"

    # --- 3.4 Path normalization ---
    def test_absolute_path_made_relative_with_base_dir(self):
        raw = [eslint_file_entry(filepath="/home/user/myapp/src/app.js")]
        f = parse_eslint(raw, base_dir="/home/user/myapp")[0]
        assert f["path"] == "src/app.js"

    def test_already_relative_path_unchanged(self):
        raw = [eslint_file_entry(filepath="src/app.js")]
        f = parse_eslint(raw)[0]
        assert f["path"] == "src/app.js"

    def test_no_base_dir_strips_leading_slash(self):
        raw = [eslint_file_entry(filepath="/home/user/myapp/src/app.js")]
        f = parse_eslint(raw)[0]
        # Without base_dir, absolute path is returned as-is
        assert "app.js" in f["path"]

    # --- 3.5 Nested structure flattening ---
    def test_multiple_messages_in_one_file_all_parsed(self):
        messages = [
            {"ruleId": "security/detect-sql-injection",      "severity": 2, "message": "SQL",  "line": 10},
            {"ruleId": "security/detect-eval-with-expression","severity": 2, "message": "eval", "line": 20},
            {"ruleId": "security/detect-child-process",       "severity": 1, "message": "exec", "line": 30},
        ]
        raw = [eslint_file_entry(messages=messages)]
        findings = parse_eslint(raw)
        assert len(findings) == 3
        assert findings[0]["line"] == 10
        assert findings[1]["line"] == 20
        assert findings[2]["line"] == 30

    def test_multiple_files_all_flattened(self):
        raw = [
            eslint_file_entry(filepath="/home/user/app/a.js"),
            eslint_file_entry(filepath="/home/user/app/b.js"),
        ]
        findings = parse_eslint(raw)
        assert len(findings) == 2
        paths = [f["path"] for f in findings]
        assert any("a.js" in p for p in paths)
        assert any("b.js" in p for p in paths)

    def test_file_with_no_messages_produces_no_findings(self):
        raw = [{"filePath": "/home/user/app/clean.js", "messages": []}]
        assert parse_eslint(raw) == []

    # --- 3.6 Empty input ---
    def test_empty_list_returns_empty_list(self):
        assert parse_eslint([]) == []

    def test_missing_line_returns_none(self):
        raw = [eslint_file_entry(messages=[{"ruleId": "security/detect-eval-with-expression", "severity": 2, "message": "x"}])]
        f = parse_eslint(raw)[0]
        assert f["line"] is None


class TestSeverityNormalizers:

    def test_bandit_high(self):      assert _normalize_severity_bandit("HIGH")     == "HIGH"
    def test_bandit_medium(self):    assert _normalize_severity_bandit("MEDIUM")   == "MEDIUM"
    def test_bandit_low(self):       assert _normalize_severity_bandit("LOW")      == "LOW"
    def test_bandit_lowercase(self): assert _normalize_severity_bandit("medium")   == "MEDIUM"
    def test_bandit_unknown(self):   assert _normalize_severity_bandit("CRITICAL") == "LOW"

    def test_semgrep_error(self):    assert _normalize_severity_semgrep("ERROR")   == "HIGH"
    def test_semgrep_warning(self):  assert _normalize_severity_semgrep("WARNING") == "MEDIUM"
    def test_semgrep_info(self):     assert _normalize_severity_semgrep("INFO")    == "LOW"
    def test_semgrep_lowercase(self):assert _normalize_severity_semgrep("error")   == "HIGH"
    def test_semgrep_unknown(self):  assert _normalize_severity_semgrep("TRACE")   == "LOW"

    def test_eslint_2(self):  assert _normalize_severity_eslint(2) == "HIGH"
    def test_eslint_1(self):  assert _normalize_severity_eslint(1) == "MEDIUM"
    def test_eslint_0(self):  assert _normalize_severity_eslint(0) == "LOW"
    def test_eslint_3(self):  assert _normalize_severity_eslint(3) == "HIGH"   # anything ≥2 = HIGH


class TestExtractCWESemgrep:

    def test_cwe_list_with_description(self):
        assert _extract_cwe_semgrep({"cwe": ["CWE-89: SQL Injection"]}) == "CWE-89"

    def test_cwe_string_with_description(self):
        assert _extract_cwe_semgrep({"cwe": "CWE-78: OS Command Injection"}) == "CWE-78"

    def test_cwe_bare(self):
        assert _extract_cwe_semgrep({"cwe": "CWE-22"}) == "CWE-22"

    def test_cwe_list_takes_first(self):
        assert _extract_cwe_semgrep({"cwe": ["CWE-89: ...", "CWE-20: ..."]}) == "CWE-89"

    def test_missing_cwe_key(self):
        assert _extract_cwe_semgrep({}) == "CWE-UNKNOWN"

    def test_empty_cwe_value(self):
        assert _extract_cwe_semgrep({"cwe": ""}) == "CWE-UNKNOWN"

    def test_cwe_uppercase_key(self):
        assert _extract_cwe_semgrep({"CWE": ["CWE-502: Deserialization"]}) == "CWE-502"


class TestMakePathRelative:

    def test_absolute_with_base_dir(self):
        assert _make_path_relative("/home/user/app/src/main.py", "/home/user/app") == "src/main.py"

    def test_already_relative(self):
        assert _make_path_relative("src/main.py") == "src/main.py"

    def test_no_base_dir_absolute_stripped(self):
        result = _make_path_relative("/home/user/app/main.py")
        assert not result.startswith("/")

    def test_exact_match_base_dir(self):
        assert _make_path_relative("/app/main.py", "/app") == "main.py"


class TestNormalizeAll:
    """Integration tests for normalize_all(raw_results).

    Writes real JSON to tmp_path so the file-based interface matches what
    the orchestrator passes in at runtime.
    """

    # --- helpers ---

    def _write(self, tmp_path, name, data):
        import json
        p = tmp_path / name
        p.write_text(json.dumps(data))
        return str(p)

    def _raw_results(self, tmp_path, *, bandit=None, semgrep=None, eslint=None):
        raw = {}
        if bandit is not None:
            raw["Bandit"]  = {"stdout_file": self._write(tmp_path, "bandit.json",  bandit),  "exit_code": 0}
        if semgrep is not None:
            raw["Semgrep"] = {"stdout_file": self._write(tmp_path, "semgrep.json", semgrep), "exit_code": 0}
        if eslint is not None:
            raw["ESLint"]  = {"stdout_file": self._write(tmp_path, "eslint.json",  eslint),  "exit_code": 0}
        return raw

    # --- tests ---

    def test_all_three_tools_combined(self, tmp_path):
        raw = self._raw_results(tmp_path,
            bandit={"results": [bandit_result()]},
            semgrep={"results": [semgrep_result()]},
            eslint=[eslint_file_entry()],
        )
        assert len(normalize_all(raw)) == 3

    def test_tools_list_per_finding_is_correct(self, tmp_path):
        raw = self._raw_results(tmp_path,
            bandit={"results": [bandit_result()]},
            semgrep={"results": [semgrep_result()]},
            eslint=[eslint_file_entry()],
        )
        tools = [f["tool"] for f in normalize_all(raw)]
        assert ["Bandit"]  in tools
        assert ["Semgrep"] in tools
        assert ["ESLint"]  in tools

    def test_only_bandit(self, tmp_path):
        raw = self._raw_results(tmp_path, bandit={"results": [bandit_result()]})
        findings = normalize_all(raw)
        assert len(findings) == 1
        assert findings[0]["tool"] == ["Bandit"]

    def test_only_semgrep(self, tmp_path):
        raw = self._raw_results(tmp_path, semgrep={"results": [semgrep_result()]})
        findings = normalize_all(raw)
        assert len(findings) == 1
        assert findings[0]["tool"] == ["Semgrep"]

    def test_only_eslint(self, tmp_path):
        raw = self._raw_results(tmp_path, eslint=[eslint_file_entry()])
        findings = normalize_all(raw)
        assert len(findings) == 1
        assert findings[0]["tool"] == ["ESLint"]

    def test_empty_dict_returns_empty_list(self):
        assert normalize_all({}) == []

    def test_all_empty_results_returns_empty_list(self, tmp_path):
        raw = self._raw_results(tmp_path,
            bandit={"results": []},
            semgrep={"results": []},
            eslint=[],
        )
        assert normalize_all(raw) == []

    def test_unified_schema_keys_present(self, tmp_path):
        """Every finding must have all required unified schema keys."""
        required_keys = {"path", "line", "tool", "rule_id", "severity", "message", "confidence"}
        raw = self._raw_results(tmp_path,
            bandit={"results": [bandit_result()]},
            semgrep={"results": [semgrep_result()]},
            eslint=[eslint_file_entry()],
        )
        for f in normalize_all(raw):
            assert required_keys.issubset(f.keys()), f"Finding missing keys: {required_keys - f.keys()}"

    def test_severity_values_are_valid(self, tmp_path):
        """Severity must always be HIGH, MEDIUM, or LOW, never anything else."""
        valid = {"HIGH", "MEDIUM", "LOW"}
        raw = self._raw_results(tmp_path,
            bandit={"results": [
                bandit_result(issue_severity="HIGH"),
                bandit_result(issue_severity="MEDIUM"),
                bandit_result(issue_severity="LOW"),
            ]},
            semgrep={"results": [semgrep_result()]},
        )
        for f in normalize_all(raw):
            assert f["severity"] in valid, f"Invalid severity: {f['severity']}"

    def test_confidence_is_float_between_0_and_1(self, tmp_path):
        raw = self._raw_results(tmp_path,
            bandit={"results": [bandit_result()]},
            semgrep={"results": [semgrep_result()]},
            eslint=[eslint_file_entry()],
        )
        for f in normalize_all(raw):
            assert isinstance(f["confidence"], float)
            assert 0.0 <= f["confidence"] <= 1.0

    def test_tool_field_is_always_a_list(self, tmp_path):
        raw = self._raw_results(tmp_path,
            bandit={"results": [bandit_result()]},
            semgrep={"results": [semgrep_result()]},
            eslint=[eslint_file_entry()],
        )
        for f in normalize_all(raw):
            assert isinstance(f["tool"], list)
