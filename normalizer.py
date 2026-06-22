"""Convert raw Bandit/Semgrep/ESLint JSON outputs into the unified schema.

A normalized finding is a dict with these keys:
    path, line, tool (list), rule_id, severity, message, confidence
"""

import json
import os
import re
from typing import Any


BANDIT_TO_CWE: dict[str, str] = {
    "B101": "CWE-703",
    "B102": "CWE-78",
    "B103": "CWE-732",
    "B104": "CWE-605",
    "B105": "CWE-259",
    "B106": "CWE-259",
    "B107": "CWE-259",
    "B108": "CWE-377",
    "B110": "CWE-390",
    "B112": "CWE-390",
    "B201": "CWE-94",
    "B301": "CWE-502",
    "B302": "CWE-502",
    "B303": "CWE-327",
    "B304": "CWE-327",
    "B305": "CWE-327",
    "B306": "CWE-377",
    "B307": "CWE-78",
    "B308": "CWE-79",
    "B310": "CWE-601",
    "B311": "CWE-338",
    "B312": "CWE-605",
    "B313": "CWE-611",
    "B314": "CWE-611",
    "B315": "CWE-611",
    "B316": "CWE-611",
    "B317": "CWE-611",
    "B318": "CWE-611",
    "B319": "CWE-611",
    "B320": "CWE-611",
    "B321": "CWE-321",
    "B322": "CWE-78",
    "B323": "CWE-295",
    "B324": "CWE-327",
    "B325": "CWE-377",
    "B401": "CWE-319",
    "B402": "CWE-319",
    "B403": "CWE-502",
    "B404": "CWE-78",
    "B405": "CWE-611",
    "B406": "CWE-611",
    "B407": "CWE-611",
    "B408": "CWE-611",
    "B409": "CWE-611",
    "B410": "CWE-611",
    "B411": "CWE-611",
    "B412": "CWE-611",
    "B413": "CWE-327",
    "B501": "CWE-295",
    "B502": "CWE-326",
    "B503": "CWE-326",
    "B504": "CWE-326",
    "B505": "CWE-326",
    "B506": "CWE-20",
    "B507": "CWE-295",
    "B601": "CWE-78",
    "B602": "CWE-78",
    "B603": "CWE-78",
    "B604": "CWE-78",
    "B605": "CWE-78",
    "B606": "CWE-78",
    "B607": "CWE-78",
    "B608": "CWE-89",
    "B609": "CWE-78",
    "B610": "CWE-89",
    "B611": "CWE-89",
    "B701": "CWE-94",
    "B702": "CWE-79",
    "B703": "CWE-79",
}

# eslint-plugin-security rule -> CWE.
# Some entries are aliases the plugin has used across versions.
ESLINT_TO_CWE: dict[str, str] = {
    "security/detect-sql-injection": "CWE-89",
    "security/detect-non-literal-regexp": "CWE-1333",
    "security/detect-non-literal-require": "CWE-706",
    "security/detect-non-literal-fs-filename": "CWE-22",
    "security/detect-eval-with-expression": "CWE-95",
    "security/detect-no-csrf-before-method-override": "CWE-352",
    "security/detect-buffer-noassert": "CWE-120",
    "security/detect-child-process": "CWE-78",
    "security/detect-disable-mustache-escape": "CWE-79",
    "security/detect-new-buffer": "CWE-120",
    "security/detect-possible-timing-attacks": "CWE-208",
    "security/detect-pseudoRandomBytes": "CWE-338",
    "security/detect-bidi-characters": "CWE-1007",
    "security/detect-unsafe-regex": "CWE-1333",
    "security/detect-object-injection": "CWE-94",
    "no-eval": "CWE-95",
    "no-prototype-builtins": "CWE-1321",
    "no-unsafe-finally": "CWE-705",
    "no-octal": "CWE-704",
}


def _normalize_severity_bandit(raw: str) -> str:
    return {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(raw.upper(), "LOW")


def _normalize_severity_semgrep(raw: str) -> str:
    table = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }
    return table.get(raw.upper(), "LOW")


def _normalize_severity_eslint(raw: int) -> str:
    if raw >= 2:
        return "HIGH"
    if raw == 1:
        return "MEDIUM"
    return "LOW"


def _extract_cwe_semgrep(metadata: dict) -> str:
    """Pull a CWE-NNN string out of a Semgrep metadata block."""
    cwe_raw = metadata.get("cwe") or metadata.get("CWE")
    if not cwe_raw:
        return "CWE-UNKNOWN"
    if isinstance(cwe_raw, list):
        cwe_raw = cwe_raw[0]
    match = re.match(r"(CWE-\d+)", str(cwe_raw), re.IGNORECASE)
    return match.group(1).upper() if match else "CWE-UNKNOWN"


def _make_path_relative(absolute_path: str, base_dir: str = "") -> str:
    """Best-effort: relative to base_dir if given, else strip a leading slash."""
    if base_dir and absolute_path.startswith(base_dir):
        return os.path.relpath(absolute_path, base_dir)
    if not os.path.isabs(absolute_path):
        return absolute_path
    return absolute_path.lstrip("/")


def _initial_confidence_from_severity(severity: str) -> float:
    return {"HIGH": 0.7, "MEDIUM": 0.5, "LOW": 0.3}.get(severity, 0.3)


def parse_bandit(raw_json: dict, base_dir: str = "") -> list[dict]:
    findings: list[dict] = []
    for item in raw_json.get("results", []):
        rule_id_raw = item.get("test_id", "UNKNOWN")
        severity = _normalize_severity_bandit(item.get("issue_severity", "LOW"))
        path = _make_path_relative(item.get("filename", "UNKNOWN"), base_dir)
        findings.append({
            "path": path,
            "line": item.get("line_number"),
            "tool": ["Bandit"],
            "rule_id": BANDIT_TO_CWE.get(rule_id_raw, "CWE-UNKNOWN"),
            "severity": severity,
            "message": item.get("issue_text", "").strip(),
            "confidence": _initial_confidence_from_severity(severity),
        })
    return findings


def parse_semgrep(raw_json: dict, base_dir: str = "") -> list[dict]:
    if "runs" in raw_json:
        return _parse_semgrep_sarif(raw_json, base_dir)

    findings: list[dict] = []
    for item in raw_json.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        severity = _normalize_severity_semgrep(extra.get("severity", "INFO"))
        cwe = _extract_cwe_semgrep(metadata)
        if cwe == "CWE-UNKNOWN":
            check_id = item.get("check_id", "")
            rule_id = check_id if check_id else "CWE-UNKNOWN"
        else:
            rule_id = cwe
        path = _make_path_relative(item.get("path", "UNKNOWN"), base_dir)
        findings.append({
            "path": path,
            "line": item.get("start", {}).get("line"),
            "tool": ["Semgrep"],
            "rule_id": rule_id,
            "severity": severity,
            "message": extra.get("message", "").strip(),
            "confidence": _initial_confidence_from_severity(severity),
        })
    return findings


def _parse_semgrep_sarif(sarif_json: dict, base_dir: str = "") -> list[dict]:
    findings: list[dict] = []

    for run in sarif_json.get("runs", []):
        rules_lookup: dict[str, Any] = {
            rule.get("id", ""): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }

        for result in run.get("results", []):
            rule_id_raw = result.get("ruleId", "")
            level = result.get("level", "warning")
            severity = _normalize_severity_semgrep(
                {"error": "ERROR", "warning": "WARNING", "note": "INFO"}.get(level, "INFO")
            )

            props = rules_lookup.get(rule_id_raw, {}).get("properties", {})
            cwe = _extract_cwe_semgrep(props) if props else "CWE-UNKNOWN"
            if cwe == "CWE-UNKNOWN" and rule_id_raw:
                cwe = rule_id_raw

            locations = result.get("locations", [])
            path = "UNKNOWN"
            line: int | None = None
            if locations:
                phys = locations[0].get("physicalLocation", {})
                path = phys.get("artifactLocation", {}).get("uri", "UNKNOWN")
                line = phys.get("region", {}).get("startLine")
            path = _make_path_relative(path, base_dir)

            findings.append({
                "path": path,
                "line": line,
                "tool": ["Semgrep"],
                "rule_id": cwe,
                "severity": severity,
                "message": result.get("message", {}).get("text", "").strip(),
                "confidence": _initial_confidence_from_severity(severity),
            })

    return findings


def parse_eslint(raw_json: list, base_dir: str = "") -> list[dict]:
    findings: list[dict] = []

    for file_entry in raw_json:
        rel_path = _make_path_relative(file_entry.get("filePath", "UNKNOWN"), base_dir)
        for msg in file_entry.get("messages", []):
            rule_id_raw = msg.get("ruleId") or "UNKNOWN"
            severity = _normalize_severity_eslint(msg.get("severity", 1))
            findings.append({
                "path": rel_path,
                "line": msg.get("line"),
                "tool": ["ESLint"],
                "rule_id": ESLINT_TO_CWE.get(rule_id_raw, "CWE-UNKNOWN"),
                "severity": severity,
                "message": msg.get("message", "").strip(),
                "confidence": _initial_confidence_from_severity(severity),
            })

    return findings


def normalize_all(raw_results: dict, base_dir: str = "") -> list[dict]:
    """Read each tool's stdout file and merge into one flat list.

    raw_results keys are tool names; values are dicts with a 'stdout_file' path.
    base_dir is the scan root, used to convert absolute paths to repo-relative.
    """
    def _load(path: str) -> Any:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    all_findings: list[dict] = []

    if "Bandit" in raw_results and "stdout_file" in raw_results["Bandit"]:
        raw = _load(raw_results["Bandit"]["stdout_file"])
        findings = parse_bandit(raw, base_dir)
        print(f"[Bandit]  {len(findings)} findings parsed.")
        all_findings.extend(findings)

    if "Semgrep" in raw_results and "stdout_file" in raw_results["Semgrep"]:
        raw = _load(raw_results["Semgrep"]["stdout_file"])
        findings = parse_semgrep(raw, base_dir)
        print(f"[Semgrep] {len(findings)} findings parsed.")
        all_findings.extend(findings)

    if "ESLint" in raw_results and "stdout_file" in raw_results["ESLint"]:
        raw = _load(raw_results["ESLint"]["stdout_file"])
        findings = parse_eslint(raw, base_dir)
        print(f"[ESLint]  {len(findings)} findings parsed.")
        all_findings.extend(findings)

    print(f"Total normalized findings: {len(all_findings)}")
    return all_findings
