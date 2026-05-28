"""
normalizer.py — MultiScan CLI | Part 2: Data Normalization & Parsers
=====================================================================
Responsibilities:
  - Parse raw JSON output from Bandit, Semgrep, and ESLint
  - Normalize all findings into a single Unified Schema
  - Map tool-specific rule IDs to CWE identifiers
  - Normalize severity scales to HIGH / MEDIUM / LOW
  - Return a single flat list of findings for downstream processing

Unified Schema (one dict per finding):
{
    "path":       str,         # relative file path
    "line":       int | None,  # line number (None if unavailable)
    "tool":       list[str],   # e.g. ["Bandit"]  — deduplicator may merge later
    "rule_id":    str,         # CWE identifier, e.g. "CWE-78"
    "severity":   str,         # "HIGH" | "MEDIUM" | "LOW"
    "message":    str,         # human-readable description
    "confidence": float,       # initial per-tool confidence (0.0 – 1.0)
}
"""

import json
import os
import re
from typing import Any


# ---------------------------------------------------------------------------
# CWE Lookup Tables
# ---------------------------------------------------------------------------

# Bandit rule ID  →  CWE
BANDIT_TO_CWE: dict[str, str] = {
    "B101": "CWE-703",   # assert used
    "B102": "CWE-78",    # exec used
    "B103": "CWE-732",   # chmod setting permissive mask
    "B104": "CWE-605",   # binding to all interfaces
    "B105": "CWE-259",   # hardcoded password string
    "B106": "CWE-259",   # hardcoded password funcarg
    "B107": "CWE-259",   # hardcoded password default
    "B108": "CWE-377",   # tmp file / insecure tempfile
    "B110": "CWE-390",   # try/except pass
    "B112": "CWE-390",   # try/except continue
    "B201": "CWE-94",    # flask debug mode
    "B301": "CWE-502",   # pickle usage
    "B302": "CWE-502",   # marshal usage
    "B303": "CWE-327",   # md5/sha1 used
    "B304": "CWE-327",   # ciphers – deprecated modes
    "B305": "CWE-327",   # cipher modes
    "B306": "CWE-377",   # mktemp
    "B307": "CWE-78",    # eval
    "B308": "CWE-79",    # mark_safe
    "B310": "CWE-601",   # urllib open
    "B311": "CWE-338",   # random
    "B312": "CWE-605",   # telnetlib
    "B313": "CWE-611",   # xml.etree.cElementTree
    "B314": "CWE-611",   # xml.etree.ElementTree
    "B315": "CWE-611",   # xml.etree.expat
    "B316": "CWE-611",   # xml.etree.minidom
    "B317": "CWE-611",   # xml.etree.pulldom
    "B318": "CWE-611",   # xml.etree.sax
    "B319": "CWE-611",   # xml.etree.xmlrpc
    "B320": "CWE-611",   # lxml
    "B321": "CWE-321",   # ftp
    "B322": "CWE-78",    # input() py2
    "B323": "CWE-295",   # unverified context
    "B324": "CWE-327",   # hashlib new with insecure hash
    "B325": "CWE-377",   # tempnam
    "B401": "CWE-319",   # import telnetlib
    "B402": "CWE-319",   # import ftplib
    "B403": "CWE-502",   # import pickle
    "B404": "CWE-78",    # import subprocess
    "B405": "CWE-611",   # import xml.etree
    "B406": "CWE-611",   # import xml.sax
    "B407": "CWE-611",   # import xml.expat
    "B408": "CWE-611",   # import xml.minidom
    "B409": "CWE-611",   # import xml.pulldom
    "B410": "CWE-611",   # import lxml
    "B411": "CWE-611",   # import xmlrpclib
    "B412": "CWE-611",   # import httpoxy
    "B413": "CWE-327",   # import pycrypto
    "B501": "CWE-295",   # request with no cert verify
    "B502": "CWE-326",   # ssl with bad version
    "B503": "CWE-326",   # ssl with bad defaults
    "B504": "CWE-326",   # ssl with no version
    "B505": "CWE-326",   # weak cryptographic key
    "B506": "CWE-20",    # yaml load
    "B507": "CWE-295",   # ssh no host key verify
    "B601": "CWE-78",    # paramiko shell
    "B602": "CWE-78",    # subprocess shell=True
    "B603": "CWE-78",    # subprocess without shell
    "B604": "CWE-78",    # any function with shell
    "B605": "CWE-78",    # start process with shell
    "B606": "CWE-78",    # start process with no shell
    "B607": "CWE-78",    # start process with partial path
    "B608": "CWE-89",    # SQL injection
    "B609": "CWE-78",    # wildcard injection
    "B610": "CWE-89",    # django extra used
    "B611": "CWE-89",    # django rawsql used
    "B701": "CWE-94",    # jinja2 autoescape false
    "B702": "CWE-79",    # use of mako templates
    "B703": "CWE-79",    # django mark_safe
}

# ESLint security plugin rule  →  CWE
ESLINT_TO_CWE: dict[str, str] = {
    "security/detect-sql-injection":                  "CWE-89",
    "security/detect-non-literal-regexp":             "CWE-1333",
    "security/detect-non-literal-require":            "CWE-706",
    "security/detect-non-literal-fs-filename":        "CWE-22",
    "security/detect-eval-with-expression":           "CWE-95",
    "security/detect-no-csrf-before-method-override": "CWE-352",
    "security/detect-buffer-noassert":                "CWE-120",
    "security/detect-child-process":                  "CWE-78",
    "security/detect-disable-mustache-escape":        "CWE-79",
    "security/detect-new-buffer":                     "CWE-120",
    "security/detect-possible-timing-attacks":        "CWE-208",
    "security/detect-pseudoRandomBytes":              "CWE-338",
    "security/detect-unsafe-regex":                   "CWE-1333",
    "security/detect-object-injection":               "CWE-94",
    "no-eval":                                        "CWE-95",
}


# ---------------------------------------------------------------------------
# Severity Normalizers
# ---------------------------------------------------------------------------

def _normalize_severity_bandit(raw: str) -> str:
    """Bandit already uses HIGH/MEDIUM/LOW — just uppercase and validate."""
    mapping = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    return mapping.get(raw.upper(), "LOW")


def _normalize_severity_semgrep(raw: str) -> str:
    """Semgrep uses ERROR / WARNING / INFO."""
    mapping = {
        "ERROR":   "HIGH",
        "WARNING": "MEDIUM",
        "INFO":    "LOW",
        # Some rulesets also emit these directly
        "HIGH":    "HIGH",
        "MEDIUM":  "MEDIUM",
        "LOW":     "LOW",
    }
    return mapping.get(raw.upper(), "LOW")


def _normalize_severity_eslint(raw: int) -> str:
    """ESLint uses numeric severity: 2 = error, 1 = warning, 0 = off."""
    if raw >= 2:
        return "HIGH"
    if raw == 1:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# CWE Extractors
# ---------------------------------------------------------------------------

def _extract_cwe_semgrep(metadata: dict) -> str:
    """
    Semgrep metadata may contain a 'cwe' key with values like:
      - "CWE-89: SQL Injection"
      - ["CWE-89: SQL Injection"]
    Strip to just "CWE-89".
    """
    cwe_raw = metadata.get("cwe") or metadata.get("CWE")
    if not cwe_raw:
        return "CWE-UNKNOWN"

    # Could be a list; take the first entry
    if isinstance(cwe_raw, list):
        cwe_raw = cwe_raw[0]

    # Strip description after colon: "CWE-89: SQL Injection" → "CWE-89"
    match = re.match(r"(CWE-\d+)", str(cwe_raw), re.IGNORECASE)
    return match.group(1).upper() if match else "CWE-UNKNOWN"


def _make_path_relative(absolute_path: str, base_dir: str = "") -> str:
    """
    Convert an absolute path to a relative one.
    If base_dir is provided, make it relative to that directory.
    Falls back to just stripping the leading slash if no base_dir.
    """
    if base_dir and absolute_path.startswith(base_dir):
        rel = os.path.relpath(absolute_path, base_dir)
        return rel
    # Best-effort: return as-is if already relative, otherwise strip leading /
    if not os.path.isabs(absolute_path):
        return absolute_path
    return absolute_path.lstrip("/")


def _initial_confidence_from_severity(severity: str) -> float:
    """
    Assign a baseline confidence based on severity.
    The deduplication/scoring engine will refine this later.
    """
    return {"HIGH": 0.7, "MEDIUM": 0.5, "LOW": 0.3}.get(severity, 0.3)


# ---------------------------------------------------------------------------
# Parser: Bandit
# ---------------------------------------------------------------------------

def parse_bandit(raw_json: dict) -> list[dict]:
    """
    Parse Bandit JSON output into a list of unified findings.

    Expected top-level key: "results" (list of issue dicts).

    Args:
        raw_json: Parsed JSON dict from `bandit -f json` output.

    Returns:
        List of normalized finding dicts.
    """
    findings: list[dict] = []
    results = raw_json.get("results", [])

    for item in results:
        rule_id_raw: str = item.get("test_id", "UNKNOWN")
        severity_raw: str = item.get("issue_severity", "LOW")
        severity = _normalize_severity_bandit(severity_raw)

        finding = {
            "path":       item.get("filename", "UNKNOWN"),
            "line":       item.get("line_number"),           # int or None
            "tool":       ["Bandit"],
            "rule_id":    BANDIT_TO_CWE.get(rule_id_raw, "CWE-UNKNOWN"),
            "severity":   severity,
            "message":    item.get("issue_text", "").strip(),
            "confidence": _initial_confidence_from_severity(severity),
        }
        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Parser: Semgrep
# ---------------------------------------------------------------------------

def parse_semgrep(raw_json: dict) -> list[dict]:
    """
    Parse Semgrep JSON output into a list of unified findings.

    Semgrep JSON structure:
      { "results": [ { "path", "start": {"line"}, "check_id",
                       "extra": { "message", "severity",
                                  "metadata": { "cwe": [...] } } } ] }

    Also handles SARIF format if 'runs' key is present.

    Args:
        raw_json: Parsed JSON dict from `semgrep --json` output.

    Returns:
        List of normalized finding dicts.
    """
    # Detect SARIF vs plain JSON
    if "runs" in raw_json:
        return _parse_semgrep_sarif(raw_json)

    findings: list[dict] = []
    results = raw_json.get("results", [])

    for item in results:
        extra: dict     = item.get("extra", {})
        metadata: dict  = extra.get("metadata", {})
        severity_raw    = extra.get("severity", "INFO")
        severity        = _normalize_severity_semgrep(severity_raw)
        cwe             = _extract_cwe_semgrep(metadata)

        # Fallback: if no CWE in metadata, try to infer from check_id
        if cwe == "CWE-UNKNOWN":
            check_id: str = item.get("check_id", "")
            # check_id often contains descriptive slug, keep as fallback rule_id
            rule_id = check_id if check_id else "CWE-UNKNOWN"
        else:
            rule_id = cwe

        finding = {
            "path":       item.get("path", "UNKNOWN"),
            "line":       item.get("start", {}).get("line"),
            "tool":       ["Semgrep"],
            "rule_id":    rule_id,
            "severity":   severity,
            "message":    extra.get("message", "").strip(),
            "confidence": _initial_confidence_from_severity(severity),
        }
        findings.append(finding)

    return findings


def _parse_semgrep_sarif(sarif_json: dict) -> list[dict]:
    """
    Parse Semgrep SARIF output (when --sarif flag is used).

    SARIF structure:
      { "runs": [ { "results": [ { "ruleId", "message": {"text"},
                                   "locations": [ { "physicalLocation":
                                     { "artifactLocation": {"uri"},
                                       "region": {"startLine"} } } ],
                                   "level" } ] } ] }
    """
    findings: list[dict] = []

    for run in sarif_json.get("runs", []):
        # Build a rule lookup: ruleId → { properties: { cwe, severity } }
        rules_lookup: dict[str, Any] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules_lookup[rule.get("id", "")] = rule

        for result in run.get("results", []):
            rule_id_raw: str = result.get("ruleId", "")
            level: str       = result.get("level", "warning")  # SARIF levels
            severity = _normalize_severity_semgrep(
                {"error": "ERROR", "warning": "WARNING", "note": "INFO"}.get(level, "INFO")
            )

            # Extract CWE from rule metadata if available
            rule_meta = rules_lookup.get(rule_id_raw, {})
            props     = rule_meta.get("properties", {})
            cwe       = _extract_cwe_semgrep(props) if props else "CWE-UNKNOWN"
            if cwe == "CWE-UNKNOWN" and rule_id_raw:
                cwe = rule_id_raw  # fallback to rule ID slug

            # Extract location
            locations     = result.get("locations", [])
            path          = "UNKNOWN"
            line: int | None = None
            if locations:
                phys = locations[0].get("physicalLocation", {})
                path = phys.get("artifactLocation", {}).get("uri", "UNKNOWN")
                line = phys.get("region", {}).get("startLine")

            message = result.get("message", {}).get("text", "").strip()

            finding = {
                "path":       path,
                "line":       line,
                "tool":       ["Semgrep"],
                "rule_id":    cwe,
                "severity":   severity,
                "message":    message,
                "confidence": _initial_confidence_from_severity(severity),
            }
            findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Parser: ESLint
# ---------------------------------------------------------------------------

def parse_eslint(raw_json: list, base_dir: str = "") -> list[dict]:
    """
    Parse ESLint JSON output into a list of unified findings.

    ESLint JSON structure (a list of file objects):
      [ { "filePath": "/abs/path/file.js",
          "messages": [ { "ruleId", "severity", "message", "line" } ] } ]

    Args:
        raw_json:  Parsed JSON list from `eslint --format json` output.
        base_dir:  Optional base directory to make paths relative.

    Returns:
        List of normalized finding dicts.
    """
    findings: list[dict] = []

    for file_entry in raw_json:
        abs_path: str      = file_entry.get("filePath", "UNKNOWN")
        rel_path: str      = _make_path_relative(abs_path, base_dir)
        messages: list     = file_entry.get("messages", [])

        for msg in messages:
            rule_id_raw: str  = msg.get("ruleId") or "UNKNOWN"
            severity_raw: int = msg.get("severity", 1)
            severity          = _normalize_severity_eslint(severity_raw)

            finding = {
                "path":       rel_path,
                "line":       msg.get("line"),
                "tool":       ["ESLint"],
                "rule_id":    ESLINT_TO_CWE.get(rule_id_raw, "CWE-UNKNOWN"),
                "severity":   severity,
                "message":    msg.get("message", "").strip(),
                "confidence": _initial_confidence_from_severity(severity),
            }
            findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Master Normalizer
# ---------------------------------------------------------------------------

def normalize_all(raw_results: dict) -> list[dict]:
    """
    Run all available parsers and return a single flat list of findings.

    Args:
        raw_results: Dict keyed by tool name, e.g.:
            {
                "Bandit":  {"stdout_file": "output/raw/bandit_raw.json",  "exit_code": 0, ...},
                "Semgrep": {"stdout_file": "output/raw/semgrep_raw.json", "exit_code": 0, ...},
                "ESLint":  {"stdout_file": "output/raw/eslint_raw.json",  "exit_code": 0, ...},
            }

    Returns:
        Combined list of normalized findings from all tools.
    """
    def _load(path: str) -> Any:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    all_findings: list[dict] = []

    if "Bandit" in raw_results:
        raw = _load(raw_results["Bandit"]["stdout_file"])
        findings = parse_bandit(raw)
        print(f"[Bandit]  {len(findings)} findings parsed.")
        all_findings.extend(findings)

    if "Semgrep" in raw_results:
        raw = _load(raw_results["Semgrep"]["stdout_file"])
        findings = parse_semgrep(raw)
        print(f"[Semgrep] {len(findings)} findings parsed.")
        all_findings.extend(findings)

    if "ESLint" in raw_results:
        raw = _load(raw_results["ESLint"]["stdout_file"])
        findings = parse_eslint(raw)
        print(f"[ESLint]  {len(findings)} findings parsed.")
        all_findings.extend(findings)

    print(f"\n✅ Total normalized findings: {len(all_findings)}")
    return all_findings


# ---------------------------------------------------------------------------
# Convenience: load from file paths
# ---------------------------------------------------------------------------

def normalize_from_files(
    bandit_path:     str | None = None,
    semgrep_path:    str | None = None,
    eslint_path:     str | None = None,
    eslint_base_dir: str = "",
) -> list[dict]:
    """
    Load raw output files from disk, parse, and normalize.

    Args:
        bandit_path:     Path to bandit JSON output file.
        semgrep_path:    Path to semgrep JSON (or SARIF) output file.
        eslint_path:     Path to eslint JSON output file.
        eslint_base_dir: Optional base directory for relative ESLint paths.

    Returns:
        Combined list of normalized findings.
    """
    def load_json(path: str) -> Any:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    bandit_raw  = load_json(bandit_path)  if bandit_path  else None
    semgrep_raw = load_json(semgrep_path) if semgrep_path else None
    eslint_raw  = load_json(eslint_path)  if eslint_path  else None

    return normalize_all(
        bandit_raw=bandit_raw,
        semgrep_raw=semgrep_raw,
        eslint_raw=eslint_raw,
        eslint_base_dir=eslint_base_dir,
    )


# ---------------------------------------------------------------------------
# Quick smoke test (run directly: python normalizer.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    # --- Minimal synthetic samples to verify parsers work ---

    sample_bandit = {
        "results": [
            {
                "filename": "app/utils.py",
                "line_number": 42,
                "test_id": "B602",
                "issue_severity": "HIGH",
                "issue_text": "subprocess call with shell=True identified, security issue.",
            },
            {
                "filename": "app/auth.py",
                "line_number": 10,
                "test_id": "B303",
                "issue_severity": "MEDIUM",
                "issue_text": "Use of MD5 considered insecure.",
            },
        ]
    }

    sample_semgrep = {
        "results": [
            {
                "path": "app/db.py",
                "start": {"line": 17},
                "check_id": "python.django.security.injection.sql",
                "extra": {
                    "message": "Possible SQL injection via string formatting",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89: SQL Injection"]},
                },
            },
            {
                "path": "app/utils.py",
                "start": {"line": 42},
                "check_id": "python.lang.security.subprocess-shell-true",
                "extra": {
                    "message": "subprocess called with shell=True",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
                },
            },
        ]
    }

    sample_eslint = [
        {
            "filePath": "/home/user/myapp/routes/login.js",
            "messages": [
                {
                    "ruleId": "security/detect-sql-injection",
                    "severity": 2,
                    "message": "Found potential SQL injection",
                    "line": 34,
                },
                {
                    "ruleId": "security/detect-eval-with-expression",
                    "severity": 2,
                    "message": "eval with expression is dangerous",
                    "line": 58,
                },
            ],
        }
    ]

    # Write temp files so the smoke test can use the new file-based interface
    import tempfile, pathlib
    tmp = pathlib.Path(tempfile.mkdtemp())
    (tmp / "bandit.json").write_text(json.dumps(sample_bandit))
    (tmp / "semgrep.json").write_text(json.dumps(sample_semgrep))
    (tmp / "eslint.json").write_text(json.dumps(sample_eslint))

    results = normalize_all({
        "Bandit":  {"stdout_file": str(tmp / "bandit.json"),  "exit_code": 0},
        "Semgrep": {"stdout_file": str(tmp / "semgrep.json"), "exit_code": 0},
        "ESLint":  {"stdout_file": str(tmp / "eslint.json"),  "exit_code": 0},
    })

    print("\n--- Normalized Findings ---")
    for i, f in enumerate(results, 1):
        print(f"\n[{i}] {f['severity']} | {f['rule_id']} | {f['path']}:{f['line']}")
        print(f"     Tool: {f['tool']}")
        print(f"     Msg:  {f['message']}")
        print(f"     Conf: {f['confidence']}")
