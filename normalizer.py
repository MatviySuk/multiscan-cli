import json
import os


def normalize_all(raw_results):
    """
    INTERFACE FOR PART 2 (Data Normalization & Parsers)

    Incoming: raw_results (dict)
        Example: {
            "Semgrep": {"stdout_file": "output/raw/semgrep_raw.json", "exit_code": 0, "duration": 1.2},
            "Bandit": {"stdout_file": "output/raw/bandit_raw.json", "exit_code": 0, "duration": 0.8}
        }

    Outcoming: List of dictionaries matching the Unified JSON Schema.
    """

    normalized_list = []

    # TODO: Teammate implementing Part 2 should:
    # 1. Loop through raw_results keys (Semgrep, Bandit, ESLint)
    # 2. Read the 'stdout_file' for each
    # 3. Parse tool-specific JSON into the unified schema below:

    # Unified Schema Example:
    # {
    #   "path": "app/utils.py",
    #   "line": 42,
    #   "tool": ["ToolName"],
    #   "rule_id": "CWE-XX",
    #   "severity": "HIGH",
    #   "message": "Finding description",
    #   "confidence": 0.8  <-- Default tool confidence before merging
    # }

    # --- MOCK DATA FOR INITIAL TESTING ---
    # This allows Part 1 to run even before Part 2 is finished.
    # Teammate: Replace this with your parsing logic!
    normalized_list = [
        {
            "path": "app/utils.py",
            "line": 42,
            "tool": ["Bandit"],
            "rule_id": "CWE-78",
            "severity": "HIGH",
            "confidence": 0.8,
            "message": "Command injection via subprocess shell=True",
        },
        {
            "path": "app/utils.py",
            "line": 42,
            "tool": ["Semgrep"],
            "rule_id": "CWE-78",
            "severity": "HIGH",
            "confidence": 0.9,
            "message": "Command injection via subprocess shell=True",
        },
    ]

    return normalized_list
