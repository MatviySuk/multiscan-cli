def deduplicate_and_score(normalized_findings):
    """
    INTERFACE FOR PART 3 (Deduplication & Scoring Algorithm)
    
    Incoming: List of normalized findings (from Part 2)
    
    Outcoming: (processed_findings, stats)
        processed_findings: Deduplicated list with calculated confidence.
        stats: Dictionary with 'duplicates_removed' count.
    """
    
    # TODO: Teammate implementing Part 3 should:
    # 1. Group findings by File + Line Range (+-5)
    # 2. Check for CWE similarity
    # 3. Apply the Formula: 
    #    Confidence = 0.4*ToolAgreement + 0.25*Severity + 0.2*CWEAgreement + 0.15*LocationOverlap
    
    processed = []
    stats = {"duplicates_removed": 0}

    # --- MOCK DATA FOR INITIAL TESTING ---
    # Teammate: Replace this with your grouping and math logic!
    processed = [
        {
            "path": "app/utils.py", "line": 42, "tool": ["Bandit", "Semgrep"],
            "rule_id": "CWE-78", "severity": "HIGH", "confidence": 0.92,
            "message": "Command injection via subprocess shell=True"
        }
    ]
    stats["duplicates_removed"] = len(normalized_findings) - len(processed)
    
    return processed, stats
