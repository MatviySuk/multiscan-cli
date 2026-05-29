from difflib import SequenceMatcher

from config.settings import (
    SEVERITY_ORDER,
    SEVERITY_SCORES,
    MESSAGE_SIMILARITY_THRESHOLD,
)


def location_match(first_finding, second_finding):
    """
    Check if:
    - findings are in the same file
    - findings are within 5 lines of each other

    If both are true, they may be duplicates.
    """

    return (
        first_finding["path"] == second_finding["path"]
        and abs(first_finding["line"] - second_finding["line"]) <= 5
    )


def cwe_match(first_finding, second_finding):
    """
    Check if findings share the same CWE.
    """

    return first_finding["rule_id"] == second_finding["rule_id"]


def message_similarity(first_finding, second_finding):
    """
    Compare vulnerability messages using fuzzy matching.
    Returns similarity score between 0 and 1.
    """

    return SequenceMatcher(
        None,
        str(first_finding["message"]).lower(),
        str(second_finding["message"]).lower(),
    ).ratio()


def is_duplicate(first_finding, second_finding):
    """
    A finding is considered duplicate if at least
    TWO conditions match:
    - same location region
    - same CWE
    - similar messages
    """

    matches = 0

    if location_match(first_finding, second_finding):
        matches += 1

    if cwe_match(first_finding, second_finding):
        matches += 1

    if (
        message_similarity(first_finding, second_finding)
        >= MESSAGE_SIMILARITY_THRESHOLD
    ):
        matches += 1

    return matches >= 2


def calculate_confidence(finding, unique_cwes=1, unique_locations=1):
    """
    Calculate confidence score based on:
    - tool agreement
    - severity
    - CWE agreement
    - location overlap
    """

    # Tool agreement
    tool_agreement = min(len(finding["tool"]) / 3, 1.0)

    # Severity score
    severity = finding["severity"].upper()
    severity_score = SEVERITY_SCORES.get(severity, 0.3)

    # If multiple tools reported this but they found DIFFERENT CWEs, cwe_score drops
    # 1.0 if they all agreed on the same CWE, else 0.5 (or less)
    cwe_score = 1.0 if unique_cwes == 1 else 0.5
    
    # If they all reported the exact same location, location_score = 1.0, else 0.5
    location_score = 1.0 if unique_locations == 1 else 0.5

    confidence = (
        0.4 * tool_agreement
        + 0.25 * severity_score
        + 0.2 * cwe_score
        + 0.15 * location_score
    )

    return round(confidence, 2)


def deduplicate_and_score(normalized_findings):
    """
    PART 3 — Deduplication & Confidence Scoring

    Incoming:
        List of normalized findings.

    Outcoming:
        processed findings + statistics
    """

    processed = []
    stats = {"duplicates_removed": 0}

    used = set()

    for i in range(len(normalized_findings)):
        if i in used:
            continue

        current = normalized_findings[i]
        
        # Track unique CWEs and Locations for dynamic scoring
        merged_cwes = {current["rule_id"]}
        merged_locations = {f"{current['path']}:{current['line']}"}

        for finding in range(i + 1, len(normalized_findings)):
            if finding in used:
                continue

            candidate = normalized_findings[finding]

            if is_duplicate(current, candidate):
                merged_tools = list(set(current["tool"] + candidate["tool"]))
                merged_cwes.add(candidate["rule_id"])
                merged_locations.add(f"{candidate['path']}:{candidate['line']}")

                current_severity = current["severity"].upper()
                candidate_severity = candidate["severity"].upper()

                if (
                    SEVERITY_ORDER.get(current_severity, 0)
                    >= SEVERITY_ORDER.get(candidate_severity, 0)
                ):
                    severity = current_severity
                else:
                    severity = candidate_severity

                message = max([current["message"], candidate["message"]], key=len)

                current = {
                    "path": current["path"],
                    "line": min(current["line"], candidate["line"]),
                    "tool": merged_tools,
                    "rule_id": current["rule_id"],
                    "severity": severity,
                    "message": message,
                    "confidence": 0.0,
                }

                used.add(finding)

        current["confidence"] = calculate_confidence(current, len(merged_cwes), len(merged_locations))

        processed.append(current)

    stats["duplicates_removed"] = len(normalized_findings) - len(processed)

    return processed, stats
