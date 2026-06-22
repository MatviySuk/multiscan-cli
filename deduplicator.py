"""Merge overlapping findings from multiple tools and score the result."""

from difflib import SequenceMatcher

from config.settings import (
    SEVERITY_ORDER,
    SEVERITY_SCORES,
    MESSAGE_SIMILARITY_THRESHOLD,
)


LINE_PROXIMITY = 5


def location_match(a, b):
    """Same file, lines within LINE_PROXIMITY of each other."""
    if a["path"] != b["path"]:
        return False
    l1, l2 = a.get("line"), b.get("line")
    if l1 is None and l2 is None:
        return True
    if l1 is None or l2 is None:
        return False
    return abs(l1 - l2) <= LINE_PROXIMITY


def cwe_match(a, b):
    return a["rule_id"] == b["rule_id"]


def message_similarity(a, b):
    return SequenceMatcher(None, str(a["message"]).lower(), str(b["message"]).lower()).ratio()


def is_duplicate(a, b):
    """Same file is required; then at least two of: line proximity, CWE, message."""
    if a["path"] != b["path"]:
        return False

    matches = 0
    if location_match(a, b):
        matches += 1
    if cwe_match(a, b):
        matches += 1
    if message_similarity(a, b) >= MESSAGE_SIMILARITY_THRESHOLD:
        matches += 1
    return matches >= 2


def calculate_confidence(finding, unique_cwes=1, unique_locations=1):
    """0.4*tool_agreement + 0.25*severity + 0.2*cwe + 0.15*location."""
    tool_agreement = min(len(finding["tool"]) / 3, 1.0)
    severity_score = SEVERITY_SCORES.get(finding["severity"].upper(), 0.3)
    cwe_score = 1.0 if unique_cwes == 1 else 0.5
    location_score = 1.0 if unique_locations == 1 else 0.5

    confidence = (
        0.4 * tool_agreement
        + 0.25 * severity_score
        + 0.2 * cwe_score
        + 0.15 * location_score
    )
    return round(confidence, 2)


def deduplicate_and_score(normalized_findings):
    """Walk the list once, merging duplicates into the earlier finding."""
    processed = []
    used = set()

    for i in range(len(normalized_findings)):
        if i in used:
            continue

        current = normalized_findings[i]
        merged_cwes = {current["rule_id"]}
        merged_locations = {f"{current['path']}:{current['line']}"}

        for j in range(i + 1, len(normalized_findings)):
            if j in used:
                continue

            candidate = normalized_findings[j]
            if not is_duplicate(current, candidate):
                continue

            merged_tools = list(set(current["tool"] + candidate["tool"]))
            merged_cwes.add(candidate["rule_id"])
            merged_locations.add(f"{candidate['path']}:{candidate['line']}")

            cs = current["severity"].upper()
            ds = candidate["severity"].upper()
            severity = cs if SEVERITY_ORDER.get(cs, 0) >= SEVERITY_ORDER.get(ds, 0) else ds

            message = max(current["message"], candidate["message"], key=len)

            l1, l2 = current.get("line"), candidate.get("line")
            if l1 is not None and l2 is not None:
                merged_line = min(l1, l2)
            else:
                merged_line = l1 if l1 is not None else l2

            current = {
                "path": current["path"],
                "line": merged_line,
                "tool": merged_tools,
                "rule_id": current["rule_id"],
                "severity": severity,
                "message": message,
                "confidence": 0.0,
            }

            used.add(j)

        current["confidence"] = calculate_confidence(
            current, len(merged_cwes), len(merged_locations)
        )
        processed.append(current)

    stats = {"duplicates_removed": len(normalized_findings) - len(processed)}
    return processed, stats
