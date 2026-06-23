"""Compare processed multiscan findings against the manually verified Juice Shop ground truth.

Usage:
    python evaluation/metrics.py <results.json> <raw_total_count>
"""

import json
import sys
from pathlib import Path


LINE_TOLERANCE = 10

# Sub-CWEs frequently emitted for the same underlying weakness. Used so the
# eval doesn't punish a Semgrep CWE-89 against a ground-truth CWE-943 entry
# when both describe the same injection vulnerability.
CWE_FAMILIES = [
    {"CWE-77", "CWE-78", "CWE-89", "CWE-917", "CWE-943"},
    {"CWE-94", "CWE-95", "CWE-502", "CWE-915", "CWE-1104", "CWE-1321", "CWE-1336"},
    {"CWE-259", "CWE-321", "CWE-326", "CWE-327", "CWE-338", "CWE-798"},
    {"CWE-22", "CWE-23", "CWE-73", "CWE-706"},
    {"CWE-79", "CWE-80", "CWE-83", "CWE-87"},
    {"CWE-209", "CWE-532"},
    {"CWE-611", "CWE-776", "CWE-827"},
]


def load_json(path):
    with open(path) as f:
        return json.load(f)


def same_cwe_family(a: str, b: str) -> bool:
    if not a or not b:
        return False
    if a == b:
        return True
    for fam in CWE_FAMILIES:
        if a in fam and b in fam:
            return True
    return False


def matches_ground_truth(finding, gt_entry, family_ok: bool = False):
    """Same basename + (exact CWE or family CWE) + line within tolerance."""
    if Path(finding.get("path", "")).name != Path(gt_entry["path"]).name:
        return False

    finding_cwe = finding.get("rule_id", "")
    gt_cwe = gt_entry["cwe"]
    cwe_ok = same_cwe_family(finding_cwe, gt_cwe) if family_ok else (finding_cwe == gt_cwe)
    if not cwe_ok:
        return False

    line_diff = abs((finding.get("line") or 0) - gt_entry["line"])
    return line_diff <= LINE_TOLERANCE


def evaluate(processed_findings, ground_truth, raw_count, family_ok: bool = False):
    tp_findings = []
    fp_findings = []
    matched_gt_ids = set()

    for finding in processed_findings:
        matched = False
        for gt in ground_truth:
            if gt["id"] in matched_gt_ids:
                continue
            if matches_ground_truth(finding, gt, family_ok):
                tp_findings.append({"finding": finding, "matched_gt": gt["id"]})
                matched_gt_ids.add(gt["id"])
                matched = True
                break
        if not matched:
            fp_findings.append(finding)

    fn_entries = [gt for gt in ground_truth if gt["id"] not in matched_gt_ids]

    tp = len(tp_findings)
    fp = len(fp_findings)
    fn = len(fn_entries)
    processed_count = len(processed_findings)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    dup_reduction = (raw_count - processed_count) / raw_count if raw_count > 0 else 0.0

    return {
        "matching_mode": "cwe_family" if family_ok else "cwe_exact",
        "raw_count": raw_count,
        "processed_count": processed_count,
        "duplicates_removed": raw_count - processed_count,
        "duplicate_reduction_rate": round(dup_reduction, 4),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "tp_findings": [t["matched_gt"] for t in tp_findings],
        "fp_findings": [f.get("path") for f in fp_findings],
        "fn_ground_truth": [gt["id"] for gt in fn_entries],
    }


def print_report(exact, family):
    sep = "=" * 56
    print(f"\n{sep}")
    print("  MultiScan CLI: Evaluation Report")
    print("  Target : OWASP Juice Shop v15.0.0")
    print(sep)

    print("\n  Noise reduction")
    print("  " + "-" * 40)
    print(f"  Raw findings (combined tools) : {family['raw_count']}")
    print(f"  After deduplication           : {family['processed_count']}")
    print(f"  Duplicates removed            : {family['duplicates_removed']}")
    rate = family["duplicate_reduction_rate"] * 100
    target_met = "PASS" if family["duplicate_reduction_rate"] >= 0.30 else "FAIL"
    print(f"  Reduction rate                : {rate:.1f}%  (>=30% target {target_met})")

    for label, metrics in (("Exact-CWE match", exact), ("CWE-family match", family)):
        print(f"\n  Detection quality - {label}")
        print("  " + "-" * 40)
        print(f"  True positives                : {metrics['true_positives']}")
        print(f"  False positives               : {metrics['false_positives']}")
        print(f"  False negatives               : {metrics['false_negatives']}")
        print(f"  Precision                     : {metrics['precision']*100:.1f}%")
        print(f"  Recall                        : {metrics['recall']*100:.1f}%")
        print(f"  F1 score                      : {metrics['f1_score']*100:.1f}%")

    if family["fn_ground_truth"]:
        print(f"\n  Missed ground-truth entries   : {', '.join(family['fn_ground_truth'])}")
    print(f"\n{sep}\n")


if __name__ == "__main__":
    base = Path(__file__).parent
    gt_data = load_json(base / "ground_truth.json")
    ground_truth = gt_data["vulnerabilities"]

    if len(sys.argv) < 3:
        print("Usage: python evaluation/metrics.py <processed_results.json> <raw_total_count>")
        sys.exit(1)

    results_path = Path(sys.argv[1])
    raw_count = int(sys.argv[2])

    raw = load_json(results_path)
    if isinstance(raw, dict):
        processed = raw.get("findings", raw.get("results", list(raw.values())))
    else:
        processed = raw

    exact = evaluate(processed, ground_truth, raw_count, family_ok=False)
    family = evaluate(processed, ground_truth, raw_count, family_ok=True)
    print_report(exact, family)

    out_path = base / "evaluation_results.json"
    with open(out_path, "w") as f:
        json.dump({"exact": exact, "family": family}, f, indent=2)
    print(f"  Full metrics saved to: {out_path}\n")
