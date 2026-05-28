"""
metrics.py — Part 4: Evaluation metrics for MultiScan CLI
Computes TP/FP/FN, precision, recall, F1, and duplicate reduction rate
against the manually verified ground truth for OWASP Juice Shop.

Usage:
    python evaluation/metrics.py <processed_results.json> <raw_total_count>

Example:
    python evaluation/metrics.py output/results.json 23
"""

import json
import sys
from pathlib import Path

LINE_TOLERANCE = 10


def load_json(path):
    with open(path) as f:
        return json.load(f)


def matches_ground_truth(finding, gt_entry):
    """
    Returns True if a processed finding corresponds to a ground truth entry.

    Matching criteria (all three must hold):
      1. Same filename (basename comparison, handles absolute vs relative paths)
      2. Same CWE identifier
      3. Line number within LINE_TOLERANCE of the ground truth line
    """
    finding_name = Path(finding.get("path", "")).name
    gt_name = Path(gt_entry["path"]).name

    if finding_name != gt_name:
        return False

    if finding.get("rule_id") != gt_entry["cwe"]:
        return False

    finding_line = finding.get("line") or 0
    gt_line = gt_entry["line"]

    return abs(finding_line - gt_line) <= LINE_TOLERANCE


def evaluate(processed_findings, ground_truth, raw_count):
    """
    Compare processed findings against the ground truth.

    Returns a dict containing all evaluation metrics.
    """
    tp_findings = []
    fp_findings = []
    matched_gt_ids = set()

    for finding in processed_findings:
        matched = False
        for gt in ground_truth:
            if gt["id"] in matched_gt_ids:
                continue
            if matches_ground_truth(finding, gt):
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
    f1 = (
        (2 * precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    dup_reduction = (raw_count - processed_count) / raw_count if raw_count > 0 else 0.0

    return {
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


def print_report(metrics):
    sep = "=" * 52
    print(f"\n{sep}")
    print("  MultiScan CLI — Evaluation Report")
    print(f"  Target : OWASP Juice Shop v15.0.0")
    print(sep)

    print("\n  Noise Reduction")
    print("  " + "─" * 38)
    print(f"  Raw findings (combined tools) : {metrics['raw_count']}")
    print(f"  After deduplication           : {metrics['processed_count']}")
    print(f"  Duplicates removed            : {metrics['duplicates_removed']}")
    rate = metrics["duplicate_reduction_rate"] * 100
    target_met = "✓ PASS" if metrics["duplicate_reduction_rate"] >= 0.30 else "✗ FAIL"
    print(f"  Reduction rate                : {rate:.1f}%  (≥30% target {target_met})")

    print("\n  Detection Quality")
    print("  " + "─" * 38)
    print(f"  True  positives (TP)          : {metrics['true_positives']}")
    print(f"  False positives (FP)          : {metrics['false_positives']}")
    print(f"  False negatives (FN)          : {metrics['false_negatives']}")
    print(f"  Precision                     : {metrics['precision']*100:.1f}%")
    print(f"  Recall                        : {metrics['recall']*100:.1f}%")
    print(f"  F1 Score                      : {metrics['f1_score']*100:.1f}%")

    if metrics["fn_ground_truth"]:
        print(f"\n  Missed ground-truth entries   : {', '.join(metrics['fn_ground_truth'])}")
    if metrics["fp_findings"]:
        print(f"  False-positive paths          :")
        for fp_path in metrics["fp_findings"]:
            print(f"    - {fp_path}")

    print(f"\n{sep}\n")


if __name__ == "__main__":
    base = Path(__file__).parent

    gt_data = load_json(base / "ground_truth.json")
    ground_truth = gt_data["vulnerabilities"]

    if len(sys.argv) < 3:
        print(
            "Usage: python evaluation/metrics.py <processed_results.json> <raw_total_count>"
        )
        sys.exit(1)

    results_path = Path(sys.argv[1])
    raw_count = int(sys.argv[2])

    raw = load_json(results_path)
    if isinstance(raw, dict):
        processed = raw.get("findings", raw.get("results", list(raw.values())))
    else:
        processed = raw

    metrics = evaluate(processed, ground_truth, raw_count)
    print_report(metrics)

    out_path = base / "evaluation_results.json"
    with open(out_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Full metrics saved to: {out_path}\n")
