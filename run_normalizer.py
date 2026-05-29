"""
run_normalizer.py — Quick runner to test the normalizer with a real semgrep.json file
======================================================================================
Usage:
    python run_normalizer.py
    python run_normalizer.py --semgrep path/to/semgrep.json
"""

import json
import argparse


def main():
    parser = argparse.ArgumentParser(description="Run normalizer on a semgrep.json file")
    parser.add_argument(
        "--semgrep",
        default="semgrep.json",
        help="Path to semgrep JSON output file (default: semgrep.json)"
    )
    args = parser.parse_args()

    # --- Load the semgrep.json file ---
    print(f"\n📂 Loading: {args.semgrep}")
    try:
        with open(args.semgrep, "r", encoding="utf-8") as f:
            semgrep_raw = json.load(f)
    except FileNotFoundError:
        print(f"❌ File not found: {args.semgrep}")
        print("   Make sure semgrep.json is in the same folder, or pass the path with --semgrep")
        return
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in file: {e}")
        return

    # --- Run through the normalizer ---
    from normalizer import parse_semgrep
    findings = parse_semgrep(semgrep_raw)

    # --- Print results ---
    print(f"\n{'='*60}")
    print(f"  Semgrep Normalized Findings ({len(findings)} total)")
    print(f"{'='*60}")

    if not findings:
        print("  No findings found.")
        return

    for i, f in enumerate(findings, 1):
        print(f"\n[{i}] {f['severity']:<6}  {f['rule_id']}")
        print(f"     📄 {f['path']}  line {f['line']}")
        print(f"     🔧 Tool: {f['tool']}")
        print(f"     💬 {f['message']}")
        print(f"     📊 Confidence: {f['confidence']}")

    print(f"\n{'='*60}")
    print(f"  ✅ Done — {len(findings)} findings normalized")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
