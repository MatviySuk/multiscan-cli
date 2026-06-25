# MultiScan CLI

A small command-line tool that runs Bandit, Semgrep and ESLint in parallel,
normalizes their outputs into one schema, deduplicates overlapping findings,
and prints a prioritized report. Built for the Secure Software Engineering
course as the "MultiScan CLI" project.

The evaluation target is OWASP Juice Shop v15.0.0; the ground truth and
metrics script live under `evaluation/`.

## Layout

```
multiscan.py            # CLI entry point and orchestrator
normalizer.py           # per-tool JSON parsers + unified schema
deduplicator.py         # duplicate detection and confidence scoring
config/settings.py      # severity tables and similarity thresholds
evaluation/             # ground truth, metrics, committed raw samples
tests/                  # pytest suite (parsers, dedup, metrics, integration)
scripts/                # fetch_juice_shop.sh
```

## Prerequisites

The host system needs:

- Python 3.10 or newer (we use `int | None` PEP 604 syntax)
- Node.js 18 or newer (required by ESLint 9)
- `npm`, `git`, `bash`

Everything else (`semgrep`, `bandit`, `pytest`, `eslint`, `eslint-plugin-security`)
is pinned in `requirements.txt` and `package.json` and installed by the setup
commands below.

## Setup

From a fresh clone, run these once:

```bash
python3 -m venv .venv
source .venv/bin/activate                   # required for every shell session
pip install -r requirements.txt             # semgrep, bandit, click, rich, pytest
npm install                                 # eslint + eslint-plugin-security (local)
bash scripts/fetch_juice_shop.sh            # clones Juice Shop v15.0.0 into ./juice-shop
```

ESLint is resolved from `./node_modules/.bin/` first, so a local `npm install`
is enough; you do not need a global install. Activating the venv is what puts
`semgrep` and `bandit` on the path. If you open a new shell, `source` it again
before running the CLI.

## Quick smoke test

To confirm the install end-to-end without waiting on a full Juice Shop scan:

```bash
python multiscan.py --target ./test_vuln       # 12 raw -> 5 deduped
pytest -q                                       # 131 tests
```

## Run

```bash
# whole repo, auto-pick tools
python multiscan.py --target ./juice-shop --output results.json

# python-only target
python multiscan.py --target ./test_vuln --lang python

# baseline mode: hide findings already present in a previous report
python multiscan.py --target ./juice-shop --baseline results.json
```

The terminal summary prints raw count, dedup count, baseline-filtered count
(when `--baseline` is passed) and scan duration. The JSON written by
`--output` is the deduplicated list, in the unified schema.

## Unified schema

Every finding, regardless of which tool produced it, ends up shaped like:

```json
{
  "path": "routes/search.ts",
  "line": 23,
  "tool": ["Semgrep"],
  "rule_id": "CWE-89",
  "severity": "HIGH",
  "message": "SQL injection via raw sequelize.query",
  "confidence": 0.66
}
```

`tool` is a list because the deduplicator merges multi-tool agreements into
a single entry.

## How deduplication decides

Two findings are merged when they share the same file path and at least two
of the following hold:

- their line numbers are within ±5 lines of each other,
- they carry the same CWE,
- their messages are at least 65% similar (Python's `difflib.SequenceMatcher`).

The same-file precondition was added after we saw the unconditional 2-of-3
rule merge unrelated CWE-89 findings across `routes/search.ts` and
`routes/login.ts`. The thresholds live in `config/settings.py`.

## Confidence score

After merging, each finding is scored:

```
confidence = 0.4 * tool_agreement
           + 0.25 * severity
           + 0.2  * cwe_agreement
           + 0.15 * location_overlap
```

`tool_agreement` is `len(tools) / 3`, `severity` is HIGH=1.0 / MED=0.6 /
LOW=0.3, and the two agreement fields are 1.0 when all merged findings
share the same CWE or location and 0.5 otherwise.

## Evaluation

```bash
python multiscan.py --target ./juice-shop --output results.json
# Look at the summary line, e.g.: "Raw findings: 1358 | Duplicates removed: ..."
# Pass that number as the second argument to metrics.py:
python evaluation/metrics.py results.json 1358
```
The evaluation report PDF file can be accessed here: [Evaluation report](Evaluation%20report.pdf)

`metrics.py` reports both an exact-CWE match score and a CWE-family score
(so a Semgrep CWE-1104 detection on a ground-truth CWE-94 entry still counts
as a true positive). Results are saved to `evaluation/evaluation_results.json`.

On a clean v15.0.0 run we see roughly:
- raw: 1358, deduped: 49, reduction rate: 96.4%
- exact-CWE recall: 75% (9/12), precision: 18.4%
- CWE-family recall: 83.3% (10/12), precision: 20.4%

Sample raw scans from a v15.0.0 run live in `evaluation/raw_samples/` so the
before/after comparison is reproducible without re-running the tools.

## Tests

```bash
pytest -q
```

Covers the parsers, severity/CWE mappers, the deduplication logic and the
metric computations.

## Notes

- The `--lang` filter currently routes to `Semgrep + Bandit` (python) or
  `Semgrep + ESLint` (javascript). Without the flag, all three are run.
- Bandit produces no findings on a TypeScript target; that is expected.
- ESLint emits ~1300 `detect-object-injection` warnings on Juice Shop's
  minified vendor bundles; the deduplicator collapses these into a handful.
