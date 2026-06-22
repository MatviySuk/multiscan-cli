"""Orchestrate Bandit, Semgrep and ESLint scans, then print/export the merged report."""

import click
import json
import subprocess
import time
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.logging import RichHandler

from normalizer import normalize_all
from deduplicator import deduplicate_and_score


logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)
log = logging.getLogger("multiscan")
console = Console()


SEVERITY_RANK = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}


class MultiScanCLI:
    def __init__(
        self,
        target: str,
        lang: Optional[str],
        baseline: Optional[str] = None,
        output: Optional[str] = None,
    ):
        self.target = os.path.abspath(target)
        self.lang = lang
        self.baseline = baseline
        self.output = output
        self.raw_results: Dict[str, Dict[str, Any]] = {}

        now = time.time()
        self.stats = {
            "start_time": now,
            "end_time": now,
            "tools_attempted": 0,
            "tools_failed": 0,
            "raw_findings": 0,
            "duplicates_removed": 0,
            "baseline_filtered": 0,
        }

    def check_dependencies(self, tools: List[str]) -> List[str]:
        missing = []
        which = "where" if os.name == "nt" else "which"
        for tool in tools:
            try:
                result = subprocess.run(
                    [which, tool.lower()], capture_output=True, text=True
                )
                if result.returncode != 0:
                    missing.append(tool)
            except Exception:
                missing.append(tool)
        return missing

    def run_analyzer(self, tool_name: str, cmd_args: List[str]) -> Dict[str, Any]:
        log.info(f"Starting {tool_name}...")
        start_time = time.time()

        os.makedirs("output/raw", exist_ok=True)
        raw_output_path = f"output/raw/{tool_name.lower()}_raw.json"

        try:
            process = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=300,
            )

            duration = time.time() - start_time

            with open(raw_output_path, "w") as f:
                f.write(process.stdout)

            # Semgrep exits 1 when it finds issues, so a non-zero code is only
            # a real failure if there's nothing on stdout to parse.
            if process.returncode != 0 and not process.stdout and process.stderr:
                log.error(f"{tool_name} error: {process.stderr[:100]}...")
                return {
                    "tool": tool_name,
                    "error": "Execution Failed",
                    "exit_code": process.returncode,
                }

            log.info(f"Finished {tool_name} in {duration:.2f}s")
            return {
                "tool": tool_name,
                "stdout_file": raw_output_path,
                "exit_code": process.returncode,
                "duration": duration,
            }

        except subprocess.TimeoutExpired:
            log.error(f"{tool_name} timed out after 5 minutes.")
            return {"tool": tool_name, "error": "Timeout", "exit_code": -1}
        except Exception as e:
            log.error(f"{tool_name} exception: {str(e)}")
            return {"tool": tool_name, "error": str(e), "exit_code": -1}

    def orchestrate(self) -> None:
        self.stats["start_time"] = time.time()

        registry = {
            "Semgrep": ["semgrep", "scan", "--json", "--quiet", self.target],
            "Bandit": ["bandit", "-r", self.target, "-f", "json"],
            "ESLint": ["eslint", self.target, "--format", "json"],
        }

        if self.lang == "python":
            tools_to_run = ["Semgrep", "Bandit"]
        elif self.lang == "javascript":
            tools_to_run = ["Semgrep", "ESLint"]
        else:
            tools_to_run = list(registry.keys())

        missing_tools = self.check_dependencies(tools_to_run)
        active_tools = [t for t in tools_to_run if t not in missing_tools]
        self.stats["tools_attempted"] = len(active_tools)

        if missing_tools:
            log.warning(f"Tools not installed: {', '.join(missing_tools)}. Skipping.")

        if not active_tools:
            console.print(
                "\n[red]No security tools available to run. Check your PATH.[/red]"
            )
            self.stats["end_time"] = time.time()
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("[cyan]Scanning...", total=len(active_tools))

            with ThreadPoolExecutor(max_workers=len(active_tools)) as executor:
                futures = {
                    executor.submit(self.run_analyzer, name, registry[name]): name
                    for name in active_tools
                }

                for future in as_completed(futures):
                    tool_name = futures[future]
                    result = future.result()
                    self.raw_results[tool_name] = result
                    if "error" in result:
                        self.stats["tools_failed"] += 1
                    progress.advance(task_id)

        self.stats["end_time"] = time.time()

    def apply_baseline(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self.baseline:
            return findings

        if not os.path.exists(self.baseline):
            log.warning(f"Baseline {self.baseline} not found.")
            return findings

        try:
            with open(self.baseline, "r") as f:
                baseline_data = json.load(f)

            fingerprints = {
                f"{f['path']}:{f['line']}:{f['rule_id']}" for f in baseline_data
            }
            new_findings = [
                f
                for f in findings
                if f"{f['path']}:{f['line']}:{f['rule_id']}" not in fingerprints
            ]

            self.stats["baseline_filtered"] += len(findings) - len(new_findings)
            return new_findings
        except Exception as e:
            log.error(f"Baseline error: {e}")
            return findings

    def render_report(self, findings: List[Dict[str, Any]]) -> None:
        console.print("\n" + "=" * 60)
        console.print("MultiScan CLI | Results", style="bold green")
        console.print("=" * 60)

        if not findings:
            console.print("[bold green]No vulnerabilities identified.[/bold green]")
        else:
            table = Table(box=None, padding=(0, 2), show_header=False)
            table.add_column("Sev", width=8)
            table.add_column("ID", width=12)
            table.add_column("Location", width=30)
            table.add_column("Message")
            table.add_column("Conf", justify="right")

            sorted_findings = sorted(
                findings,
                key=lambda f: (
                    -SEVERITY_RANK.get(f["severity"].upper(), 0),
                    -f["confidence"],
                ),
            )

            for f in sorted_findings:
                sev = f["severity"].upper()
                color = "red" if sev == "HIGH" else "yellow" if sev == "MEDIUM" else "blue"
                table.add_row(
                    f"[{color}][{sev}][/{color}]",
                    f["rule_id"],
                    f"{f['path']}:{f['line']}",
                    f"{f['message']} [dim]({' + '.join(f['tool'])})[/dim]",
                    f"conf: {f['confidence']:.2f}",
                )
            console.print(table)

        console.print("=" * 60)
        duration = self.stats["end_time"] - self.stats["start_time"]
        successful_tools = self.stats["tools_attempted"] - self.stats["tools_failed"]

        raw = self.stats["raw_findings"]
        dups = self.stats["duplicates_removed"]
        base = self.stats["baseline_filtered"]
        reduction = (dups / raw * 100) if raw else 0.0

        console.print(
            f"Raw findings: [bold]{raw}[/bold]  |  "
            f"Duplicates removed: [green]{dups}[/green] ({reduction:.1f}%)  |  "
            f"After dedup: [bold]{raw - dups}[/bold]"
        )
        if self.baseline:
            console.print(
                f"Baseline filtered: [cyan]{base}[/cyan]  |  Reported: [bold]{len(findings)}[/bold]"
            )
        console.print(
            f"Tools run: [bold]{successful_tools}[/bold]  |  Duration: {duration:.2f}s"
        )
        console.print("=" * 60 + "\n")


@click.command()
@click.option("--target", required=True, type=click.Path(exists=True), help="Path to scan.")
@click.option("--lang", type=click.Choice(["python", "javascript"]), help="Filter for language.")
@click.option("--baseline", type=click.Path(), help="Baseline JSON.")
@click.option("--output", type=click.Path(), help="JSON export path.")
def main(target: str, lang: Optional[str], baseline: Optional[str], output: Optional[str]):
    scanner = MultiScanCLI(target, lang, baseline, output)

    scanner.orchestrate()

    normalized = normalize_all(scanner.raw_results, base_dir=scanner.target)
    scanner.stats["raw_findings"] = len(normalized)

    processed, dedup_stats = deduplicate_and_score(normalized)
    scanner.stats["duplicates_removed"] = dedup_stats.get("duplicates_removed", 0)

    final = scanner.apply_baseline(processed)
    scanner.render_report(final)

    if output:
        try:
            with open(output, "w") as f:
                json.dump(final, f, indent=4)
            log.info(f"Results exported to {output}")
        except Exception as e:
            log.error(f"Export failed: {e}")


if __name__ == "__main__":
    main()
