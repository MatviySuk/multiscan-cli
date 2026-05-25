import click
import json
import subprocess
import time
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.logging import RichHandler

# --- Interfaces for Teammates ---
from normalizer import normalize_all
from deduplicator import deduplicate_and_score

# Setup logging
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
log = logging.getLogger("multiscan")
console = Console()

class MultiScanCLI:
    """
    Core Orchestrator for MultiScan CLI (Part 1).
    Handles tool execution, baseline filtering, and reporting.
    """
    
    def __init__(self, target: str, lang: Optional[str], baseline: Optional[str] = None, output: Optional[str] = None):
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
            "duplicates_removed": 0
        }

    def check_dependencies(self, tools: List[str]) -> List[str]:
        """Check if required security tools are installed on the system."""
        missing = []
        for tool in tools:
            # Safer check than shell=True
            cmd = "where" if os.name == "nt" else "which"
            try:
                result = subprocess.run([cmd, tool.lower()], capture_output=True, text=True)
                if result.returncode != 0:
                    missing.append(tool)
            except Exception:
                missing.append(tool)
        return missing

    def run_analyzer(self, tool_name: str, cmd_args: List[str]) -> Dict[str, Any]:
        """
        Runs a single analyzer tool as a subprocess.
        Uses list-based arguments for security (prevents shell injection).
        """
        log.info(f"Starting {tool_name}...")
        start_time = time.time()
        
        # Ensure raw output directory exists
        os.makedirs("output/raw", exist_ok=True)
        raw_output_path = f"output/raw/{tool_name.lower()}_raw.json"

        try:
            # Secure execution: No shell=True
            process = subprocess.run(
                cmd_args, 
                capture_output=True, 
                text=True, 
                timeout=300 # 5 minute safety timeout
            )
            
            duration = time.time() - start_time
            
            # Save raw output for Part 2 teammate
            with open(raw_output_path, "w") as f:
                f.write(process.stdout)

            # Logic Check: Semgrep returns 1 if findings are found, so we check stderr/stdout
            if process.returncode != 0:
                if not process.stdout and process.stderr:
                    log.error(f"{tool_name} error: {process.stderr[:100]}...")
                    return {"tool": tool_name, "error": "Execution Failed", "exit_code": process.returncode}

            log.info(f"Finished {tool_name} in {duration:.2f}s")
            return {
                "tool": tool_name,
                "stdout_file": raw_output_path,
                "exit_code": process.returncode,
                "duration": duration
            }

        except subprocess.TimeoutExpired:
            log.error(f"{tool_name} timed out after 5 minutes.")
            return {"tool": tool_name, "error": "Timeout", "exit_code": -1}
        except Exception as e:
            log.error(f"{tool_name} exception: {str(e)}")
            return {"tool": tool_name, "error": str(e), "exit_code": -1}

    def orchestrate(self) -> None:
        """Manages the parallel execution pipeline."""
        self.stats["start_time"] = time.time()
        
        # Tool Configuration Registry
        # Format: ToolName -> [Command, Args...]
        registry = {
            "Semgrep": ["semgrep", "scan", "--json", "--quiet", self.target],
            "Bandit": ["bandit", "-r", self.target, "-f", "json"],
            "ESLint": ["eslint", self.target, "--format", "json"]
        }
        
        # Filtering based on --lang requirement
        tools_to_run = ["Semgrep"]
        if self.lang == "python":
            tools_to_run.append("Bandit")
        elif self.lang == "javascript":
            tools_to_run.append("ESLint")
        else:
            # Default: attempt all if no lang filter
            tools_to_run = list(registry.keys())

        missing_tools = self.check_dependencies(tools_to_run)
        active_tools = [t for t in tools_to_run if t not in missing_tools]
        self.stats["tools_attempted"] = len(active_tools)

        if missing_tools:
            log.warning(f"Tools not installed: {', '.join(missing_tools)}. Skipping.")

        if not active_tools:
            console.print("\n[red]CRITICAL: No security tools available to run. Check your PATH.[/red]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True
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
        """Filters findings against a baseline report."""
        if not self.baseline:
            return findings

        if not os.path.exists(self.baseline):
            log.warning(f"Baseline {self.baseline} not found.")
            return findings

        try:
            with open(self.baseline, 'r') as f:
                baseline_data = json.load(f)
            
            # Fingerprint: location + rule
            fingerprints = {f"{f['path']}:{f['line']}:{f['rule_id']}" for f in baseline_data}
            new_findings = [f for f in findings if f"{f['path']}:{f['line']}:{f['rule_id']}" not in fingerprints]
            
            self.stats["duplicates_removed"] += (len(findings) - len(new_findings))
            return new_findings
        except Exception as e:
            log.error(f"Baseline error: {e}")
            return findings

    def render_report(self, findings: List[Dict[str, Any]]) -> None:
        """Renders the high-visibility terminal report."""
        console.print("\n" + "=" * 60)
        console.print("🔍 MultiScan CLI | Results", style="bold green")
        console.print("=" * 60)
        
        if not findings:
            console.print("[bold green]✨ Clean Scan: No vulnerabilities identified![/bold green]")
        else:
            table = Table(box=None, padding=(0, 2), show_header=False)
            table.add_column("Sev", width=8)
            table.add_column("ID", width=12)
            table.add_column("Location", width=30)
            table.add_column("Message")
            table.add_column("Conf", justify="right")

            for f in findings:
                sev = f['severity'].upper()
                color = "red" if sev == "HIGH" else "yellow" if sev == "MEDIUM" else "blue"
                
                table.add_row(
                    f"[{color}][{sev}][/{color}]",
                    f"{f['rule_id']}",
                    f"{f['path']}:{f['line']}",
                    f"{f['message']} [dim]({' + '.join(f['tool'])})[/dim]",
                    f"conf: {f['confidence']:.2f}"
                )
            console.print(table)

        console.print("=" * 60)
        duration = self.stats["end_time"] - self.stats["start_time"]
        
        summary = (
            f"Duplicates removed: [green]{self.stats['duplicates_removed']}[/green]  |  "
            f"Total findings: [bold]{len(findings)}[/bold]  |  "
            f"Tools run: [bold]{len(self.raw_results)}[/bold]"
        )
        console.print(summary)
        console.print(f"[dim]Total scan duration: {duration:.2f}s[/dim]")
        console.print("=" * 60 + "\n")

@click.command()
@click.option('--target', required=True, type=click.Path(exists=True), help='Path to scan.')
@click.option('--lang', type=click.Choice(['python', 'javascript']), help='Filter for language.')
@click.option('--baseline', type=click.Path(), help='Baseline JSON.')
@click.option('--output', type=click.Path(), help='JSON export path.')
def main(target: str, lang: Optional[str], baseline: Optional[str], output: Optional[str]):
    scanner = MultiScanCLI(target, lang, baseline, output)
    
    # 1. ORCHESTRATION
    scanner.orchestrate()
    
    # 2. NORMALIZATION (Part 2)
    normalized = normalize_all(scanner.raw_results)
    
    # 3. DEDUPLICATION (Part 3)
    processed, stats = deduplicate_and_score(normalized)
    scanner.stats.update(stats)
    
    # 4. BASELINE
    final = scanner.apply_baseline(processed)
    
    # 5. REPORT
    scanner.render_report(final)
    
    # 6. EXPORT
    if output:
        try:
            with open(output, 'w') as f:
                json.dump(final, f, indent=4)
            log.info(f"Results exported to {output}")
        except Exception as e:
            log.error(f"Export failed: {e}")

if __name__ == "__main__":
    main()
