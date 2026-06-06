"""Rich console reporter — beautiful CLI output."""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from vulnscan5g.models.scan_result import ScanResult
from vulnscan5g.models.finding import Severity

console = Console()

SEV_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

SEV_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def print_results(result: ScanResult, verbose: bool = False):
    """Print scan results as a rich table."""
    s = result.summary()

    # ── header panel ──────────────────────────────────────────
    header = Text()
    header.append("🛡️  VulnScan5G Report\n", style="bold white")
    header.append(f"Target: {s['target']}\n", style="dim")
    header.append(f"Files scanned: {s['files_scanned']}  |  ", style="dim")
    header.append(f"Duration: {s['duration_seconds']}s\n", style="dim")
    header.append(f"Findings: ", style="white")
    header.append(f"{s['critical']} critical  ", style="bold red")
    header.append(f"{s['high']} high  ", style="red")
    header.append(f"{s['medium']} medium  ", style="yellow")
    header.append(f"{s['low']} low  ", style="cyan")
    header.append(f"{s['info']} info", style="dim")

    console.print(Panel(header, border_style="blue", box=box.DOUBLE))

    if not result.findings:
        console.print("\n[bold green]✅ No vulnerabilities found![/bold green]\n")
        return

    # ── findings table ────────────────────────────────────────
    table = Table(
        title="Vulnerability Findings",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold white on dark_blue",
        title_style="bold",
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Rule", width=10)
    table.add_column("CWE", width=9)
    table.add_column("File", style="cyan", max_width=40)
    table.add_column("Line", width=5, justify="right")
    table.add_column("Vulnerability", max_width=50)
    table.add_column("Detector", width=10)

    for i, f in enumerate(result.findings, 1):
        sev = f.severity.value
        icon = SEV_ICONS.get(sev, "")
        color = SEV_COLORS.get(sev, "white")
        table.add_row(
            str(i),
            Text(f"{icon} {sev.upper()}", style=color),
            f.rule_id,
            f.cwe_id,
            f.file_path.replace("\\", "/").split("/")[-1],
            str(f.line),
            f.vuln_type,
            f.detector,
        )

    console.print(table)

    # ── detailed view (verbose) ───────────────────────────────
    if verbose:
        console.print("\n[bold]📋 Detailed Findings[/bold]\n")
        for i, f in enumerate(result.findings, 1):
            sev = f.severity.value
            color = SEV_COLORS.get(sev, "white")
            console.print(
                Panel(
                    f"[bold]{f.vuln_type}[/bold]\n"
                    f"[dim]File:[/dim] {f.file_path}:{f.line}\n"
                    f"[dim]CWE:[/dim]  {f.cwe_id}\n"
                    f"[dim]Desc:[/dim] {f.description}\n"
                    f"[dim]Fix:[/dim]  {f.recommendation}\n"
                    + (f"\n[dim]LLM:[/dim]  {f.llm_explanation}" if f.llm_explanation else ""),
                    title=f"#{i} [{sev.upper()}]",
                    border_style=color,
                )
            )

    # ── errors ────────────────────────────────────────────────
    if result.errors:
        console.print(f"\n[yellow]⚠️  {len(result.errors)} file(s) had errors:[/yellow]")
        for e in result.errors[:10]:
            console.print(f"  [dim]• {e}[/dim]")


def print_scan_progress(file_path: str, file_num: int, total: int):
    """Print a progress line for the current file."""
    short = file_path.replace("\\", "/").split("/")[-1]
    console.print(f"  [dim][{file_num}/{total}][/dim] Scanning [cyan]{short}[/cyan]…", end="\r")
