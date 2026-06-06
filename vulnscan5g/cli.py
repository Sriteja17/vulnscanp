"""VulnScan5G — CLI interface powered by Click."""
import sys
import click
from rich.console import Console

from vulnscan5g import __version__

console = Console()


@click.group()
@click.version_option(__version__, prog_name="vulnscan5g")
def main():
    """🛡️  VulnScan5G — C/C++ Vulnerability Detection & Auto-Fix CLI"""
    pass


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--fix", "do_fix", is_flag=True, help="Generate LLM-powered auto-fixes")
@click.option("--llm", "use_llm", is_flag=True, help="Enable LLM reasoning to confirm/reject findings")
@click.option("--model", "model_name", default=None, help="Ollama model name (e.g. codellama:7b, deepseek-coder:6.7b)")
@click.option("--severity", "min_sev", default="low",
              type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
              help="Minimum severity threshold")
@click.option("--report", "report_fmt", default="console",
              type=click.Choice(["console", "json", "html", "all"], case_sensitive=False),
              help="Report output format")
@click.option("--output", "-o", default=None, help="Output file path for json/html reports")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed findings with descriptions")
@click.option("--diff", "show_diff", is_flag=True, help="Show diff between original and fixed code")
def scan(target, do_fix, use_llm, model_name, min_sev, report_fmt, output, verbose, show_diff):
    """Scan C/C++ files or directories for vulnerabilities."""
    from vulnscan5g.pipeline import run_pipeline
    from vulnscan5g.reporter.console import print_results
    from vulnscan5g.reporter.json_report import save_json
    from vulnscan5g.reporter.html_report import save_html

    console.print(f"\n[bold blue]🛡️  VulnScan5G v{__version__}[/bold blue]\n")

    result = run_pipeline(
        target=target,
        min_severity=min_sev,
        use_llm=use_llm,
        do_fix=do_fix,
        verbose=verbose,
        model_name=model_name,
        show_diff=show_diff,
    )

    # ── report output ─────────────────────────────────────────
    if report_fmt in ("console", "all"):
        print_results(result, verbose=verbose)

    if report_fmt in ("json", "all"):
        out = output or "vulnscan5g_report.json"
        save_json(result, out)
        console.print(f"\n[green]📄 JSON report saved → {out}[/green]")

    if report_fmt in ("html", "all"):
        out = output or "vulnscan5g_report.html"
        if report_fmt == "all" and output:
            out = output.replace(".json", ".html")
        save_html(result, out)
        console.print(f"\n[green]🌐 HTML report saved → {out}[/green]")

    # ── CI exit code: return 1 if vulnerabilities found ───────
    if result.findings:
        sys.exit(1)


@main.command()
def rules():
    """List all detection rules."""
    from rich.table import Table
    from rich import box
    from vulnscan5g.detectors.rules import ALL_RULES

    table = Table(title="Detection Rules", box=box.ROUNDED, header_style="bold white on dark_blue")
    table.add_column("ID", width=10)
    table.add_column("Name", width=30)
    table.add_column("CWE", width=9)
    table.add_column("Severity", width=10)
    table.add_column("Languages", width=10)

    sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}

    for r in ALL_RULES:
        sev = r.severity.value
        table.add_row(r.id, r.name, r.cwe_id, f"[{sev_colors.get(sev, 'white')}]{sev.upper()}[/]",
                       ", ".join(r.languages))

    console.print(table)
    console.print(f"\n[dim]Total: {len(ALL_RULES)} rules[/dim]")


@main.command()
@click.argument("target", type=click.Path(exists=True))
def info(target):
    """Show file/project metadata without scanning."""
    from vulnscan5g.ingest.loader import load_files, is_c_file
    from vulnscan5g.preprocess.cleaner import extract_metadata
    from rich.table import Table
    from rich import box

    files = load_files(target)
    if not files:
        console.print("[yellow]No C/C++ files found.[/yellow]")
        return

    table = Table(title="Project Info", box=box.ROUNDED, header_style="bold")
    table.add_column("File", style="cyan")
    table.add_column("Language", width=8)
    table.add_column("Total Lines", justify="right")
    table.add_column("Code Lines", justify="right")
    table.add_column("Functions", justify="right")
    table.add_column("Includes", justify="right")

    for fpath in files[:50]:
        with open(fpath, "r", errors="ignore") as f:
            code = f.read()
        lang = "c" if is_c_file(fpath) else "cpp"
        meta = extract_metadata(fpath, code, lang)
        short = fpath.replace("\\", "/").split("/")[-1]
        table.add_row(short, lang, str(meta.total_lines), str(meta.code_lines),
                       str(len(meta.functions)), str(len(meta.includes)))

    console.print(table)
    console.print(f"\n[dim]Showing {min(len(files), 50)} of {len(files)} files[/dim]")


@main.command()
@click.option("--target", "-t", default="./tests/", type=click.Path(exists=True),
              help="Directory with test files")
def benchmark(target):
    """Run precision/recall benchmark against test files."""
    from vulnscan5g.ingest.loader import load_files, is_c_file
    from vulnscan5g.detectors.regex_detector import RegexDetector
    from vulnscan5g.detectors.ast_detector import ASTDetector
    from vulnscan5g.detectors.treesitter_detector import TreeSitterDetector
    from vulnscan5g.analyzer.merger import merge_findings
    from rich.table import Table
    from rich import box

    console.print("\n[bold blue]📊 VulnScan5G Benchmark[/bold blue]\n")

    files = load_files(target)
    if not files:
        console.print("[yellow]No files found[/yellow]")
        return

    regex_det = RegexDetector()
    ast_det = ASTDetector()
    ts_det = TreeSitterDetector()

    # Classify files: "safe" in name = no vulns expected, otherwise = vulns expected
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0
    total_findings = 0

    results_rows = []

    for fpath in files:
        with open(fpath, "r", errors="ignore") as f:
            code = f.read()
        lang = "c" if is_c_file(fpath) else "cpp"
        fname = fpath.replace("\\", "/").split("/")[-1]

        findings = regex_det.scan(code, fpath, lang)
        findings += ast_det.scan(code, fpath, lang)
        findings += ts_det.scan(code, fpath, lang)
        findings = merge_findings(findings)
        total_findings += len(findings)

        # Only HIGH+ findings matter for accuracy — LOW/INFO are informational
        from vulnscan5g.models.finding import Severity
        significant = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]

        is_safe = "safe" in fname.lower() or "_fixed" in fname.lower() or "_good" in fname.lower()
        has_findings = len(significant) > 0

        if is_safe and not has_findings:
            true_negatives += 1
            status = "[green]TN ✅[/green]"
        elif is_safe and has_findings:
            false_positives += 1
            status = "[red]FP ❌[/red]"
        elif not is_safe and has_findings:
            true_positives += 1
            status = "[green]TP ✅[/green]"
        else:
            false_negatives += 1
            status = "[yellow]FN ⚠️[/yellow]"

        results_rows.append((fname, str(len(findings)), "safe" if is_safe else "vuln", status))

    # Metrics
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (true_positives + true_negatives) / len(files) if files else 0

    # File results table
    file_table = Table(title="Per-File Results", box=box.ROUNDED, header_style="bold")
    file_table.add_column("File", style="cyan")
    file_table.add_column("Findings", justify="right")
    file_table.add_column("Expected", width=8)
    file_table.add_column("Result", width=10)

    for row in results_rows:
        file_table.add_row(*row)
    console.print(file_table)

    # Metrics table
    console.print()
    m_table = Table(title="Benchmark Metrics", box=box.DOUBLE, header_style="bold white on dark_green")
    m_table.add_column("Metric", width=20)
    m_table.add_column("Value", justify="right", width=10)
    m_table.add_row("Total Files", str(len(files)))
    m_table.add_row("Total Findings", str(total_findings))
    m_table.add_row("True Positives", f"[green]{true_positives}[/green]")
    m_table.add_row("True Negatives", f"[green]{true_negatives}[/green]")
    m_table.add_row("False Positives", f"[red]{false_positives}[/red]")
    m_table.add_row("False Negatives", f"[yellow]{false_negatives}[/yellow]")
    m_table.add_row("─" * 20, "─" * 10)
    m_table.add_row("[bold]Precision[/bold]", f"[bold]{precision:.1%}[/bold]")
    m_table.add_row("[bold]Recall[/bold]", f"[bold]{recall:.1%}[/bold]")
    m_table.add_row("[bold]F1 Score[/bold]", f"[bold]{f1:.1%}[/bold]")
    m_table.add_row("[bold]Accuracy[/bold]", f"[bold]{accuracy:.1%}[/bold]")
    console.print(m_table)


if __name__ == "__main__":
    main()
