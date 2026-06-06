"""Full scan pipeline — orchestrates all 7 stages."""
import os
from datetime import datetime
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from vulnscan5g.ingest.loader import load_files, is_c_file
from vulnscan5g.preprocess.cleaner import extract_metadata
from vulnscan5g.detectors.regex_detector import RegexDetector
from vulnscan5g.detectors.ast_detector import ASTDetector
from vulnscan5g.detectors.treesitter_detector import TreeSitterDetector
from vulnscan5g.analyzer.merger import merge_findings
from vulnscan5g.analyzer.severity import filter_by_severity
from vulnscan5g.analyzer.cwe_mapper import enrich_cwe
from vulnscan5g.models.scan_result import ScanResult
from vulnscan5g.models.finding import Finding

console = Console()


def _scan_single_file(fpath: str, regex_det: RegexDetector, ast_det: ASTDetector,
                      ts_det: TreeSitterDetector):
    """Scan a single file with the appropriate detectors.

    Parser priority (no collisions):
      • Regex  — always runs (fast first-pass for both C and C++)
      • AST    — pycparser, C files only (skips C++ automatically)
      • TS     — tree-sitter, C++ files always; C files only when
                 pycparser is unavailable (checked inside ts_det.scan)
    """
    with open(fpath, "r", errors="ignore") as f:
        code = f.read()
    lang = "c" if is_c_file(fpath) else "cpp"
    findings = regex_det.scan(code, fpath, lang)
    findings += ast_det.scan(code, fpath, lang)
    findings += ts_det.scan(code, fpath, lang)
    return fpath, code, findings


def run_pipeline(
    target: str,
    min_severity: str = "low",
    use_llm: bool = False,
    do_fix: bool = False,
    verbose: bool = False,
    model_name: str | None = None,
    show_diff: bool = False,
) -> ScanResult:
    """
    Execute the full 7-stage vulnerability scan pipeline.

    Args:
        target:        File or directory to scan
        min_severity:  Minimum severity threshold (critical/high/medium/low/info)
        use_llm:       Whether to run LLM reasoning (Stage 5)
        do_fix:        Whether to generate LLM fixes (Stage 6)
        verbose:       Print extra detail during scanning
        model_name:    Ollama model name override (default: from config)
        show_diff:     Show diff between original and fixed code
    """
    result = ScanResult(target_path=os.path.abspath(target))

    # ── STAGE 1: INGEST ──────────────────────────────────────
    files = load_files(target)
    if not files:
        console.print("[yellow]⚠️  No C/C++ files found.[/yellow]")
        return result

    result.files_scanned = len(files)
    console.print(f"[dim]Found [bold]{len(files)}[/bold] C/C++ file(s)[/dim]\n")

    # ── STAGE 2-4: PREPROCESS → DETECT → MERGE (parallel) ───
    regex_det = RegexDetector()
    ast_det = ASTDetector()
    ts_det = TreeSitterDetector()
    all_findings: List[Finding] = []
    file_codes: dict[str, str] = {}
    files_with_issues = set()

    # Use parallel scanning for 4+ files, sequential for small sets
    use_parallel = len(files) >= 4

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning files…", total=len(files))

        if use_parallel:
            with ThreadPoolExecutor(max_workers=min(8, len(files))) as executor:
                futures = {
                    executor.submit(_scan_single_file, fpath, regex_det, ast_det, ts_det): fpath
                    for fpath in files
                }
                for future in as_completed(futures):
                    try:
                        fpath, code, findings = future.result()
                        file_codes[fpath] = code
                        if findings:
                            files_with_issues.add(fpath)
                        all_findings.extend(findings)
                    except Exception as e:
                        result.errors.append(f"{futures[future]}: {e}")
                    progress.advance(task)
        else:
            for fpath in files:
                try:
                    fpath, code, findings = _scan_single_file(fpath, regex_det, ast_det, ts_det)
                    file_codes[fpath] = code
                    if findings:
                        files_with_issues.add(fpath)
                    all_findings.extend(findings)
                except Exception as e:
                    result.errors.append(f"{fpath}: {e}")
                progress.advance(task)

    # Stage 4: Merge & deduplicate
    merged = merge_findings(all_findings)
    # CWE enrichment
    merged = enrich_cwe(merged)
    # Severity filter
    merged = filter_by_severity(merged, min_severity)

    result.findings = merged
    result.files_with_issues = len(files_with_issues)

    # ── Resolve LLM model ────────────────────────────────────
    def _get_client():
        from vulnscan5g.llm.client import OllamaClient
        if model_name:
            return OllamaClient(model=model_name)
        return OllamaClient()

    # ── STAGE 5: LLM REASONING (optional) ────────────────────
    if use_llm and merged:
        try:
            from vulnscan5g.llm.reasoner import reason

            client = _get_client()
            if client.is_available():
                console.print(f"\n[dim]🧠 Running LLM reasoning ({client.model})…[/dim]")
                with Progress(
                    SpinnerColumn(), TextColumn("{task.description}"),
                    BarColumn(bar_width=30), TaskProgressColumn(),
                    console=console,
                ) as progress:
                    llm_task = progress.add_task("LLM analysis…", total=len(merged))
                    for finding in merged:
                        code = file_codes.get(finding.file_path, "")
                        reason(finding, code, client)
                        progress.advance(llm_task)
            else:
                console.print("[yellow]⚠️  Ollama not reachable — skipping LLM reasoning[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠️  LLM reasoning failed: {e}[/yellow]")

    # ── STAGE 6: AUTO-FIX (optional) ─────────────────────────
    #   Tier 1 = template fixes  (instant, no LLM, always runs)
    #   Tier 2 = snippet LLM     (only when Ollama is reachable)
    if do_fix and merged:
        try:
            from vulnscan5g.llm.fixer import fix_file
            from vulnscan5g.llm.template_fixer import can_template_fix
            from vulnscan5g.reporter.diff_patch import save_fixed_files

            # Group findings by file
            by_file: dict[str, list] = {}
            for f in merged:
                by_file.setdefault(f.file_path, []).append(f)

            # Count template vs LLM-needed findings
            total_template = sum(1 for f in merged if can_template_fix(f))
            total_llm = len(merged) - total_template

            # Resolve LLM client — None if Ollama is unreachable
            client = None
            if total_llm > 0:
                try:
                    llm_client = _get_client()
                    if llm_client.is_available():
                        client = llm_client
                        console.print(f"\n[dim]🔧 Fixing {len(by_file)} file(s): "
                                      f"{total_template} template + {total_llm} LLM ({llm_client.model})…[/dim]")
                    else:
                        console.print(f"\n[dim]🔧 Fixing {len(by_file)} file(s): "
                                      f"{total_template} template (LLM offline — {total_llm} deferred)…[/dim]")
                except Exception:
                    console.print(f"\n[dim]🔧 Fixing {len(by_file)} file(s): "
                                  f"{total_template} template (LLM unavailable)…[/dim]")
            else:
                console.print(f"\n[dim]🔧 Fixing {len(by_file)} file(s): "
                              f"{total_template} template fixes (no LLM needed!)…[/dim]")

            fixed_codes: dict[str, str] = {}

            with Progress(
                SpinnerColumn(), TextColumn("{task.description}"),
                BarColumn(bar_width=30), TaskProgressColumn(),
                console=console,
            ) as progress:
                fix_task = progress.add_task("Fixing…", total=len(by_file))
                for fpath, file_findings in by_file.items():
                    code = file_codes.get(fpath, "")
                    lang = "c" if is_c_file(fpath) else "cpp"
                    fixed = fix_file(code, file_findings, client,
                                     file_path=fpath, language=lang)
                    if fixed:
                        fixed_codes[fpath] = fixed
                    progress.advance(fix_task)

            if fixed_codes:
                # Save fixed files next to the scanned source
                target_dir = os.path.abspath(target)
                if os.path.isfile(target_dir):
                    target_dir = os.path.dirname(target_dir)
                out_dir = os.path.join(target_dir, "_vulnscan5g_fixed")
                out_dir = os.path.normpath(out_dir)
                saved = save_fixed_files(fixed_codes, output_dir=out_dir)
                console.print(f"\n[green]✅ Fixed {len(saved)} file(s) → [bold]{out_dir}[/bold][/green]")
                for s in saved:
                    console.print(f"  [dim]• {os.path.basename(s)}[/dim]")

                # ── Show diff if requested ────────────────
                if show_diff:
                    _print_diffs(file_codes, fixed_codes)
            else:
                console.print("[yellow]⚠️  No fixable vulnerabilities found[/yellow]")
        except Exception as e:
            console.print(f"[yellow]⚠️  Auto-fix failed: {e}[/yellow]")

    result.scan_end = datetime.now()
    return result


def _print_diffs(originals: dict[str, str], fixed: dict[str, str]):
    """Print colored diffs between original and fixed code."""
    import difflib
    from rich.syntax import Syntax
    from rich.panel import Panel

    for fpath, fixed_code in fixed.items():
        orig = originals.get(fpath, "")
        fname = os.path.basename(fpath)

        diff = difflib.unified_diff(
            orig.splitlines(keepends=True),
            fixed_code.splitlines(keepends=True),
            fromfile=f"original/{fname}",
            tofile=f"fixed/{fname}",
            lineterm="",
        )
        diff_text = "\n".join(diff)
        if diff_text.strip():
            console.print(Panel(
                Syntax(diff_text, "diff", theme="monokai"),
                title=f"[bold]📝 Diff: {fname}[/bold]",
                border_style="cyan",
            ))
