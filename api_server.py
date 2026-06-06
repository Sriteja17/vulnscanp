"""VulnScan5G — FastAPI backend for the Electron desktop app.

Runs on port 8765.  All blocking work (pipeline, subprocess) is offloaded
via asyncio.to_thread() so the event-loop stays responsive.
"""

import asyncio
import io
import json
import os
import platform
import subprocess
import sys
import tempfile
import urllib.request
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import asdict
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── VulnScan5G imports ────────────────────────────────────────
from vulnscan5g.pipeline import run_pipeline
from vulnscan5g.models import Finding, Severity, ScanResult
from vulnscan5g.detectors.rules import ALL_RULES
from vulnscan5g.ingest import load_files, is_c_file
from vulnscan5g.preprocess import extract_metadata
from vulnscan5g.reporter.json_report import save_json
from vulnscan5g.reporter.html_report import save_html
from vulnscan5g.llm.client import OllamaClient
from vulnscan5g.config import (
    OLLAMA_URL,
    OLLAMA_MODEL,
    LLM_TIMEOUT,
    LLM_TEMPERATURE,
    ALL_EXTENSIONS,
    SEVERITY_ORDER,
)

# ═════════════════════════════════════════════════════════════════
#  App setup
# ═════════════════════════════════════════════════════════════════

app = FastAPI(
    title="VulnScan5G API",
    version="1.0.0",
    description="Backend API for the VulnScan5G Electron desktop application.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═════════════════════════════════════════════════════════════════
#  Global state
# ═════════════════════════════════════════════════════════════════

_scan_running: bool = False
_scan_result: Optional[ScanResult] = None
_scan_error: Optional[str] = None

_pull_running: bool = False
_pull_output: str = ""
_pull_model: str = ""

# ═════════════════════════════════════════════════════════════════
#  Request / response models
# ═════════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    target: str
    min_severity: str = "low"
    use_llm: bool = False
    do_fix: bool = False
    model_name: Optional[str] = None


class InfoRequest(BaseModel):
    target: str


class ReportRequest(BaseModel):
    output_path: str


class OllamaPullRequest(BaseModel):
    model: str = OLLAMA_MODEL


class FixesSaveRequest(BaseModel):
    output_dir: str


# ═════════════════════════════════════════════════════════════════
#  Helpers
# ═════════════════════════════════════════════════════════════════

def _run_pipeline_quiet(**kwargs) -> ScanResult:
    """Run the scan pipeline while suppressing rich console output."""
    buf_out = io.StringIO()
    buf_err = io.StringIO()
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        return run_pipeline(**kwargs)


def _rule_to_dict(rule) -> dict:
    """Convert a Rule dataclass to a plain dict, handling Severity enum."""
    d = asdict(rule)
    # Severity is an enum — convert to string value
    if hasattr(d.get("severity"), "value"):
        d["severity"] = d["severity"].value
    elif isinstance(d.get("severity"), str):
        pass  # already string from asdict
    else:
        # asdict converts Enum to its value in modern Python
        sev = d.get("severity")
        if sev and not isinstance(sev, str):
            d["severity"] = str(sev)
    return d


# Original /scan endpoint removed — replaced by start_scan_v2 below (with fix tracking)



# ═════════════════════════════════════════════════════════════════
#  GET /scan/status — poll scan progress
# ═════════════════════════════════════════════════════════════════

@app.get("/scan/status")
async def scan_status():
    result_json = None
    if _scan_result is not None:
        result_json = json.loads(_scan_result.to_json())
    return {
        "running": _scan_running,
        "result": result_json,
        "error": _scan_error,
    }


# ═════════════════════════════════════════════════════════════════
#  GET /rules — list all detection rules
# ═════════════════════════════════════════════════════════════════

@app.get("/rules")
async def get_rules():
    return [_rule_to_dict(r) for r in ALL_RULES]


# ═════════════════════════════════════════════════════════════════
#  POST /info — file / project metadata
# ═════════════════════════════════════════════════════════════════

@app.post("/info")
async def project_info(req: InfoRequest):
    target = os.path.abspath(req.target)
    if not os.path.exists(target):
        raise HTTPException(status_code=404, detail=f"Target not found: {target}")

    def _gather():
        files = load_files(target)
        total_lines = 0
        total_code_lines = 0
        languages: Dict[str, int] = {"c": 0, "cpp": 0}
        file_details = []

        for fpath in files:
            try:
                with open(fpath, "r", errors="ignore") as f:
                    code = f.read()
                lang = "c" if is_c_file(fpath) else "cpp"
                meta = extract_metadata(fpath, code, lang)
                total_lines += meta.total_lines
                total_code_lines += meta.code_lines
                languages[lang] += 1
                file_details.append({
                    "path": meta.path,
                    "total_lines": meta.total_lines,
                    "code_lines": meta.code_lines,
                    "language": meta.language,
                    "includes": meta.includes,
                    "functions": meta.functions,
                })
            except Exception:
                continue

        return {
            "target": target,
            "file_count": len(files),
            "total_lines": total_lines,
            "total_code_lines": total_code_lines,
            "languages": languages,
            "files": file_details,
        }

    return await asyncio.to_thread(_gather)


# ═════════════════════════════════════════════════════════════════
#  GET /llm/status — Ollama availability check
# ═════════════════════════════════════════════════════════════════

@app.get("/llm/status")
async def llm_status():
    def _check():
        try:
            client = OllamaClient()
            return {
                "available": client.is_available(),
                "model": client.model,
                "url": client.url,
            }
        except Exception:
            return {
                "available": False,
                "model": OLLAMA_MODEL,
                "url": OLLAMA_URL,
            }

    return await asyncio.to_thread(_check)


# ═════════════════════════════════════════════════════════════════
#  POST /report/html — generate HTML report
# ═════════════════════════════════════════════════════════════════

@app.post("/report/html")
async def generate_html_report(req: ReportRequest):
    if _scan_result is None:
        raise HTTPException(status_code=400, detail="No scan result available. Run a scan first.")

    output = os.path.abspath(req.output_path)

    def _save():
        save_html(_scan_result, output)

    try:
        await asyncio.to_thread(_save)
        return {"status": "ok", "path": output}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate HTML report: {exc}")


# ═════════════════════════════════════════════════════════════════
#  POST /report/json — generate JSON report
# ═════════════════════════════════════════════════════════════════

@app.post("/report/json")
async def generate_json_report(req: ReportRequest):
    if _scan_result is None:
        raise HTTPException(status_code=400, detail="No scan result available. Run a scan first.")

    output = os.path.abspath(req.output_path)

    def _save():
        save_json(_scan_result, output)

    try:
        await asyncio.to_thread(_save)
        return {"status": "ok", "path": output}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate JSON report: {exc}")


# ═════════════════════════════════════════════════════════════════
#  GET /config — return configuration constants
# ═════════════════════════════════════════════════════════════════

@app.get("/config")
async def get_config():
    return {
        "ollama_url": OLLAMA_URL,
        "ollama_model": OLLAMA_MODEL,
        "llm_timeout": LLM_TIMEOUT,
        "llm_temperature": LLM_TEMPERATURE,
        "supported_extensions": sorted(ALL_EXTENSIONS),
        "severity_levels": list(SEVERITY_ORDER.keys()),
    }


# ═════════════════════════════════════════════════════════════════
#  GET /ollama/check — check if Ollama is already installed
# ═════════════════════════════════════════════════════════════════

@app.get("/ollama/check")
async def ollama_check():
    """Check if ollama command exists on PATH."""
    def _check():
        try:
            result = subprocess.run(
                ["ollama", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return {"installed": True, "version": result.stdout.strip()}
            return {"installed": False, "version": None}
        except FileNotFoundError:
            return {"installed": False, "version": None}
        except Exception:
            return {"installed": False, "version": None}
    return await asyncio.to_thread(_check)


# ═════════════════════════════════════════════════════════════════
#  POST /ollama/install — download & run Ollama installer
# ═════════════════════════════════════════════════════════════════

_install_status = {"running": False, "stage": "", "error": None, "done": False}

@app.post("/ollama/install")
async def ollama_install():
    global _install_status

    if _install_status["running"]:
        return {"status": "already_running", "detail": "Installation already in progress."}

    _install_status = {"running": True, "stage": "downloading", "error": None, "done": False}

    async def _do_install():
        global _install_status
        system = platform.system().lower()

        if system != "windows":
            _install_status = {"running": False, "stage": "", "error": f"Use manual install for {system}", "done": False}
            return

        url = "https://ollama.com/download/OllamaSetup.exe"
        installer_path = os.path.join(tempfile.gettempdir(), "OllamaSetup.exe")

        try:
            # Download
            _install_status["stage"] = "downloading"
            await asyncio.to_thread(urllib.request.urlretrieve, url, installer_path)

            # Verify file exists and has size
            fsize = os.path.getsize(installer_path)
            if fsize < 1_000_000:  # Less than 1MB = probably an error page
                _install_status = {"running": False, "stage": "", "error": "Download too small — check internet.", "done": False}
                return

            # Launch installer
            _install_status["stage"] = "launching"
            subprocess.Popen([installer_path], shell=False)
            _install_status = {"running": False, "stage": "launched", "error": None, "done": True}

        except Exception as exc:
            _install_status = {"running": False, "stage": "", "error": str(exc), "done": False}

    asyncio.create_task(_do_install())
    return {"status": "started", "detail": "Downloading Ollama installer..."}


@app.get("/ollama/install/status")
async def ollama_install_status():
    return _install_status


# ═════════════════════════════════════════════════════════════════
#  POST /ollama/pull — pull an Ollama model
# ═════════════════════════════════════════════════════════════════

@app.post("/ollama/pull")
async def ollama_pull(req: OllamaPullRequest):
    global _pull_running, _pull_output, _pull_model

    if _pull_running:
        raise HTTPException(status_code=409, detail="A model pull is already in progress.")

    _pull_running = True
    _pull_output = ""
    _pull_model = req.model

    async def _do_pull():
        global _pull_running, _pull_output
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["ollama", "pull", req.model],
                capture_output=True,
                text=True,
                timeout=600,
            )
            _pull_output = result.stdout or result.stderr or ""
            if result.returncode != 0:
                _pull_output = f"Error (exit {result.returncode}): {_pull_output}"
        except FileNotFoundError:
            _pull_output = "Error: 'ollama' command not found. Is Ollama installed?"
        except subprocess.TimeoutExpired:
            _pull_output = "Error: Model pull timed out after 10 minutes."
        except Exception as exc:
            _pull_output = f"Error: {exc}"
        finally:
            _pull_running = False

    asyncio.create_task(_do_pull())
    return {"status": "started", "model": req.model}


# ═════════════════════════════════════════════════════════════════
#  GET /ollama/pull/status — check model pull progress
# ═════════════════════════════════════════════════════════════════

@app.get("/ollama/pull/status")
async def ollama_pull_status():
    return {
        "running": _pull_running,
        "model": _pull_model,
        "output": _pull_output,
    }


# ═════════════════════════════════════════════════════════════════
#  GET /fixes — return diffs between original and fixed files
# ═════════════════════════════════════════════════════════════════

_last_scan_target: Optional[str] = None

@app.post("/scan")
async def start_scan_v2(req: ScanRequest):
    """Override: also track the scan target for fix path resolution."""
    global _scan_running, _scan_result, _scan_error, _last_scan_target

    if _scan_running:
        raise HTTPException(status_code=409, detail="A scan is already running.")

    target = os.path.abspath(req.target)
    if not os.path.exists(target):
        raise HTTPException(status_code=404, detail=f"Target not found: {target}")

    _scan_running = True
    _scan_result = None
    _scan_error = None
    _last_scan_target = target

    async def _do_scan():
        global _scan_running, _scan_result, _scan_error
        try:
            result = await asyncio.to_thread(
                _run_pipeline_quiet,
                target=target,
                min_severity=req.min_severity,
                use_llm=req.use_llm,
                do_fix=req.do_fix,
                model_name=req.model_name,
            )
            _scan_result = result
        except Exception as exc:
            _scan_error = str(exc)
        finally:
            _scan_running = False

    asyncio.create_task(_do_scan())
    return {"status": "started"}


@app.get("/fixes")
async def get_fixes():
    """Compare original files with fixed files in _vulnscan5g_fixed/ and return diffs."""
    # Determine fixed directory relative to scan target
    fixed_dir = _get_fixed_dir()
    if not fixed_dir or not os.path.isdir(fixed_dir):
        return {"fixes": [], "fixed_dir": fixed_dir or "", "total_files": 0,
                "message": "No fixed files found."}

    def _compute_diffs():
        import difflib

        fixes = []
        for fname in sorted(os.listdir(fixed_dir)):
            fixed_path = os.path.join(fixed_dir, fname)
            if not os.path.isfile(fixed_path):
                continue

            # Find the original file
            original_path = _find_original(fname)

            # Read files
            try:
                with open(fixed_path, "r", errors="ignore") as f:
                    fixed_lines = f.readlines()
            except Exception:
                continue

            original_lines = []
            if original_path and os.path.isfile(original_path):
                try:
                    with open(original_path, "r", errors="ignore") as f:
                        original_lines = f.readlines()
                except Exception:
                    pass

            # Generate diff
            diff = list(difflib.unified_diff(
                original_lines, fixed_lines,
                fromfile=f"original/{fname}",
                tofile=f"fixed/{fname}",
                lineterm=""
            ))

            if diff or not original_path:
                additions = sum(1 for l in diff if l.startswith('+') and not l.startswith('+++'))
                deletions = sum(1 for l in diff if l.startswith('-') and not l.startswith('---'))

                fixes.append({
                    "filename": fname,
                    "original_path": original_path or "unknown",
                    "fixed_path": fixed_path,
                    "diff": "\n".join(diff) if diff else "(new file or identical)",
                    "additions": additions,
                    "deletions": deletions,
                    "applied": False,  # Track if already applied
                })

        return {
            "fixes": fixes,
            "fixed_dir": fixed_dir,
            "total_files": len(fixes),
        }

    return await asyncio.to_thread(_compute_diffs)


def _get_fixed_dir() -> Optional[str]:
    """Get the _vulnscan5g_fixed/ directory path based on scan target."""
    if _last_scan_target:
        target_dir = _last_scan_target
        if os.path.isfile(target_dir):
            target_dir = os.path.dirname(target_dir)
        fixed_dir = os.path.join(target_dir, "_vulnscan5g_fixed")
        if os.path.isdir(fixed_dir):
            return fixed_dir
    # Fallback: check old location
    old_dir = os.path.join(os.getcwd(), "fixed_output")
    if os.path.isdir(old_dir):
        return old_dir
    return None


def _find_original(fname: str) -> Optional[str]:
    """Find the original file path for a given filename."""
    if _scan_result:
        for finding in _scan_result.findings:
            if os.path.basename(finding.file_path) == fname:
                return finding.file_path
    if _last_scan_target:
        target_dir = _last_scan_target
        if os.path.isfile(target_dir):
            target_dir = os.path.dirname(target_dir)
        if os.path.isdir(target_dir):
            for root, dirs, files in os.walk(target_dir):
                # Skip the fixed directory itself
                if "_vulnscan5g_fixed" in root:
                    continue
                if fname in files:
                    return os.path.join(root, fname)
    return None


# ═════════════════════════════════════════════════════════════════
#  POST /fixes/apply — replace originals with fixed files (.bak backup)
# ═════════════════════════════════════════════════════════════════

@app.post("/fixes/apply")
async def apply_fixes():
    """Replace original files with fixed versions. Creates .bak backups."""
    fixed_dir = _get_fixed_dir()
    if not fixed_dir or not os.path.isdir(fixed_dir):
        raise HTTPException(status_code=404, detail="No fixed files found.")

    def _apply():
        import shutil
        applied = []
        errors = []

        for fname in sorted(os.listdir(fixed_dir)):
            fixed_path = os.path.join(fixed_dir, fname)
            if not os.path.isfile(fixed_path):
                continue

            original_path = _find_original(fname)
            if not original_path or not os.path.isfile(original_path):
                errors.append({"filename": fname, "error": "Original file not found"})
                continue

            try:
                # Create backup
                backup_path = original_path + ".bak"
                shutil.copy2(original_path, backup_path)

                # Replace with fixed version
                shutil.copy2(fixed_path, original_path)

                applied.append({
                    "filename": fname,
                    "original_path": original_path,
                    "backup_path": backup_path,
                })
            except Exception as exc:
                errors.append({"filename": fname, "error": str(exc)})

        return {
            "applied": applied,
            "errors": errors,
            "total_applied": len(applied),
            "total_errors": len(errors),
        }

    return await asyncio.to_thread(_apply)


# ═════════════════════════════════════════════════════════════════
#  POST /fixes/save — copy fixed files to a user-chosen directory
# ═════════════════════════════════════════════════════════════════

@app.post("/fixes/save")
async def save_fixes(req: FixesSaveRequest):
    """Copy fixed files to a user-specified directory."""
    fixed_dir = _get_fixed_dir()
    if not fixed_dir or not os.path.isdir(fixed_dir):
        raise HTTPException(status_code=404, detail="No fixed files found.")

    output_dir = os.path.abspath(req.output_dir)

    def _save():
        import shutil
        os.makedirs(output_dir, exist_ok=True)
        saved = []
        errors = []

        for fname in sorted(os.listdir(fixed_dir)):
            src = os.path.join(fixed_dir, fname)
            if not os.path.isfile(src):
                continue
            dst = os.path.join(output_dir, fname)
            try:
                shutil.copy2(src, dst)
                saved.append({"filename": fname, "saved_to": dst})
            except Exception as exc:
                errors.append({"filename": fname, "error": str(exc)})

        return {
            "saved": saved,
            "errors": errors,
            "total_saved": len(saved),
            "output_dir": output_dir,
        }

    return await asyncio.to_thread(_save)

# ═════════════════════════════════════════════════════════════════
#  Health check
# ═════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok"}


# ═════════════════════════════════════════════════════════════════
#  Entrypoint
# ═════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
