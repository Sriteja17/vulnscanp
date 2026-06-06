# VulnScan5G

**CLI vulnerability detection & auto-fix tool for C/C++ source files.**

Built for analyzing security-critical code used in 5G network stacks, embedded systems, and any C/C++ project.

---

## Quick Start

```bash
# Install dependencies
pip install click rich pycparser requests jinja2

# Scan a file
python -m vulnscan5g scan path/to/file.c

# Scan a directory
python -m vulnscan5g scan ./my_project/ -v

# Scan with LLM reasoning (requires Ollama running)
python -m vulnscan5g scan ./my_project/ --llm

# Scan + auto-fix
python -m vulnscan5g scan ./my_project/ --fix

# Filter by severity
python -m vulnscan5g scan ./my_project/ --severity high

# Export reports
python -m vulnscan5g scan ./my_project/ --report json -o report.json
python -m vulnscan5g scan ./my_project/ --report html -o report.html
python -m vulnscan5g scan ./my_project/ --report all -o report.json
```

## Commands

| Command | Description |
|---------|-------------|
| `scan <path>` | Scan files/directories for vulnerabilities |
| `rules` | List all 25 detection rules |
| `info <path>` | Show file/project metadata |

## Scan Options

| Flag | Description |
|------|-------------|
| `--fix` | Generate LLM-powered auto-fixes (`_fixed.c` files) |
| `--llm` | Enable LLM reasoning to confirm/reject findings |
| `--severity` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `--report` | Output format: `console`, `json`, `html`, `all` |
| `-o, --output` | Output file path for reports |
| `-v, --verbose` | Show detailed findings |

## Pipeline Architecture

```
INGEST → PREPROCESS → DETECT (Regex + AST) → MERGE & SCORE → LLM REASONING → AUTO-FIX → REPORT
```

1. **Ingest** — Recursively discover `.c`, `.cpp`, `.h`, `.hpp` files
2. **Preprocess** — Strip comments, normalize whitespace
3. **Detect** — Dual-engine scanning (Regex + AST via pycparser)
4. **Merge & Score** — Deduplicate, assign CWE IDs, boost confidence
5. **LLM Reasoning** — Ollama-powered confirmation (optional)
6. **Auto-Fix** — LLM-generated patches (optional)
7. **Report** — Console table, JSON, or HTML output

## Detection Coverage (25 Rules)

| Category | CWE | Examples |
|----------|-----|---------|
| Buffer Overflow | CWE-120/242 | `gets()`, `strcpy()`, `sprintf()`, `scanf %s` |
| Format String | CWE-134 | `printf(var)`, `fprintf(f, var)` |
| Command Injection | CWE-78 | `system()`, `popen()` |
| Use-After-Free | CWE-416/415 | `free()` without NULL, double free |
| Integer Overflow | CWE-190 | `malloc(a * b)`, `realloc(p, n + m)` |
| Race Condition | CWE-367 | `access()` then `open()`, TOCTOU |
| NULL Deref | CWE-476 | Unchecked `malloc()`, `realloc()` |
| Memory Leak | CWE-401 | `malloc` in loop without `free` |
| Uninitialized Memory | CWE-908 | Stack buffers without init |
| Unsafe Memory Ops | CWE-120 | `memcpy()` with variable size |

## Project Structure

```
OMO/
├── vulnscan5g/             # Main package
│   ├── cli.py              # Click CLI commands
│   ├── pipeline.py         # Full 7-stage pipeline orchestrator
│   ├── config.py           # Configuration & defaults
│   ├── ingest/             # Stage 1: File discovery
│   ├── preprocess/         # Stage 2: Code cleaning & metadata
│   ├── detectors/          # Stage 3: Regex + AST detection engines
│   ├── analyzer/           # Stage 4: Merge, deduplicate, CWE mapping
│   ├── llm/                # Stage 5-6: Ollama reasoning & auto-fix
│   ├── reporter/           # Stage 7: Console, JSON, HTML reports
│   └── models/             # Data models (Finding, ScanResult)
├── tests/                  # Test C/C++ files (vulnerable + safe)
├── srsRAN/                 # Real-world 5G codebase for testing
└── pyproject.toml          # Project metadata & dependencies
```

## LLM Integration (Optional)

VulnScan5G uses [Ollama](https://ollama.ai/) for local LLM reasoning:

```bash
# Install Ollama, then:
ollama pull codellama:7b
ollama serve

# Now use --llm or --fix flags
python -m vulnscan5g scan ./code/ --llm --fix
```

## License

MIT
