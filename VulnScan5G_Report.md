# VulnScan5G: Architecture & Technical Report

## 1. Executive Summary
VulnScan5G is a robust, Python-based vulnerability scanner and auto-patching tool tailored for C and C++ source code. It utilizes a hybrid detection engine combining AST (Abstract Syntax Tree) parsing, Tree-sitter semantic analysis, and Regular Expressions to identify security vulnerabilities. What sets VulnScan5G apart is its auto-patching pipeline, which leverages a local Large Language Model (LLM) via Ollama for reasoning and fallback generation, supplemented by a deterministic template-based auto-fixer for known vulnerabilities.

## 2. Project Requirements
To run and develop VulnScan5G, the following requirements must be met:
*   **Operating System:** Windows, Linux, or macOS.
*   **Python:** Python 3.10+
*   **System Dependencies:** C compiler (gcc/clang) if testing compilability, and an active local instance of Ollama.
*   **Hardware:** A machine with sufficient RAM and a capable GPU (optional but recommended) to run local LLMs (e.g., DeepSeek-Coder 6.7B) via Ollama with reasonable inference times.
*   **Storage:** Sufficient disk space for datasets, local LLM models (~4GB to 8GB per model), and generated reports.

## 3. Technologies & Python Libraries
The project heavily relies on Python and a curated set of libraries to function:
*   **Core Language:** Python 3.x
*   **pycparser:** For generating and traversing the AST of C code to find unsafe function calls and logic flaws.
*   **tree-sitter & tree-sitter-c / tree-sitter-cpp:** For robust parsing of both C and C++ code, providing a resilient semantic model of the source files.
*   **re (Standard Library):** Fast, first-pass regex-based vulnerability detection acting as a safety net.
*   **requests:** To communicate with the local Ollama REST API for LLM inference.
*   **rich:** For rendering beautiful, colorized terminal outputs, progress bars, and ASCII tables.
*   **jinja2:** For generating HTML-based vulnerability reports from templates.
*   **flask (Optional/Dashboard):** For providing a web-based UI/dashboard for viewing reports.
*   **dataclasses (Standard Library):** For structuring `Finding` and `Result` objects cleanly.

## 4. Full Pipeline & Phase-by-Phase Explanation
The pipeline is designed to be sequential, deterministic, and highly accurate.

*   **Phase 1: Ingestion & Preprocessing**
    *   The `loader.py` module recursively scans the target directory, filtering for `.c`, `.cpp`, `.h`, and `.hpp` files, while ignoring standard skip directories (like `.git`, `build/`).
    *   The file is read and passed to the cleaner to strip comments and preprocessor directives (while maintaining exact line numbers by replacing with newlines).
*   **Phase 2: Hybrid Detection**
    *   **AST Detector:** Runs first for C files using `pycparser`. Uses fake headers to bypass include requirements.
    *   **Tree-sitter Detector:** Runs for C++ files (or C files if pycparser fails). Identifies structural flaws.
    *   **Regex Detector:** Runs on all files as a fast baseline to catch generic string-matching patterns (e.g., unbounded `strcpy`).
*   **Phase 3: Deduplication & Merging**
    *   The `merger.py` combines findings from all three detectors.
    *   **Pass 1:** Merges findings on the exact same line, assigning a boosted confidence score and prioritizing AST details.
    *   **Pass 2:** Collapses identical vulnerability types within the same file to prevent report spam.
*   **Phase 4: LLM Reasoning (Optional)**
    *   Sends snippets of identified vulnerabilities to the local LLM. The LLM acts as an expert judge, verifying if the flagged line is a true positive or a false positive.
*   **Phase 5: Auto-Fix Generation**
    *   **Tier 1 (Template Fixer):** Deterministic regex templates instantly patch known unsafe patterns (e.g., `gets` -> `fgets`) with 100% reliability, no LLM required.
    *   **Tier 2 (Snippet LLM):** For complex bugs, a ±5 line snippet is sent to the LLM to generate a contextual fix without risking corruption of the entire file.
*   **Phase 6: Reporting**
    *   Diffs are applied to the source, and patched files are output to a `fixed_output` directory.
    *   A CLI table summary is displayed, and a static HTML dashboard report is generated.

## 5. Role of Each Tool
*   **pycparser:** The primary engine for C code. Understands scope and variable types, eliminating regex-based false positives.
*   **tree-sitter:** The primary engine for C++ code. Fault-tolerant parser that can build syntax trees even for incomplete code.
*   **Regex Engine:** Catches basic flaws fast. Crucial for catching issues in code that is too broken for AST parsers to read.
*   **Merger (analyzer):** The "brain" of the reporting system. It maps CWEs to canonical families (e.g., CWE-242 maps to CWE-120) so findings from different detectors align perfectly.
*   **Ollama (LLM):** Provides advanced reasoning capabilities. Handles complex auto-patching for vulnerabilities that cannot be solved with simple string replacements (like Use-After-Free).
*   **Rich Console:** Enhances the developer experience (DX) by providing clear, understandable, and highly visual feedback in the terminal.

## 6. Datasets & Test Suites
*   **Juliet Test Suite (C/C++):** A comprehensive suite of test cases provided by the NSA Center for Assured Software (CAS). Used to validate detection of CWE-120 (Buffer Overflow), CWE-121, CWE-122, CWE-416 (Use After Free), and others.
*   **Basic Synthetic Tests:** Custom minimal C files (`basic.c`, `gets.c`, `strcpy.c`) designed specifically to trigger Tier 1 template fixes and verify baseline pipeline functionality.

## 7. Scalability & Performance
*   **Detection Scale:** The AST, Tree-Sitter, and Regex detectors are incredibly fast. The system can scan thousands of files in seconds.
*   **Fixing Scale:**
    *   *Tier 1 (Templates):* Executes in sub-milliseconds per file. Scales infinitely.
    *   *Tier 2 (LLM):* Scalability is bounded by the local LLM inference speed. Sending snippets instead of full files drastically improved this, reducing token usage by ~95%, but it remains the primary bottleneck for massive codebases.

## 8. Advantages & Disadvantages
**Advantages:**
*   **High Accuracy:** The hybrid approach minimizes both false positives (via AST) and false negatives (via regex).
*   **Safe Auto-Patching:** The two-tier fixer guarantees that unchanged code is never corrupted.
*   **Privacy-Preserving:** Uses a local LLM via Ollama. Source code never leaves the developer's machine.
*   **Fast:** The template fixer patches common bugs instantly without waiting for AI generation.

**Disadvantages:**
*   **Hardware Intensive:** Running a 7B parameter LLM locally requires decent hardware.
*   **C++ AST Limitations:** Relying on Tree-sitter for C++ is robust but less semantically deep than a full compiler-frontend like Clang AST.
*   **LLM Hallucinations:** While mitigated by snippet-level context, the LLM can still occasionally generate invalid code for complex Tier 2 fixes.

## 9. Limitations
*   **Semantic Depth:** The scanner does not perform deep, cross-file inter-procedural taint analysis. It cannot easily detect a vulnerability where a variable is tainted in File A and used unsafely in File B.
*   **Language Support:** Strictly limited to C and C++.
*   **Macro Expansion:** Extensive use of complex C preprocessor macros can obscure vulnerabilities from both the AST and Tree-sitter parsers.

## 10. Future Improvements
*   **LSP Integration:** Convert the scanner into a Language Server Protocol (LSP) server, allowing real-time vulnerability detection directly inside VS Code or Neovim.
*   **Data Flow Analysis:** Implement lightweight taint analysis to track malicious input from `Source` to `Sink` across function boundaries.
*   **Clang Integration:** Replace Tree-Sitter for C++ with libclang bindings for compiler-accurate semantic analysis.
*   **Model Fine-Tuning:** Fine-tune a smaller, faster model (e.g., 1.5B or 3B parameters) specifically on C/C++ security patches to replace the generic DeepSeek-Coder model, vastly improving inference speed.

## 11. CLI Commands & Usage
VulnScan5G provides a rich command-line interface. Below are the primary commands and their specific use cases:

*   `python main.py rules`
    Lists all available vulnerability detection rules, including their IDs, severity, and supported languages.

*   `python main.py scan <path/to/directory>`
    Performs a standard hybrid scan (AST + Tree-sitter + Regex) on the target directory and outputs a vulnerability report table.

*   `python main.py scan <path/to/directory> --fix`
    Scans the directory and automatically applies patches. Instantly patches known vulnerabilities using Tier 1 (Templates) even if the LLM is offline. Output is saved to the `fixed_output/` directory.

*   `python main.py scan <path/to/directory> --llm`
    Enables Tier 4 LLM Reasoning. Before generating the final report, it queries the local Ollama LLM to judge each finding as a True Positive or False Positive, filtering out noise.

*   `python main.py scan <path/to/directory> --fix --llm`
    Executes the complete pipeline: Scans the code, uses the LLM to verify findings, and then fixes the verified vulnerabilities using both Tier 1 templates and Tier 2 Snippet LLM fallback.

*   `python main.py scan <path/to/directory> --diff`
    When used with `--fix`, displays a visual line-by-line patch comparison in the terminal, showing exactly what code was modified.
