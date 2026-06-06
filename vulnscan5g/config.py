"""Global configuration and defaults."""

# Supported file extensions
C_EXTENSIONS = {".c", ".h"}
CPP_EXTENSIONS = {".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".hh"}
ALL_EXTENSIONS = C_EXTENSIONS | CPP_EXTENSIONS

# Directories to skip during scanning
SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__",
    ".venv", "venv", "build", "cmake-build-debug",
    "cmake-build-release", ".idea", ".vscode", "dist",
}

# LLM / Ollama settings
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "deepseek-coder:6.7b"
LLM_TIMEOUT = 180  # seconds
LLM_TEMPERATURE = 0.1  # low = deterministic code output

# Snippet window (lines above/below finding)
SNIPPET_WINDOW = 5

# Severity ordering (for filtering)
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
