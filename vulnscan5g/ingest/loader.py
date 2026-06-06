"""Recursively discover C/C++ source files."""
import os
from typing import List, Set

from vulnscan5g.config import ALL_EXTENSIONS, C_EXTENSIONS, CPP_EXTENSIONS, SKIP_DIRS


def load_files(
    path: str,
    extensions: Set[str] | None = None,
    skip_dirs: Set[str] | None = None,
) -> List[str]:
    """Return sorted list of C/C++ file paths under *path*."""
    extensions = extensions or ALL_EXTENSIONS
    skip_dirs = skip_dirs or SKIP_DIRS
    path = os.path.abspath(path)

    if os.path.isfile(path):
        return [path] if os.path.splitext(path)[1].lower() in extensions else []

    if not os.path.isdir(path):
        return []

    files: List[str] = []
    for root, dirs, fnames in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in sorted(fnames):
            if os.path.splitext(fname)[1].lower() in extensions:
                files.append(os.path.join(root, fname))
    return files


def is_c_file(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in C_EXTENSIONS


def is_cpp_file(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in CPP_EXTENSIONS
