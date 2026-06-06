# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for VulnScan5G API server.
Bundles the FastAPI/Uvicorn server + the entire vulnscan5g package
into a single directory distribution.
"""

import sys
import os

block_cipher = None

# Collect all hidden imports that PyInstaller may miss
hidden_imports = [
    # FastAPI / Uvicorn / ASGI
    'uvicorn',
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'uvicorn.lifespan.off',
    'fastapi',
    'fastapi.middleware',
    'fastapi.middleware.cors',
    'starlette',
    'starlette.middleware',
    'starlette.middleware.cors',
    'starlette.routing',
    'starlette.responses',
    'starlette.requests',
    'starlette.exceptions',
    'pydantic',
    'pydantic_core',
    'annotated_types',
    'typing_extensions',
    'typing_inspection',
    'anyio',
    'anyio._backends',
    'anyio._backends._asyncio',
    'h11',
    'click',
    'colorama',

    # VulnScan5G package
    'vulnscan5g',
    'vulnscan5g.pipeline',
    'vulnscan5g.config',
    'vulnscan5g.cli',
    'vulnscan5g.models',
    'vulnscan5g.models.finding',
    'vulnscan5g.models.scan_result',
    'vulnscan5g.ingest',
    'vulnscan5g.preprocess',
    'vulnscan5g.detectors',
    'vulnscan5g.detectors.base',
    'vulnscan5g.detectors.rules',
    'vulnscan5g.detectors.regex_detector',
    'vulnscan5g.detectors.ast_detector',
    'vulnscan5g.detectors.treesitter_detector',
    'vulnscan5g.analyzer',
    'vulnscan5g.llm',
    'vulnscan5g.llm.client',
    'vulnscan5g.llm.fixer',
    'vulnscan5g.llm.prompts',
    'vulnscan5g.llm.reasoner',
    'vulnscan5g.llm.template_fixer',
    'vulnscan5g.reporter',
    'vulnscan5g.reporter.console',
    'vulnscan5g.reporter.json_report',
    'vulnscan5g.reporter.html_report',
    'vulnscan5g.reporter.diff_patch',

    # Analysis dependencies
    'pycparser',
    'pycparser.c_ast',
    'pycparser.c_generator',
    'pycparser.c_parser',
    'pycparser.c_lexer',
    'pycparser.ply',
    'pycparser.ply.lex',
    'pycparser.ply.yacc',
    'rich',
    'rich.console',
    'rich.table',
    'rich.panel',
    'rich.progress',
    'jinja2',
    'requests',

    # Tree-sitter (optional but include if available)
    'tree_sitter',
    'tree_sitter_c',
    'tree_sitter_cpp',

    # Standard lib modules PyInstaller sometimes misses
    'difflib',
    'html',
    'json',
    'tempfile',
    'urllib',
    'urllib.request',
    'io',
    'dataclasses',
    'contextlib',
    'email',
    'email.mime',
    'email.mime.text',
]

a = Analysis(
    ['api_server.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        # Include the entire vulnscan5g package
        ('vulnscan5g', 'vulnscan5g'),
    ],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude unnecessary heavy packages
        'tkinter',
        'matplotlib',
        'scipy',
        'numpy',
        'pandas',
        'PIL',
        'cv2',
        'torch',
        'tensorflow',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='vulnscan5g-server',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,  # Keep console for server logging
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='electron-app/assets/icon.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='vulnscan5g-server',
)
