from pathlib import Path

here = Path(SPECPATH).resolve()
backend = (here / ".." / ".." / ".." / "backend").resolve()

analysis = Analysis(
    [str(here / "core_main.py")],
    pathex=[str(backend), str(here)],
    binaries=[],
    datas=[(str(backend / "pyproject.toml"), ".")],
    hiddenimports=[
        "aiosqlite",
        "sqlalchemy.dialects.sqlite.aiosqlite",
        "sqlalchemy.dialects.postgresql.asyncpg",
        "asyncpg",
        "greenlet",
        "spike_core.entry",
        "spike_core.vectors",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pydoc", "IPython", "pytest", "hypothesis"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(analysis.pure)

executable = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="ciphermoth-core",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

collected = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    name="ciphermoth-core",
)
