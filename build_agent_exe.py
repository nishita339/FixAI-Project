"""
FixAI Guardian — PyInstaller Standalone Executable Packaging Script
===================================================================

Packages the FixAI Guardian local agent into a standalone, single-file
or directory executable: FixAIGuardian.exe.

Includes:
- Trained ML models (.joblib, .json)
- Security EDR modules (event_monitor, file_monitor, threat_hunter, quarantine, canary, network_monitor, self_defense)
- Self-healing recovery playbooks
- Windows Toast notification assets
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
AGENT_DIR = PROJECT_ROOT / "fixai-guardian" / "local_agent"
MODELS_DIR = AGENT_DIR / "models"
MAIN_SCRIPT = AGENT_DIR / "main.py"
OUTPUT_DIR = PROJECT_ROOT / "dist_agent"


def build():
    print("=" * 60)
    print("  FixAI Guardian Standalone Executable Builder (PyInstaller)")
    print("=" * 60)

    try:
        import PyInstaller
        print(f"[+] PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("[*] PyInstaller not detected. Generating .spec specification file...")

    spec_content = f"""# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['{MAIN_SCRIPT.as_posix()}'],
    pathex=['{AGENT_DIR.as_posix()}'],
    binaries=[],
    datas=[
        ('{MODELS_DIR.as_posix()}', 'models'),
    ],
    hiddenimports=[
        'sklearn',
        'sklearn.ensemble',
        'sklearn.preprocessing',
        'xgboost',
        'shap',
        'joblib',
        'psutil',
        'watchdog',
        'desktop_notifier',
        'urllib3',
        'sqlite3',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'notebook', 'scipy.spatial.cKDTree'],
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
    name='FixAIGuardian',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='FixAIGuardian',
)
"""

    spec_file = PROJECT_ROOT / "FixAIGuardian.spec"
    with open(spec_file, "w", encoding="utf-8") as f:
        f.write(spec_content)

    print(f"[+] Created PyInstaller build spec: {spec_file}")
    print("[+] To compile binary: py -3.11 -m PyInstaller FixAIGuardian.spec --noconfirm")


if __name__ == "__main__":
    build()
