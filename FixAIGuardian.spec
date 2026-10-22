# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['C:/Users/Monika/OneDrive/Desktop/FixAI-Project (2)/FixAI-Project/fixai-guardian/local_agent/main.py'],
    pathex=['C:/Users/Monika/OneDrive/Desktop/FixAI-Project (2)/FixAI-Project/fixai-guardian/local_agent'],
    binaries=[],
    datas=[
        ('C:/Users/Monika/OneDrive/Desktop/FixAI-Project (2)/FixAI-Project/fixai-guardian/local_agent/models', 'models'),
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
    hooksconfig={},
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
