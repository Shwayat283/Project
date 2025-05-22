# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('image.png', '.'), ('scanners', 'scanners')]
binaries = []
hiddenimports = ['playwright.sync_api', 'playwright._impl._api_types', 'playwright._impl._browser', 'playwright._impl._browser_context', 'playwright._impl._browser_type', 'playwright._impl._connection', 'playwright._impl._event_context_manager', 'playwright._impl._frame', 'playwright._impl._input', 'playwright._impl._js_handle', 'playwright._impl._page', 'playwright._impl._playwright', 'playwright._impl._transport']
tmp_ret = collect_all('playwright')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['GUI.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='RocScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['image.png'],
)
