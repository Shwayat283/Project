# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
<<<<<<< HEAD
    ['GUI.py'],
    pathex=[],
    binaries=[],
    datas=[('image.png', '.'), ('scanners/', 'scanners/'), ('GUI/', 'GUI/')],
=======
    ['D:\\Project2\\Project\\GUI\\Design\\GUI.py'],
    pathex=[],
    binaries=[],
    datas=[('D:\\Project2\\Project\\GUI\\Design\\image.png', '.')],
>>>>>>> 00a609d01e580a3ec968885c4fbd8c5c077e3d07
    hiddenimports=[],
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
    name='GUI',
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
