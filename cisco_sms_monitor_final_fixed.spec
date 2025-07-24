# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['cisco_sms_monitor_final_fixed.py'],
    pathex=[],
    binaries=[],
    datas=[('combined_sms_monitor.ui', '.'), ('device_settings_dialog.ui', '.'), ('sms_log_dialog.ui', '.'), ('ssh_credentials_dialog.ui', '.'), ('db_settings_dialog.ui', '.'), ('spinner.gif', '.'), ('icons', 'icons'), ('C:\\\\Users\\\\dnurdiansyah\\\\AppData\\\\Local\\\\Programs\\\\Python\\\\Python313\\\\Lib\\\\site-packages\\\\mysql\\\\connector\\\\locales', 'mysql\\\\connector\\\\locales')],
    hiddenimports=['mysql.connector.plugins.mysql_native_password'],
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
    name='cisco_sms_monitor_final_fixed',
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
)
