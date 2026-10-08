# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：把仿真平台 GUI 打成**单文件** Windows exe。

本地（Windows）构建::

    pip install -r requirements-build.txt
    pyinstaller wlanlab_gui.spec

产物 ``dist/WlanLab-CSMA-CA.exe``；导出的 CSV / pcap 写在 exe 同级目录的 ``out/``。

``console=False`` 表示双击不弹黑框；启动异常由 ``run_gui.py`` 弹窗兜底。
"""
import os

PROJ = os.path.abspath(SPECPATH)  # noqa: F821 - PyInstaller 注入

# TkAgg 后端与 PIL 的 Tk 接口都是运行期才 import 的，需显式声明
hiddenimports = [
    "matplotlib.backends.backend_tkagg",
    "PIL.ImageTk",
    "PIL._tkinter_finder",
]

a = Analysis(
    ["run_gui.py"],
    pathex=[PROJ],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        # matplotlib 的备选后端 / 交互式工具，exe 用不到，能显著瘦身。
        # 注意别排除 unittest：netcore.testkit 会 import 它。
        "PyQt5", "PyQt6", "PySide2", "PySide6", "gi",
        "IPython", "notebook", "scipy", "pandas",
        "tkinter.test",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="WlanLab-CSMA-CA",
    debug=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)
