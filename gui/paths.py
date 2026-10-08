"""路径解析：源码运行与 PyInstaller 冻结运行都写到同一个工程根。

冻结（exe）时 ``__file__`` 指向临时解包目录，退出即消失，
所以导出文件必须落在 exe 同级目录下。
"""

from __future__ import annotations

import os
import sys

_SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def is_frozen() -> bool:
    return getattr(sys, "frozen", False)


def project_root() -> str:
    """可写的工程根目录：exe 同级目录，或源码里的 ``wlan-csma-gui-v2``。"""
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return _SRC_ROOT
