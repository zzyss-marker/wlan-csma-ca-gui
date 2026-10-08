#!/usr/bin/env python3
"""图形界面入口（源码 / exe 两用）。

打包成 exe 后没有控制台，任何启动期异常都会被吞掉，
所以这里统一兜底：出错就弹窗把 traceback 显示出来。

用法::

    python3 run_gui.py            # 正常启动
    python3 run_gui.py --smoke    # 自检：建好窗口立刻销毁，验证依赖齐全（CI 用）
"""
from __future__ import annotations

import os
import sys
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def _show_fatal(exc: BaseException) -> None:
    detail = "".join(
        traceback.format_exception(type(exc), exc, exc.__traceback__))
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("仿真平台启动失败", detail[-1800:])
        root.destroy()
    except Exception:  # noqa: BLE001 - 连 Tk 都起不来时只能退回 stderr
        sys.stderr.write(detail)


def _smoke() -> None:
    from gui.app import App

    app = App()
    app.update_idletasks()
    app.destroy()


def main() -> int:
    try:
        if "--smoke" in sys.argv[1:]:
            _smoke()
            return 0
        from gui.app import main as gui_main

        gui_main()
    except SystemExit:  # gui.app 自己给出的退出原因（如 Linux 无 DISPLAY）
        raise
    except Exception as exc:  # noqa: BLE001
        _show_fatal(exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
