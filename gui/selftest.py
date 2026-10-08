#!/usr/bin/env python3
"""界面自检：不开窗口也能把整套交互跑一遍。

为什么需要它
------------
Tkinter 的错误大多只在「某个按钮被点下去」的瞬间才炸出来。答辩现场
最怕的就是这种暗病：平时看着好好的，一讲到这里就崩。

这个脚本不进入 ``mainloop``，用 ``update()`` 手动泵事件，然后把

* 全部 5 个选项卡
* 全部 9 个讲解步骤（每一步都会真的去动界面）
* 5 个演示场景
* 四张图表现场计算
* 导出 pcap / 导出 CSV
* 5 个功能开关

逐项跑一遍，任何一项抛异常都会立刻报出来。

用法::

    cd wlan-csma-gui-v2
    python3 gui/selftest.py
"""

from __future__ import annotations

import os
import sys
import time
import tkinter as tk
import traceback
from typing import Callable, List, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT = os.path.abspath(os.path.join(_HERE, ".."))
for _p in (_PROJECT, os.path.abspath(os.path.join(_PROJECT, "..", ".."))):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gui import engine, glossary, guide  # noqa: E402
from gui.app import PRESETS, App  # noqa: E402

_FAIL: List[Tuple[str, str]] = []


def pump(app: tk.Tk, seconds: float = 0.4) -> None:
    end = time.time() + seconds
    while time.time() < end:
        app.update()
        time.sleep(0.02)


def wait_for(app: tk.Tk, cond: Callable[[], bool], timeout: float = 25.0
             ) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        app.update()
        if cond():
            return True
        time.sleep(0.03)
    return False


def check(name: str, fn: Callable[[], None], app: tk.Tk) -> None:
    try:
        fn()
        pump(app, 0.25)
        print(f"  ✓ {name}")
    except Exception as exc:  # noqa: BLE001
        _FAIL.append((name, f"{type(exc).__name__}: {exc}"))
        print(f"  ✗ {name}  →  {type(exc).__name__}: {exc}")
        traceback.print_exc(limit=3)


def main() -> int:
    print("构建窗口…")
    app = App()
    app.geometry("1440x900+40+40")
    app.withdraw()          # 自检不需要真看到窗口
    app.update()
    if not wait_for(app, lambda: app._pb is not None):
        print("✗ 初始场景 25 秒内没跑出来")
        return 1
    print(f"初始场景就绪：{app._pb.topology}，"
          f"{len(app._pb.events)} 个事件\n")

    print("① 选项卡切换")
    for i, name in enumerate(("空口舞台", "讲解模式", "实验图表",
                              "数据明细", "术语与说明")):
        check(f"切到「{name}」", lambda i=i: app.select_tab(i), app)

    print("\n② 演示场景（每个都跑一遍）")
    for label in PRESETS:
        def go(label=label):
            app._preset_var.set(label)     # trace 会自动触发重跑
            if not wait_for(app, lambda: not app._busy, timeout=25.0):
                raise TimeoutError("场景未在 25 秒内跑完")
        check(f"载入 {label}", go, app)

    print("\n③ 功能开关")
    check("翻转 RTS/CTS 并重跑", lambda: (
        app.toggle_rts_compare(),
        wait_for(app, lambda: not app._busy, timeout=25.0)), app)
    check("舞台图层 全开", lambda: app._stage.set_flags(
        links=True, range=True, nav=True, backoff=True), app)
    check("舞台图层 全关", lambda: app._stage.set_flags(
        links=False, range=False, nav=False, backoff=False), app)
    check("舞台图层 复原", lambda: app._stage.set_flags(
        links=True, range=True, nav=True, backoff=True), app)
    for spd in ("慢放 1×", "标准 5×", "快 25×", "极速 250×"):
        check(f"倍速 {spd}", lambda spd=spd: app._stage.set_speed(spd), app)

    print("\n④ 回放控制")
    check("播放", lambda: app._stage.play(), app)
    check("暂停", lambda: app._stage.pause(), app)
    check("重置", lambda: app._stage.reset(), app)
    check("跳到下一个碰撞", lambda: app._stage.jump_next_collision(), app)
    check("点站点跳转(模拟)",
          lambda: app._stage._on_click(type("E", (), {
              "x": app._stage._canvas.winfo_width() // 2,
              "y": app._stage._canvas.winfo_height() // 2})()), app)

    print("\n⑤ 讲解模式：9 步全走一遍")
    app.select_tab(1)
    for i, step in enumerate(guide.STEPS):
        def go(i=i):
            app.guide_goto(i)
            if not wait_for(app, lambda: not app._busy, timeout=30.0):
                raise TimeoutError("该步骤等待超时")
        check(f"第 {i + 1} 步：{step.title}", go, app)
    check("上一步", app.guide_prev, app)
    check("下一步", app.guide_next, app)
    check("回到第一步", lambda: app.guide_goto(0), app)

    print("\n⑥ 术语表与说明页")
    for key in ("xs", "matrix", "edca", "airtime"):
        def look(key=key):
            text = app._doc_text()
            assert glossary.charts_takeaway()[key] in text, f"{key} 结论缺失"
        check(f"说明页含 {key} 结论", look, app)
    assert "wlan_radio.fcs_bad == 1" in app._doc_text()
    print("  ✓ 说明页含 Wireshark 过滤器")

    print("\n⑦ 四张图表现场计算")
    app.select_tab(2)
    t0 = time.time()
    check("计算全部图表", app._charts.compute_sync, app)
    print(f"     耗时 {time.time() - t0:.1f} 秒")
    print(f"     数据键：{sorted(app._charts._data)}")

    print("\n⑧ 导出")
    check("导出 CSV", app.export_csv, app)
    csv_path = os.path.join(_PROJECT, "out", "per_station.csv")
    print(f"     {'存在' if os.path.exists(csv_path) else '缺失'}：{csv_path}")

    def do_pcap():
        app._status_var.set("")
        app.export_pcap()
        if not wait_for(app, lambda: not app._busy, timeout=60.0):
            raise TimeoutError("pcap 导出超时")
    check("导出 pcap", do_pcap, app)
    pcap_path = os.path.join(_PROJECT, "out", "lab_live.pcap")
    size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
    print(f"     {'存在' if size else '缺失'}：{pcap_path} ({size} 字节)")

    app.destroy()

    print("\n" + "=" * 58)
    if _FAIL:
        print(f"自检结果：{len(_FAIL)} 项失败")
        for name, err in _FAIL:
            print(f"  ✗ {name}  →  {err}")
        return 1
    print("自检结果：全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
