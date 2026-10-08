#!/usr/bin/env python3
"""界面截图工具：把主窗口的各个页面自动截成 PNG。

为什么需要它
------------
课程设计报告里必须有界面截图（老师明确要求「软件用图形界面实现」），
而手工截图既要摆状态、又要切选项卡，容易漏、还不能复现。
这个脚本把「摆状态 → 切页 → 截屏」全部固定下来：

* 不进入 ``mainloop``，用 ``update()`` 手动泵事件，因此可以**同步**把
  仿真的某一时刻、某个图层组合精确摆好再截。
* 用 macOS 自带 ``screencapture -R`` 按窗口矩形截，不需要额外依赖。

用法::

    cd wlan-csma-gui-v2
    python3 gui/shot.py            # 输出到 shot/
    python3 gui/shot.py 报告配图    # 输出到指定目录

产物是若干 ``PNG``，可直接拖进 Word。
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import tkinter as tk
from typing import Callable, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT = os.path.abspath(os.path.join(_HERE, ".."))
for _p in (_PROJECT, os.path.abspath(os.path.join(_PROJECT, "..", ".."))):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gui import engine  # noqa: E402
from gui.app import PRESETS, App  # noqa: E402

WIN_W, WIN_H = 1440, 900
WIN_X, WIN_Y = 40, 40
#: 直接按窗口矩形截。不要再加减标题栏高度：试过 +28，结果是上方多截一条
#: 桌面、下方多截一条 Dock —— 窗口的 rootx/rooty 已经是内容区原点。
TITLE_H = 0

SHOTS: list[tuple[str, str]] = []   # (文件名, 说明)，运行时填充


def pump(app: tk.Tk, seconds: float) -> None:
    """手动泵事件循环：让 ``after`` 回调与后台线程的结果都能落地。"""
    end = time.time() + seconds
    while time.time() < end:
        app.update()
        time.sleep(0.02)


def wait_for(app: tk.Tk, cond: Callable[[], bool], timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        app.update()
        if cond():
            return True
        time.sleep(0.03)
    return False


def grab(app: tk.Tk, outdir: str, name: str, note: str) -> str:
    """按窗口矩形截屏。"""
    app.update()
    app.lift()
    time.sleep(0.18)
    x = app.winfo_rootx()
    y = max(0, app.winfo_rooty() - TITLE_H)
    w = app.winfo_width()
    h = app.winfo_height() + TITLE_H
    path = os.path.join(outdir, f"{name}.png")
    subprocess.run(["screencapture", "-x", "-R", f"{x},{y},{w},{h}", path],
                   check=True)
    SHOTS.append((f"{name}.png", note))
    print(f"  ✓ {name}.png   {note}")
    return path


# ---------------------------------------------------------------- 摆状态
def apply_cfg(app: App, cfg: dict) -> engine.Playback:
    """同步跑一次仿真并把结果装进界面（不依赖 mainloop）。"""
    pb = engine.run_cfg(cfg)
    app._on_scenario_ready(pb)
    app.update()
    return pb


def at_collision(app: App) -> float:
    """把回放指针停到第一次碰撞的中间时刻，返回该时刻。"""
    pb = app._pb
    assert pb is not None
    cs = pb.collision_events()
    if not cs:
        return pb.duration_us * 0.3
    ev = cs[0]
    app._stage.goto(ev.t_start + ev.duration_us * 0.55)
    return ev.t_start


def find_rich_moment(pb: engine.Playback, lo: float = 0.0,
                     hi: float = 0.4, samples: int = 400) -> float:
    """找一个「一张图能说明最多东西」的时刻。

    评分同时考虑：有帧在飞（看得见交换过程）、有站点在倒计时（看得见
    退避计数器跳动）、有站点被 NAV 冻结、有碰撞。用这样的时刻做主界面
    截图，比随便停一下信息量大得多。
    """
    best_t, best_score = pb.duration_us * 0.1, -1.0
    for i in range(samples):
        t = pb.duration_us * (lo + (hi - lo) * (i + 0.5) / samples)
        snap = pb.state_at(t)
        live = sum(1 for _n, _cw, b, _d, _p, _q in snap if b is not None)
        nav = sum(1 for _n, _cw, _b, d, _p, _q in snap if d > t)
        flying = sum(1 for e in pb.events
                     if e.kind != "collision" and e.t_start <= t < e.t_end)
        coll = sum(1 for e in pb.collision_events()
                   if e.t_start <= t < e.t_end + 900)
        score = live * 2.0 + flying * 3.0 + nav * 2.0 + coll * 4.0
        if score > best_score:
            best_score, best_t = score, t
    return best_t


def at_rts_exchange(app: App) -> float:
    """停到一次 RTS/CTS 握手正在进行、且 NAV 已生效的时刻。"""
    pb = app._pb
    assert pb is not None
    for i, e in enumerate(pb.events):
        if e.kind == "cts":
            app._stage.goto(e.t_start + e.duration_us * 0.35)
            return e.t_start
    return pb.duration_us * 0.2


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        _PROJECT, "shot")
    os.makedirs(outdir, exist_ok=True)

    app = App()
    app.geometry(f"{WIN_W}x{WIN_H}+{WIN_X}+{WIN_Y}")
    app.attributes("-topmost", True)
    app.lift()
    try:
        app.focus_force()
    except tk.TclError:
        pass

    print("等待初始场景就绪…")
    wait_for(app, lambda: app._pb is not None, timeout=25.0)
    pump(app, 0.6)

    # ---- 1. 主界面：默认场景 + 全部图层 + 信息最密的时刻
    cfg_ring = dict(PRESETS["③ 环形 8 站点（默认，复现报告数据）"])
    apply_cfg(app, cfg_ring)
    app._stage.pause()
    app._stage.set_flags(links=True, range=True, nav=True, backoff=True)
    assert app._pb is not None
    app._stage.goto(find_rich_moment(app._pb))
    app.select_tab(0)
    pump(app, 0.5)
    grab(app, outdir, "01_主界面_空口舞台",
         "主界面：8 站点环形，全部图层打开，退避计数器正在跳动")

    # ---- 2. 碰撞瞬间：画面里直接弹出人话解释
    at_collision(app)
    pump(app, 0.4)
    grab(app, outdir, "02_碰撞瞬间_画面内解释",
         "碰撞瞬间：接入点爆红，画面里直接写清「为什么会撞」")

    # ---- 3. 开启 RTS/CTS：NAV 冻结区出现
    cfg_rts = dict(cfg_ring, use_rts=True)
    apply_cfg(app, cfg_rts)
    app._stage.pause()
    app._stage.set_flags(links=True, range=False, nav=True, backoff=True)
    at_rts_exchange(app)
    app.select_tab(0)
    pump(app, 0.5)
    grab(app, outdir, "03_开启RTSCTS_NAV冻结",
         "开启 RTS/CTS 后：RTS+CTS 握手，其他站点被 NAV 冻结")

    # ---- 4. 三节点隐藏终端（教科书拓扑）
    cfg_line3 = dict(PRESETS["① 三节点隐藏终端（教科书拓扑 A—AP—C）"])
    apply_cfg(app, cfg_line3)
    app._stage.pause()
    app._stage.set_flags(links=True, range=True, nav=False, backoff=True)
    at_collision(app)
    app.select_tab(0)
    pump(app, 0.5)
    grab(app, outdir, "04_三节点隐藏终端拓扑",
         "教科书拓扑 A—AP—C：A 与 C 相距 160 m，互相听不到")

    # ---- 5. 讲解模式
    app.select_tab(1)
    app.guide_goto(4)          # 第 5 步：碰撞是怎么发生的
    pump(app, 0.6)
    grab(app, outdir, "05_讲解模式_碰撞那一步",
         "讲解模式：每步一句大白话 + 「看哪里」+ 真实界面动作")

    # ---- 6-9. 四张实验图表
    app.select_tab(2)
    pump(app, 0.3)
    print("现场计算四张图表（约 10-20 秒）…")
    app._charts.compute_sync()
    pump(app, 0.8)
    chart_names = ["06_图表_DCF站点数扫描", "07_图表_RTS增益热力图",
                   "08_图表_EDCA时延分层", "09_图表_空口时间分析"]
    chart_notes = ["DCF：站点数对吞吐/碰撞率/公平性的影响",
                   "RTS/CTS 增益矩阵：>1 表示划算",
                   "EDCA 四类接入时延分层（灰阶）",
                   "54 Mbps 网卡为什么只有 30 Mbps"]
    for i, (nm, note) in enumerate(zip(chart_names, chart_notes)):
        app._charts._notebook.select(i)
        pump(app, 0.5)
        grab(app, outdir, nm, note)

    # ---- 10. 数据明细
    app.select_tab(3)
    pump(app, 0.5)
    grab(app, outdir, "10_数据明细_每站点统计", "每站点统计表，可导出 CSV")

    # ---- 11. 术语与说明
    app.select_tab(4)
    pump(app, 0.5)
    grab(app, outdir, "11_术语与说明", "术语表 / 图例 / Wireshark 过滤器 / 局限")

    app.attributes("-topmost", False)
    app.destroy()

    print(f"\n共 {len(SHOTS)} 张，输出目录：{outdir}")
    for name, note in SHOTS:
        print(f"  {name:<38}{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
