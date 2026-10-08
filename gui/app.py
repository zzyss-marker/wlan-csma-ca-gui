#!/usr/bin/env python3
"""802.11 CSMA/CA 无线接入仿真平台 · 图形界面主程序。

启动方式::

    cd wlan-csma-gui-v2
    python3 demo.py gui          # 推荐
    python3 gui/app.py           # 等价

界面结构
--------
顶栏（标题 + 场景快选）
  横幅（把当前空口事件翻译成一句大白话）
    选项卡
      ├ 空口舞台   —— 动画回放 + 右栏参数 / 实时指标
      ├ 讲解模式   —— 九步走，每步「说一句 + 真的动一下界面」
      ├ 实验图表   —— 四张图现场计算
      ├ 数据明细   —— 每站点统计表（可导出 CSV）
      └ 术语与说明 —— 术语表 / 图例 / Wireshark 过滤器 / 已知局限
  状态栏（运行状态 + 回放进度）

依赖：标准库 tkinter + matplotlib（图表页用）。仿真核心零依赖。
"""

from __future__ import annotations

import csv
import os
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC_PROJECT = os.path.abspath(os.path.join(_HERE, ".."))
for _p in (_SRC_PROJECT, os.path.abspath(os.path.join(_SRC_PROJECT, "..", ".."))):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gui.paths import project_root  # noqa: E402
from gui import charts, engine, glossary, guide  # noqa: E402
from gui import theme as T  # noqa: E402
from gui.engine import EventView, Playback  # noqa: E402
from gui.jobs import Jobs  # noqa: E402
from gui.stage import StagePanel  # noqa: E402

#: 导出文件（CSV / pcap）落在这里：源码 = 工程根，exe = 程序同级目录
_PROJECT = project_root()

APP_TITLE = "基于 Python 的 IEEE 802.11 CSMA/CA 协议仿真与可视化分析平台"

#: 可切换的演示场景。key 是下拉框里显示的中文标签。
PRESETS: Dict[str, dict] = {
    "① 三节点隐藏终端（教科书拓扑 A—AP—C）": dict(
        topology="line3", n_stations=3, radius_m=80.0,
        frame_len=1500, frames_per_station=60, rate_mbps=54.0,
        use_rts=False, range_m=100.0, seed=7),
    "② 环形 4 站点（全部互相隐藏，看得最清）": dict(
        topology="ring", n_stations=4, radius_m=80.0,
        frame_len=1500, frames_per_station=80, rate_mbps=54.0,
        use_rts=False, range_m=100.0, seed=11),
    "③ 环形 8 站点（默认，复现报告数据）": dict(
        topology="ring", n_stations=8, radius_m=80.0,
        frame_len=1500, frames_per_station=150, rate_mbps=54.0,
        use_rts=False, range_m=100.0, seed=11),
    "④ 环形 16 站点（大规模，压力最大）": dict(
        topology="ring", n_stations=16, radius_m=80.0,
        frame_len=1500, frames_per_station=150, rate_mbps=54.0,
        use_rts=False, range_m=100.0, seed=11),
    "⑤ 紧凑圆 8 站点（无隐藏终端，纯退避竞争）": dict(
        topology="compact", n_stations=8, radius_m=40.0,
        frame_len=1500, frames_per_station=80, rate_mbps=54.0,
        use_rts=False, range_m=100.0, seed=42),
}

DEFAULT_PRESET = "③ 环形 8 站点（默认，复现报告数据）"

_TOPO_LABEL = ("环形（隐藏终端）", "线性（三节点）", "紧凑圆形（无隐藏）")
TOPO_OF_LABEL = {"环形（隐藏终端）": "ring",
                 "线性（三节点）": "line3",
                 "紧凑圆形（无隐藏）": "compact"}

#: Wireshark 过滤器速查（界面与说明页共用同一份，避免两处写法不一致）
FILTERS: Tuple[Tuple[str, str], ...] = (
    ("wlan_radio.fcs_bad == 1", "碰撞帧：本项目的核心演示点"),
    ("wlan.fc.retry == 1", "重传帧，与碰撞帧是同一批"),
    ("wlan.fc.type_subtype == 177", "RTS"),
    ("wlan.fc.type_subtype == 193", "CTS"),
    ("wlan.fc.type_subtype == 209", "ACK"),
    ("wlan.fc.type_subtype == 130", "QoS 数据帧"),
    ("wlan.fc.type_subtype == 128", "Beacon 管理帧"),
    ("wlan.qos.tid == 6", "语音类 AC_VO"),
    ("wlan.duration > 300", "长 NAV 预约（虚拟载波侦听）"),
)


class App(tk.Tk):
    """主窗口。"""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1440x900")
        self.minsize(1180, 720)
        self.configure(bg=T.BG)

        T.init_ttk(self)
        charts.setup_font()

        self._pb: Optional[Playback] = None
        self._busy = False
        self._jobs = Jobs(self)
        self._after_ready: Optional[Callable[[], None]] = None
        self._auto_id: Optional[int] = None
        self._step_index = 0

        cfg = PRESETS[DEFAULT_PRESET]
        self._preset_var = tk.StringVar(value=DEFAULT_PRESET)
        self._topo_var = tk.StringVar(value=_TOPO_LABEL[0])
        self._n_var = tk.IntVar(value=cfg["n_stations"])
        self._size_var = tk.IntVar(value=cfg["frame_len"])
        self._per_var = tk.IntVar(value=cfg["frames_per_station"])
        self._rate_var = tk.StringVar(value=str(int(cfg["rate_mbps"])))
        self._seed_var = tk.IntVar(value=cfg["seed"])
        self._rts_var = tk.BooleanVar(value=False)

        self._status_var = tk.StringVar(value="就绪。点右上角「▶ 运行场景」开始。")
        self._banner_var = tk.StringVar(value=glossary.BANNER["idle"])
        self._event_var = tk.StringVar(value="—— 信道空闲 ——")
        self._progress_var = tk.DoubleVar(value=0.0)

        # 右栏关键指标
        self._m = {k: tk.StringVar(value="—") for k in
                   ("progress", "frames", "collisions", "throughput",
                    "coll_rate", "jain", "dropped", "rts")}

        self._build_header()
        self._build_banner()
        self._build_notebook()
        self._build_status()

        self.after(80, self._on_ready)

    # ================================================================ 顶栏
    def _build_header(self) -> None:
        bar = tk.Frame(self, bg=T.PANEL)
        bar.pack(side="top", fill="x")
        tk.Frame(bar, bg=T.BORDER, height=1).pack(side="bottom", fill="x")

        left = tk.Frame(bar, bg=T.PANEL)
        left.pack(side="left", padx=(16, 0), pady=10)
        tk.Label(left, text="802.11 CSMA/CA 无线接入仿真平台",
                 bg=T.PANEL, fg=T.FG, font=T.font(15, True)).pack(anchor="w")
        tk.Label(left, text="碰撞是看不见的 —— 除非你能让 Wireshark "
                            "把它标成 Bad FCS",
                 bg=T.PANEL, fg=T.FG_MUTED, font=T.font(9)
                 ).pack(anchor="w", pady=(2, 0))

        right = tk.Frame(bar, bg=T.PANEL)
        right.pack(side="right", padx=16)
        tk.Label(right, text="演示场景", bg=T.PANEL, fg=T.FG_MUTED,
                 font=T.font(8)).pack(side="left", padx=(0, 6))
        box = ttk.Combobox(right, textvariable=self._preset_var,
                           values=list(PRESETS), state="readonly", width=34)
        box.pack(side="left")
        # ttk.Combobox 没有 command 参数，用变量追踪响应选择变化
        self._preset_var.trace_add("write", self._on_preset_change)
        ttk.Button(right, text="▶  运行场景", style="Accent.TButton",
                   command=self.run_scenario).pack(side="left", padx=8)
        ttk.Button(right, text="⚡ 对比 RTS/CTS",
                   command=self.toggle_rts_compare).pack(side="left")

    def _build_banner(self) -> None:
        bar = tk.Frame(self, bg=T.ACCENT_SOFT)
        bar.pack(side="top", fill="x")
        self._banner_dot = tk.Label(bar, text="●", bg=T.ACCENT_SOFT,
                                    fg=T.ACCENT, font=T.font(12))
        self._banner_dot.pack(side="left", padx=(16, 6), pady=5)
        tk.Label(bar, textvariable=self._banner_var, bg=T.ACCENT_SOFT,
                 fg="#12408f", font=T.font(9), anchor="w"
                 ).pack(side="left", fill="x", expand=True, pady=5)

    # ================================================================ 选项卡
    def _build_notebook(self) -> None:
        self._nb = ttk.Notebook(self)
        self._nb.pack(side="top", fill="both", expand=True, padx=12, pady=(10, 0))
        self._tab_stage = self._build_stage_tab()
        self._tab_guide = self._build_guide_tab()
        self._charts = charts.ChartsTab(self._nb, self._jobs)
        self._nb.add(self._charts, text="  实验图表  ")
        self._tab_detail = self._build_detail_tab()
        self._tab_doc = self._build_doc_tab()

    # ---- 空口舞台
    def _build_stage_tab(self) -> tk.Frame:
        tab = tk.Frame(self._nb, bg=T.BG)
        self._nb.add(tab, text="  空口舞台  ")

        self._stage = StagePanel(tab, on_state=self._on_state,
                                 on_progress=self._on_progress)
        self._stage.pack(side="left", fill="both", expand=True,
                         padx=(0, 10), pady=10)

        side = tk.Frame(tab, bg=T.PANEL, width=286)
        side.pack(side="right", fill="y", pady=10)
        side.pack_propagate(False)

        body = tk.Frame(side, bg=T.PANEL)
        body.pack(fill="both", expand=True, padx=14, pady=12)

        def head(text: str) -> None:
            ttk.Label(body, text=text, style="Head.TLabel").pack(
                anchor="w", pady=(6, 3))

        def prow(label: str, var: tk.Variable, values: list,
                 width: int = 11) -> None:
            """标签与控件同一行 —— 侧栏必须装得下全部控件，
            不能因为一行一个 label 把底部按钮挤出可视区。"""
            r = tk.Frame(body, bg=T.PANEL)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=label, bg=T.PANEL, fg=T.FG_MUTED,
                     font=T.font(8), width=13, anchor="w").pack(side="left")
            ttk.Combobox(r, textvariable=var, values=values,
                         state="readonly", width=width).pack(
                side="right", fill="x", expand=True)

        head("仿真参数")
        prow("拓扑类型", self._topo_var, list(_TOPO_LABEL))
        prow("站点数", self._n_var, [1, 2, 3, 4, 6, 8, 12, 16])
        prow("数据帧长(字节)", self._size_var, [200, 500, 1000, 1500, 2304])
        prow("每站帧数", self._per_var, [30, 60, 80, 150])
        prow("物理层速率(Mbps)", self._rate_var, ["6", "12", "24", "54"])
        prow("随机种子", self._seed_var, [7, 11, 13, 21, 42])
        ttk.Checkbutton(body, text="启用 RTS/CTS（发送前先握手）",
                        variable=self._rts_var).pack(anchor="w", pady=(2, 6))

        ttk.Separator(body).pack(fill="x", pady=5)
        head("实时指标")
        grid = tk.Frame(body, bg=T.PANEL)
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)
        keys = [("progress", "回放进度"), ("frames", "数据帧"),
                ("collisions", "碰撞次数"), ("throughput", "吞吐 (Mbps)"),
                ("coll_rate", "碰撞率"), ("jain", "短时 Jain"),
                ("dropped", "丢包"), ("rts", "RTS/CTS")]
        for i, (k, name) in enumerate(keys):
            tk.Label(grid, text=name, bg=T.PANEL, fg=T.FG_MUTED,
                     font=T.font(8), anchor="w").grid(
                row=i, column=0, sticky="w", pady=0)
            tk.Label(grid, textvariable=self._m[k], bg=T.PANEL, fg=T.ACCENT,
                     font=T.mono(9, True), anchor="e").grid(
                row=i, column=1, sticky="e", pady=0)

        ttk.Separator(body).pack(fill="x", pady=6)
        head("当前空口事件")
        tk.Label(body, textvariable=self._event_var, bg=T.PANEL_ALT,
                 fg=T.FG, font=T.mono(9), anchor="w", justify="left",
                 wraplength=248, padx=8, pady=6).pack(fill="x")

        ttk.Separator(body).pack(fill="x", pady=6)
        ttk.Button(body, text="📦  导出 pcap（给 Wireshark）",
                   command=self.export_pcap).pack(fill="x", pady=(0, 4))
        ttk.Button(body, text="📡  导出并打开 Wireshark",
                   command=self.open_wireshark).pack(fill="x")
        return tab

    # ---- 讲解模式
    def _build_guide_tab(self) -> tk.Frame:
        tab = tk.Frame(self._nb, bg=T.BG)
        self._nb.add(tab, text="  讲解模式  ")

        card = tk.Frame(tab, bg=T.PANEL)
        card.pack(fill="both", expand=True, padx=14, pady=14)

        nav = tk.Frame(card, bg=T.PANEL)
        nav.pack(side="bottom", fill="x", padx=24, pady=16)
        tk.Frame(card, bg=T.BORDER, height=1).pack(side="bottom", fill="x")

        mid = tk.Frame(card, bg=T.PANEL)
        mid.pack(fill="both", expand=True, padx=34)
        # 上下各放一个会膨胀的空格，让正文在卡片里垂直居中，
        # 否则大屏上会出现一大片空白的下半页
        tk.Frame(mid, bg=T.PANEL).pack(expand=True)

        self._guide_pos = tk.StringVar()
        tk.Label(mid, textvariable=self._guide_pos, bg=T.PANEL, fg=T.FG_MUTED,
                 font=T.font(10), anchor="w").pack(fill="x")
        self._guide_title = tk.Label(mid, text="", bg=T.PANEL, fg=T.FG,
                                     font=T.font(24, True), anchor="w")
        self._guide_title.pack(fill="x", pady=(4, 14))

        self._guide_say = tk.Label(mid, text="", bg=T.PANEL, fg=T.FG,
                                   font=T.font(13), anchor="w",
                                   justify="left", wraplength=1000)
        self._guide_say.pack(fill="x")

        self._guide_look = tk.Label(mid, text="", bg=T.ACCENT_SOFT,
                                    fg="#12408f", font=T.font(11, True),
                                    anchor="w", justify="left",
                                    wraplength=960, padx=14, pady=10)
        self._guide_look.pack(fill="x", pady=(18, 0))

        tk.Label(mid, bg=T.PANEL, fg=T.FG_FAINT, font=T.font(9),
                 anchor="w", justify="left", wraplength=1000,
                 text="说明：每点一次「下一步」，界面会真的做一次动作"
                      "（切倍速、跳到碰撞、开关图层、翻转 RTS/CTS），"
                      "所以你只需要照着念。画面本身在「空口舞台」页。"
                 ).pack(fill="x", pady=(14, 0))
        tk.Frame(mid, bg=T.PANEL).pack(expand=True)

        ttk.Button(nav, text="← 上一步", width=12,
                   command=self.guide_prev).pack(side="left")
        ttk.Button(nav, text="下一步 →", width=12, style="Accent.TButton",
                   command=self.guide_next).pack(side="left", padx=6)
        self._auto_btn = ttk.Button(nav, text="▶  自动讲解",
                                    command=self.guide_toggle_auto)
        self._auto_btn.pack(side="left", padx=(18, 6))
        ttk.Button(nav, text="⟲ 回到第一步",
                   command=lambda: self.guide_goto(0)).pack(side="left", padx=6)
        ttk.Button(nav, text="切到空口舞台", command=lambda: self.select_tab(0)
                   ).pack(side="right")
        return tab

    # ---- 数据明细
    def _build_detail_tab(self) -> tk.Frame:
        tab = tk.Frame(self._nb, bg=T.BG)
        self._nb.add(tab, text="  数据明细  ")

        head = tk.Frame(tab, bg=T.BG)
        head.pack(fill="x", padx=14, pady=(12, 6))
        ttk.Label(head, text="本次仿真的汇总与每站点统计",
                  style="TLabel", font=T.font(12, True)).pack(side="left")
        ttk.Button(head, text="导出 CSV", command=self.export_csv
                   ).pack(side="right")

        self._summary = tk.Text(tab, height=6, bg=T.PANEL, fg=T.FG,
                                font=T.mono(9), wrap="word", bd=0,
                                highlightthickness=1,
                                highlightbackground=T.BORDER, padx=12, pady=8)
        self._summary.pack(fill="x", padx=14, pady=(0, 10))
        self._summary.configure(state="disabled")

        wrap = tk.Frame(tab, bg=T.BG)
        wrap.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        cols = ("station", "successes", "collisions", "retransmits",
                "tx_attempts", "collision_rate", "avg_backoff_slots",
                "max_backoff", "avg_delay_us", "airtime_us",
                "nav_frozen_us", "dropped")
        heads = ("站点", "成功", "碰撞", "重传", "发送尝试", "碰撞率",
                 "平均退避(时隙)", "最大退避", "平均时延(ms)",
                 "空口时间(ms)", "NAV冻结(ms)", "丢包")
        widths = (64, 56, 56, 56, 72, 64, 96, 72, 96, 96, 96, 56)
        self._tree = ttk.Treeview(wrap, columns=cols, show="headings",
                                  height=12)
        for c, h, w in zip(cols, heads, widths):
            self._tree.heading(c, text=h)
            self._tree.column(c, width=w, anchor="center")
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vs.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        return tab

    # ---- 术语与说明
    def _build_doc_tab(self) -> tk.Frame:
        tab = tk.Frame(self._nb, bg=T.BG)
        self._nb.add(tab, text="  术语与说明  ")
        text = tk.Text(tab, bg=T.PANEL, fg=T.FG, font=T.font(10),
                       wrap="word", bd=0, padx=18, pady=14,
                       highlightthickness=1, highlightbackground=T.BORDER)
        vs = ttk.Scrollbar(tab, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=vs.set)
        text.pack(side="left", fill="both", expand=True, padx=(14, 0),
                  pady=12)
        vs.pack(side="right", fill="y", padx=(0, 14), pady=12)
        text.insert("1.0", self._doc_text())
        text.configure(state="disabled")
        return tab

    # ================================================================ 状态栏
    def _build_status(self) -> None:
        bar = tk.Frame(self, bg=T.PANEL)
        bar.pack(side="bottom", fill="x")
        tk.Frame(bar, bg=T.BORDER, height=1).pack(side="top", fill="x")
        inner = tk.Frame(bar, bg=T.PANEL)
        inner.pack(fill="x", padx=14, pady=5)
        tk.Label(inner, textvariable=self._status_var, bg=T.PANEL, fg=T.FG_MUTED,
                 font=T.font(9), anchor="w").pack(side="left")
        ttk.Progressbar(inner, variable=self._progress_var, maximum=1000.0,
                        length=260).pack(side="right")

    # ================================================================ 运行
    def _on_ready(self) -> None:
        self._stage.redraw()
        self.guide_goto(0, run=False)
        self.run_scenario()      # 一进来就在跑，演示第一印象就是「它在动」

    def _on_preset_change(self, *_a: object) -> None:
        cfg = PRESETS.get(self._preset_var.get())
        if not cfg:
            return
        self._n_var.set(cfg["n_stations"])
        self._size_var.set(cfg["frame_len"])
        self._per_var.set(cfg["frames_per_station"])
        self._rate_var.set(str(int(cfg["rate_mbps"])))
        self._seed_var.set(cfg["seed"])
        self._rts_var.set(bool(cfg["use_rts"]))
        self._topo_var.set({v: k for k, v in TOPO_OF_LABEL.items()}[
            cfg["topology"]])
        self._status_var.set("已载入场景，点「▶ 运行场景」开始")
        self.run_scenario()

    def _read_config(self) -> dict:
        topo = TOPO_OF_LABEL.get(self._topo_var.get(), "ring")
        return dict(
            topology=topo,
            n_stations=int(self._n_var.get()),
            radius_m=40.0 if topo == "compact" else 80.0,
            frame_len=int(self._size_var.get()),
            frames_per_station=int(self._per_var.get()),
            rate_mbps=float(self._rate_var.get()),
            use_rts=bool(self._rts_var.get()),
            range_m=100.0, seed=int(self._seed_var.get()))

    def run_scenario(self) -> None:
        """后台跑仿真。

        配置在**主线程**读一遍就固定住 —— Tkinter 的变量不是线程安全的，
        后台线程不能再去读 ``IntVar`` / ``BooleanVar``。
        """
        if self._busy:
            return
        self._busy = True
        self._progress_var.set(0.0)
        self._status_var.set("仿真计算中…")
        self._stage.pause()
        cfg = self._read_config()
        self._jobs.submit(lambda: engine.run_cfg(cfg),
                          on_ok=self._on_scenario_ready,
                          on_error=self._on_job_failed, tag="仿真")

    def _on_job_failed(self, message: str) -> None:
        self._busy = False
        self._status_var.set("运行失败")
        messagebox.showerror("运行失败", message)

    def _on_scenario_ready(self, pb: Playback) -> None:
        self._busy = False
        self._pb = pb
        self._stage.set_playback(pb)
        self._refresh_detail()
        m = pb.metrics
        self._status_var.set(
            f"完成：{pb.topology} · {len(pb.events)} 个空口事件 · "
            f"仿真时长 {pb.duration_us / 1000:.1f} ms · "
            f"吞吐 {m['throughput_mbps']:.2f} Mbps · "
            f"碰撞率 {m['collision_rate']:.1%} · "
            f"丢包 {m['dropped_frames']}")
        cb, self._after_ready = self._after_ready, None
        if cb is not None:
            cb()
        else:
            self._stage.play()

    def _refresh_detail(self) -> None:
        pb = self._pb
        if pb is None:
            return
        m = pb.metrics
        lines = [
            f"场景：{pb.topology}    种子 seed={pb.seed}    "
            f"RTS/CTS={'开' if pb.use_rts else '关'}",
            f"拓扑：{m.get('topology_desc', '')}",
            f"站点 {m.get('stations', '?')} 个（含 AP） · "
            f"目标帧数 {m.get('target_frames', '?')} · "
            f"完成 {m.get('completed_frames', '?')} · "
            f"丢包 {m.get('dropped_frames', '?')}",
            f"吞吐 {m.get('throughput_mbps', 0):.2f} Mbps · "
            f"碰撞率 {m.get('collision_rate', 0):.1%} · "
            f"信道利用率 {m.get('channel_utilization', 0):.1%} · "
            f"浪费空口 {m.get('wasted_ratio', 0):.1%}",
            f"短时 Jain {m.get('jain_fairness_short_term', 0):.3f} · "
            f"长时 Jain {m.get('jain_fairness', 0):.4f} · "
            f"碰撞次数 {m.get('collisions', 0)} · "
            f"发送尝试 {m.get('attempts', 0)}",
        ]
        self._summary.configure(state="normal")
        self._summary.delete("1.0", "end")
        self._summary.insert("1.0", "\n".join(lines))
        self._summary.configure(state="disabled")

        self._tree.delete(*self._tree.get_children())
        for row in m.get("per_station", []):  # type: ignore[union-attr]
            self._tree.insert("", "end", values=(
                row["station"], row["successes"], row["collisions"],
                row["retransmits"], row["tx_attempts"],
                f"{row['collision_rate']:.1%}",
                f"{row['avg_backoff_slots']:.1f}", row["max_backoff"],
                f"{row['avg_delay_us'] / 1000:.1f}",
                f"{row['airtime_us'] / 1000:.1f}",
                f"{row['nav_frozen_us'] / 1000:.1f}", row["dropped"]))

    def toggle_rts_compare(self) -> None:
        """一键翻转 RTS/CTS 并重跑 —— 演示时最常用的动作。"""
        self._rts_var.set(not self._rts_var.get())
        self.run_scenario()

    # ================================================================ 回放
    def _on_progress(self, t_us: float, total_us: float) -> None:
        self._progress_var.set(
            0.0 if total_us <= 0 else 1000.0 * t_us / total_us)

    def _on_state(self, t_us: float, ev: Optional[EventView]) -> None:
        pb = self._pb
        if pb is None:
            return
        kind = ev.kind if ev is not None else "idle"
        self._banner_var.set(glossary.BANNER.get(kind, ""))
        col = T.DANGER if kind == "collision" else T.ACCENT
        self._banner_dot.configure(fg=col)

        if ev is None:
            self._event_var.set("—— 信道空闲 ——\n（所有站点都在退避等待）")
        else:
            label = {"data": "数据帧", "rts": "RTS", "cts": "CTS",
                     "ack": "ACK", "collision": "碰撞"}.get(ev.kind, ev.kind)
            tail = "（重传）" if ev.retry else ""
            if ev.kind == "collision":
                # 找出与这次碰撞在时间上重叠的其它碰撞事件 → 点名双方
                partners = sorted({e2.src_name for e2 in pb.collision_events()
                                   if e2.src_name != ev.src_name
                                   and e2.t_start < ev.t_end
                                   and e2.t_end > ev.t_start})
                who = "、".join(partners[:2]) if partners else "另一站点"
                self._event_var.set(
                    f"碰撞 · {ev.src_name} 与 {who} 同时发射\n"
                    f"两帧在 {ev.dst_name} 处叠加撞毁，时长 "
                    f"{ev.duration_us:.0f} us\n"
                    f"时间轴：底部红色块 · Wireshark: wlan_radio.fcs_bad == 1")
            else:
                self._event_var.set(
                    f"{label}{tail} · {ev.src_name} → {ev.dst_name}\n"
                    f"{ev.length} B @ {ev.rate_mbps:g} Mbps · "
                    f"TID {ev.tid} · {ev.duration_us:.0f} us")

        done_data = sum(1 for e in pb.data_events() if e.t_start <= t_us and e.ok)
        done_coll = sum(1 for e in pb.collision_events() if e.t_start <= t_us)
        total = len(pb.data_events())
        m = pb.metrics
        self._m["progress"].set(f"{t_us / 1000:.2f} / {pb.duration_us / 1000:.1f} ms")
        self._m["frames"].set(f"{done_data} / {total}")
        self._m["collisions"].set(str(done_coll))
        self._m["throughput"].set(f"{m['throughput_mbps']:.2f}")
        self._m["coll_rate"].set(f"{m['collision_rate']:.1%}")
        self._m["jain"].set(f"{m['jain_fairness_short_term']:.3f}")
        self._m["dropped"].set(str(m["dropped_frames"]))
        self._m["rts"].set("开" if m["rts_cts"] else "关")

    # ================================================================ 讲解模式
    def guide_goto(self, index: int, run: bool = True) -> None:
        index = max(0, min(index, len(guide.STEPS) - 1))
        self._step_index = index
        step = guide.STEPS[index]
        self._guide_pos.set(f"第 {index + 1} / {len(guide.STEPS)} 步")
        self._guide_title.config(text=step.title)
        self._guide_say.config(text=step.say)
        self._guide_look.config(text="看哪里：" + step.look)
        if run:
            self._exec_step(step.cmd)

    def guide_next(self) -> None:
        if self._step_index >= len(guide.STEPS) - 1:
            self._status_var.set("已经是最后一步了")
            return
        self.guide_goto(self._step_index + 1)

    def guide_prev(self) -> None:
        self.guide_goto(self._step_index - 1)

    def guide_toggle_auto(self) -> None:
        if self._auto_id is not None:
            self.after_cancel(self._auto_id)
            self._auto_id = None
            self._auto_btn.config(text="▶  自动讲解")
            return
        self._auto_btn.config(text="⏸  停止自动")
        self.narrate_next()

    def narrate_next(self) -> None:
        """自动讲解：停够时间就翻到下一步，到最后一步自动停。"""
        if self._step_index >= len(guide.STEPS) - 1:
            self._auto_id = None
            self._auto_btn.config(text="▶  自动讲解")
            return
        self.guide_next()
        self._auto_id = self.after(guide.AUTO_GAP_MS, self.narrate_next)

    # ---- 每一步真正去动界面
    def _exec_step(self, cmd: str) -> None:
        pb = self._pb
        st = self._stage
        if cmd == "step_intro":
            st.set_speed("标准 5×")
            st.set_flags(links=False, nav=False, range=False, backoff=True)
            st.set_focus("STA-1")
            if pb is not None:
                st.goto(min(pb.duration_us * 0.25, pb.duration_us))
        elif cmd == "step_range":
            st.pause()
            st.set_flags(links=True, range=True, nav=False)
            st.set_focus(None)
        elif cmd == "step_backoff":
            st.set_flags(links=False, range=False, nav=False, backoff=True)
            st.set_focus("STA-1")
            st.goto(self._first_idle_time())
        elif cmd == "step_send":
            ev = self._first_event("data", ok=True)
            if ev is not None:
                st.set_focus(ev.src_name)
                st.goto(ev.t_start + ev.duration_us * 0.45)
                st.set_flags(links=False, nav=False, range=False)
        elif cmd == "step_collision":
            st.set_speed("慢放 1×")
            st.set_flags(links=False, nav=False, range=False, backoff=True)
            st.goto(0.0)
            if pb is not None and pb.collision_events():
                ev = pb.collision_events()[0]
                st.set_focus(ev.src_name)
                st.goto(ev.t_start + ev.duration_us * 0.55)
        elif cmd == "step_backoff2":
            if pb is not None and pb.collision_events():
                ev = pb.collision_events()[0]
                st.set_focus(ev.src_name)
                st.goto(min(pb.duration_us, ev.t_end + 900 + 6000))
            st.set_flags(backoff=True, nav=False, links=False)
        elif cmd == "step_hidden":
            st.pause()
            st.set_flags(links=True, range=True, nav=False)
            st.set_focus("STA-1")
            if pb is not None:
                st.goto(min(pb.duration_us, pb.duration_us * 0.05))
        elif cmd == "step_rts_on":
            st.set_speed("标准 5×")
            st.set_flags(links=True, range=False, nav=True, backoff=True)
            st.set_focus(None)
            if not self._rts_var.get():
                self._rts_var.set(True)
                self._after_ready = self._jump_to_rts
                self.run_scenario()
            else:
                self._jump_to_rts()
        elif cmd == "step_rts_result":
            if not self._rts_var.get():
                self._rts_var.set(True)
                self._after_ready = self._finish_rts_step
                self.run_scenario()
            else:
                self._finish_rts_step()

    def _jump_to_rts(self) -> None:
        pb = self._pb
        if pb is None:
            return
        for e in pb.events:
            if e.kind == "rts":
                self._stage.goto(e.t_start + e.duration_us * 0.4)
                break
        self._stage.pause()

    def _finish_rts_step(self) -> None:
        self._stage.pause()
        # 顺便跑一遍未启用 RTS 的对照，把两个数字放在状态栏里对比
        cfg = self._read_config()
        cfg_off = dict(cfg, use_rts=False)
        cur = self._pb.metrics if self._pb else {}

        def work():
            return engine.run_cfg(cfg_off)

        def done(pb_off: Playback) -> None:
            a = pb_off.metrics
            b = cur
            self._status_var.set(
                f"对照结果：丢包 {a['dropped_frames']} → "
                f"{b.get('dropped_frames', '?')} · "
                f"短时 Jain {a['jain_fairness_short_term']:.3f} → "
                f"{b.get('jain_fairness_short_term', 0):.3f} · "
                f"吞吐 {a['throughput_mbps']:.2f} → "
                f"{b.get('throughput_mbps', 0):.2f} Mbps"
                "   （结论：RTS/CTS 不是更好，是在特定代价下更划算）")

        self._progress_var.set(0.0)
        self._jobs.submit(work, on_ok=done, tag="RTS 对照")

    # ---- 小工具
    def _first_idle_time(self) -> float:
        pb = self._pb
        if pb is None:
            return 0.0
        end = 0.0
        for e in pb.events:
            if e.t_start > end + 500:
                return end + 250
            end = max(end, e.t_end)
        return 0.0

    def _first_event(self, kind: str,
                     ok: Optional[bool] = None) -> Optional[EventView]:
        if self._pb is None:
            return None
        for e in self._pb.events:
            if e.kind == kind and (ok is None or e.ok == ok):
                return e
        return None

    # ================================================================ 导出
    def export_pcap(self, open_after: bool = False) -> None:
        if self._busy:
            return
        self._busy = True
        self._status_var.set("生成 pcap 中…")
        cfg = self._read_config()

        def work() -> str:
            path = engine.export_pcap(cfg)
            if open_after:
                self._launch_wireshark(path)
            return path

        def done(path: str) -> None:
            self._busy = False
            self._status_var.set(
                f"已导出 {path}（linktype 127 = Radiotap + 802.11）。"
                "建议过滤器： wlan_radio.fcs_bad == 1")

        self._jobs.submit(work, on_ok=done, on_error=self._on_job_failed,
                          tag="导出 pcap")

    def open_wireshark(self) -> None:
        """导出当前场景的 pcap 并唤起 Wireshark。

        这是整个演示的收口动作：仿真里判定的碰撞，
        在 Wireshark 里能被 ``wlan_radio.fcs_bad == 1`` 直接过滤出来。
        """
        if self._busy:
            return
        self._status_var.set("导出 pcap 并启动 Wireshark…")
        self.export_pcap(open_after=True)

    def _launch_wireshark(self, path: str) -> None:
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", "-a", "Wireshark", path])
            elif sys.platform == "win32":
                # Windows 上 wireshark.exe 通常不在 PATH，交给文件关联打开
                os.startfile(path)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["wireshark", path])
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"未能启动 Wireshark：{exc}") from exc

    def export_csv(self) -> None:
        if self._pb is None:
            messagebox.showinfo("还没有数据", "先运行一次场景再导出。")
            return
        out = os.path.join(_PROJECT, "out")
        os.makedirs(out, exist_ok=True)
        path = os.path.join(out, "per_station.csv")
        rows = self._pb.metrics.get("per_station", [])  # type: ignore[union-attr]
        if not rows:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            wr = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            wr.writeheader()
            wr.writerows(rows)
        self._status_var.set(f"已导出 {path}")

    # ================================================================ 杂项
    def select_tab(self, index: int) -> None:
        """切到某个选项卡（讲解脚本和截图工具都会用）。"""
        try:
            self._nb.select(index)
        except Exception:  # noqa: BLE001
            pass

    def _doc_text(self) -> str:
        out: List[str] = []

        def add(s: str = "") -> None:
            out.append(s)

        add("怎么用这个软件（给第一次打开的人）")
        add("=" * 62)
        add("· 左上角「空口舞台」是主界面：点「▶ 运行场景」跑一次仿真，")
        add("  然后可以播放 / 暂停 / 慢放，或点「⏭ 下一个碰撞」直接跳到碰撞那一刻。")
        add("· 画布底部是「空口时间轴」：数据 / RTS / CTS / ACK / 碰撞各占一行，")
        add("  播放指针实时移动；点时间轴任意位置可以直接跳到那个时刻。")
        add("  红色块 = 碰撞，数据块顶部的深蓝刻痕 = 重传。")
        add("· 「讲解模式」是九步走的脚本。每点一次「下一步」，界面会自己把")
        add("  图层、倍速、RTS 开关调好 —— 讲解者照着念就行，不用在控件里找。")
        add("· 「实验图表」四张图是**现场计算**的，不是贴的静态图；改任何参数都会重算。")
        add("· 「数据明细」是每站点统计表，可导出 CSV。")
        add("· 导出 pcap 后，按下文第三节的过滤器在 Wireshark 里交叉验证。")
        add()
        add("术语表（界面上出现的词，这里都有一句大白话解释）")
        add("=" * 62)
        for term, expl in glossary.TERMS:
            add(f"· {term}")
            add(f"    {expl}")
        add()
        add("颜色与图例")
        add("=" * 62)
        for name, color, expl in glossary.LEGEND:
            add(f"· {name:<8}{expl}")
        add()
        add("Wireshark 过滤器速查（导出 pcap 后直接粘贴到过滤栏）")
        add("=" * 62)
        for expr, expl in FILTERS:
            add(f"· {expr:<32}{expl}")
        add()
        add("注意：wlan.fc.type_subtype 是 (subtype << 4) | type 拼出来的，"
            "不是 subtype 本身。")
        add("所以 Beacon 是 128 而不是 8，ACK 是 209 而不是 13。")
        add()
        add("四张图各自的一句话结论")
        add("=" * 62)
        for key in ("xs", "matrix", "edca", "airtime"):
            add(f"· {glossary.charts_takeaway()[key]}")
        add()
        add("已知局限（答辩时会主动说明）")
        add("=" * 62)
        for s in (
            "距离模型是硬阈值（≤100 m 就能听到），没有衰落、阴影和多径。",
            "没有捕获效应：两帧重叠即判碰撞；真实情况下强信号可以捕获信道。",
            "没有信道误码，碰撞是唯一的丢包来源。",
            "没有速率自适应、没有 MIMO、没有 OFDMA。",
            "未在真实网卡上验证（需要 Linux + mac80211_hwsim 环境）。",
            "",
            "结论对模型误差不敏感：RTS/CTS 增益在 6 Mbps 为 +83%、"
            "在 54 Mbps 为 -19%，",
            "这个数量级不会因为物理层精度而反转。",
        ):
            add("· " + s if s else "")
        return "\n".join(out)


def main() -> None:
    if sys.platform.startswith("linux"):
        if os.environ.get("DISPLAY") in (None, ""):
            sys.exit("错误：Linux 下需要图形环境（DISPLAY 未设置）")
    App().mainloop()


if __name__ == "__main__":
    main()
