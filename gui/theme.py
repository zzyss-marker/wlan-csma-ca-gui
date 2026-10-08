"""界面主题：浅色、简洁、可打印。

配色取向
--------
以白 / 浅灰为主，**颜色只用来表达语义**：

* 蓝 —— 数据帧
* 灰 —— RTS（控制帧，不抢视觉）
* 绿 —— CTS
* 青 —— ACK
* 红 —— 碰撞（全界面唯一的强警示色）
* 紫 —— 接入点 AP

这样做的两个理由：

1. 报告要打印。深色主题的截图印出来就是一整块黑色，既费墨也看不清
   细节；浅色截图在 Word 里和正文是一个调子。
2. 答辩现场。教室投影仪普遍偏灰，浅底深字比深底浅字更容易看清，
   也不容易被误认为「程序没启动」。

工程取向
--------
统一走 ``clam`` 主题。原因：macOS 的 Aqua 原生按钮一旦设了 ``bg``
就会退化成扁平灰块（看起来像禁用），而完全不设又没法把整套界面
统一成浅色。``clam`` 在三个平台上都能精确控制颜色，于是界面
在任何机器上长得一样——答辩时不会因为换台电脑就变样。
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk
from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------- 调色板
BG = "#f5f6f8"          # 窗口底色
PANEL = "#ffffff"       # 面板 / 卡片
PANEL_ALT = "#eef0f3"   # 次级面板、表头
BORDER = "#d8dce1"      # 分隔线、控件描边
FG = "#1f2328"          # 正文
FG_MUTED = "#6b7280"    # 次要文字
FG_FAINT = "#9aa1ab"    # 更弱的提示文字

ACCENT = "#1f6feb"      # 主色（蓝）
ACCENT_DARK = "#1a5fd0"
ACCENT_SOFT = "#e8f1fd"  # 主色的浅底
OK = "#1a7f37"
WARN = "#9a6700"
DANGER = "#cf222e"
DANGER_SOFT = "#fdecee"

#: 空口舞台专用配色
STAGE: Dict[str, str] = {
    "canvas": "#ffffff",
    "grid": "#eef0f3",
    "axis": "#c9ced6",
    "sta_fill": "#ffffff",
    "sta_edge": "#9aa1ab",
    "sta_text": "#1f2328",
    "ap_fill": "#6f42c1",
    "ap_edge": "#5a359f",
    "ap_text": "#ffffff",
    "tx_edge": "#cf8a00",     # 正在发送：琥珀色描边
    "tx_text": "#9a6700",
    "nav_fill": "#e8f1fd",    # NAV 冻结：浅蓝底
    "nav_edge": "#1f6feb",
    "nav_text": "#1a5fd0",
    "visible": "#3f9a52",     # 绿实线：互相可闻（站点↔站点，仅小场景画）
    "visible_soft": "#b9d8be",  # 站点↔AP 的浅绿线：默认拓扑下人人都听得到 AP
    "hidden": "#c9555e",      # 红虚线（加粗版）：碰撞参与者之间的隐藏对
    "hidden_soft": "#dfa6ac",   # 隐藏对浅红虚线：大场景下降低视觉噪声
    "range_ap": "#c3b4e6",
    "range_sta": "#dfe3e8",
    "muted_text": "#6b7280",
    "faint_text": "#9aa1ab",
    # ---- 空口时间轴（画布底部条带）
    "tl_bg": "#fbfcfd",       # 时间轴底色
    "tl_row": "#eef0f3",      # 行基线 / 空闲
    "tl_tick": "#e3e6ea",     # 时间刻度线
    "tl_collision": "#f1b3b9",  # 碰撞块填充（浅红，叠加深红描边）
    "tl_collision_edge": "#cf222e",
    "tl_retry": "#123f8c",    # 重传数据块顶部的深蓝刻痕
}

#: 帧类型 → 颜色。控制帧用灰，避免和「数据」抢注意力。
KIND_COLOR: Dict[str, str] = {
    "data": "#1f6feb",
    "rts": "#6b7280",
    "cts": "#1a7f37",
    "ack": "#0e7490",
    "collision": "#cf222e",
}

_FONT = ("TkDefaultFont", 9)
_FONT_S = ("TkDefaultFont", 8)
_FONT_B = ("TkDefaultFont", 9, "bold")
_FONT_H = ("TkDefaultFont", 13, "bold")
_MONO = ("TkFixedFont", 9)


def font(size: int = 9, bold: bool = False) -> Tuple[str, int] | Tuple[str, int, str]:
    return ("TkDefaultFont", size, "bold") if bold else ("TkDefaultFont", size)


def mono(size: int = 9, bold: bool = False) -> Tuple[str, int] | Tuple[str, int, str]:
    return ("TkFixedFont", size, "bold") if bold else ("TkFixedFont", size)


# ---------------------------------------------------------------- ttk 样式
def init_ttk(root: tk.Misc) -> ttk.Style:
    """把 ttk 控件统一成浅色扁平风。返回 Style 以便后续复用。"""
    st = ttk.Style(root)
    if "clam" in st.theme_names():
        st.theme_use("clam")

    # ---- 容器与文字
    st.configure(".", background=BG, foreground=FG, font=_FONT)
    st.configure("TFrame", background=BG)
    st.configure("Panel.TFrame", background=PANEL)
    st.configure("TLabel", background=BG, foreground=FG, font=_FONT)
    st.configure("Panel.TLabel", background=PANEL, foreground=FG, font=_FONT)
    st.configure("Muted.TLabel", background=PANEL, foreground=FG_MUTED,
                 font=_FONT_S)
    st.configure("Head.TLabel", background=PANEL, foreground=FG, font=_FONT_B)
    st.configure("Title.TLabel", background=PANEL, foreground=FG, font=_FONT_H)
    st.configure("Metric.TLabel", background=PANEL, foreground=ACCENT,
                 font=("TkFixedFont", 10, "bold"))
    st.configure("TSeparator", background=BORDER)

    # ---- 按钮
    st.configure("TButton", background=PANEL_ALT, foreground=FG,
                 bordercolor=BORDER, focuscolor=PANEL_ALT,
                 relief="flat", padding=(8, 5), font=_FONT)
    st.map("TButton",
           background=[("pressed", "#e2e5ea"), ("active", "#e6e9ee"),
                       ("disabled", PANEL_ALT)],
           foreground=[("disabled", FG_FAINT)])

    st.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                 bordercolor=ACCENT, focuscolor=ACCENT, relief="flat",
                 padding=(10, 6), font=_FONT_B)
    st.map("Accent.TButton",
           background=[("pressed", ACCENT_DARK), ("active", ACCENT_DARK),
                       ("disabled", "#a9c4f2")],
           foreground=[("disabled", "#f0f4fb")])

    st.configure("Danger.TButton", background=DANGER, foreground="#ffffff",
                 bordercolor=DANGER, focuscolor=DANGER, relief="flat",
                 padding=(10, 6), font=_FONT_B)
    st.map("Danger.TButton",
           background=[("pressed", "#b31c27"), ("active", "#b31c27")])

    # ---- 选项卡
    st.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(2, 6, 2, 0))
    st.configure("TNotebook.Tab", background=PANEL_ALT, foreground=FG_MUTED,
                 padding=(16, 7), font=_FONT, bordercolor=BORDER)
    st.map("TNotebook.Tab",
           background=[("selected", PANEL), ("active", "#e6e9ee")],
           foreground=[("selected", ACCENT)],
           font=[("selected", _FONT_B)])

    # ---- 下拉框
    st.configure("TCombobox", fieldbackground=PANEL, background=PANEL,
                 foreground=FG, arrowcolor=FG_MUTED, bordercolor=BORDER,
                 lightcolor=BORDER, darkcolor=BORDER, padding=(6, 4),
                 font=_FONT)
    st.map("TCombobox",
           fieldbackground=[("readonly", PANEL), ("disabled", PANEL_ALT)],
           foreground=[("disabled", FG_FAINT)])

    # ---- 勾选 / 单选
    for name in ("TCheckbutton", "TRadiobutton"):
        st.configure(name, background=PANEL, foreground=FG, font=_FONT,
                     focuscolor=PANEL,
                     indicatorcolor=PANEL, indicatorbackground=PANEL)
        st.map(name,
               background=[("active", PANEL)],
               foreground=[("disabled", FG_FAINT)],
               indicatorcolor=[("selected", ACCENT), ("!selected", PANEL)],
               indicatorbackground=[("selected", ACCENT), ("!selected", PANEL)])

    # ---- 表格
    st.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                 foreground=FG, bordercolor=BORDER, rowheight=22, font=_FONT)
    st.map("Treeview", background=[("selected", ACCENT_SOFT)],
           foreground=[("selected", FG)])
    st.configure("Treeview.Heading", background=PANEL_ALT, foreground=FG,
                 font=_FONT_B, relief="flat", padding=(6, 5))
    st.map("Treeview.Heading", background=[("active", "#e6e9ee")])

    # ---- 进度条
    st.configure("TProgressbar", background=ACCENT, troughcolor=PANEL_ALT,
                 bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT)
    return st


def is_macos() -> bool:
    return sys.platform.startswith("darwin")


def stage(key: str, default: str = "#000000") -> str:
    return STAGE.get(key, default)


def kind_color(kind: str) -> str:
    return KIND_COLOR.get(kind, FG_MUTED)


#: 兼容旧调用点（stage.py 早期版本用过）
def btn(bg: str = PANEL_ALT, fg: str = FG, width: int = 0) -> Dict[str, object]:
    kw: Dict[str, object] = {"style": "TButton"}
    if width:
        kw["width"] = width
    return kw


def chk(fg: str = FG, font: Optional[Tuple] = None) -> Dict[str, object]:
    return {"style": "TCheckbutton"}


def radiobutton(fg: str = FG, font: Optional[Tuple] = None) -> Dict[str, object]:
    return {"style": "TRadiobutton"}
