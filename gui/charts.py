"""统计图表页。

四张图全部**现场计算**，不是贴的静态图：切到「图表」页点一下，
后台线程跑仿真、算完再回主线程画。好处是演示时可以直接说
「这些数字是现在跑的」，改任何参数都会重新出图。

四张图对应报告正文的四个实验结论：

1. **DCF 站点数扫描** —— 人越多越慢，吞吐在 2 站点见顶
2. **RTS/CTS 增益热力图** —— 不是「更好」，是「更划算」
3. **EDCA 四类时延分层** —— VO 与 BK 差 5.5 倍
4. **空口时间 / 帧长** —— 54 Mbps 的网卡为什么实测只有 30 Mbps
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Optional, Tuple

import matplotlib

matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402
from matplotlib import font_manager, pyplot as plt  # noqa: E402

from . import engine  # noqa: E402
from . import theme as _theme  # noqa: E402
from .jobs import Jobs  # noqa: F401, E402  # 仅用于类型标注
from wlanlab import dcf as D  # noqa: E402
from wlanlab import edca as E  # noqa: E402
from wlanlab import phy  # noqa: E402

#: 从主题层取几个常用色，避免在绘图代码里重复字面量
T_BG = _theme.BG
T_FG_MUTED = _theme.FG_MUTED
T_FAINT = _theme.FG_FAINT

_CJK = ["PingFang SC", "Heiti TC", "Hiragino Sans GB", "Arial Unicode MS",
        "Songti SC", "Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]


def setup_font() -> Optional[str]:
    """挑一个系统里真实存在的中文字体，避免图表中文乱码。"""
    global _CJK
    available = {f.name for f in font_manager.fontManager.ttflist}
    # 负号用的是 Unicode 减号，多数中文字体没有这个字形，会画成方框
    plt.rcParams["axes.unicode_minus"] = False
    for cand in _CJK:
        if cand in available:
            plt.rcParams["font.sans-serif"] = [cand] + list(
                plt.rcParams["font.sans-serif"])
            return cand
    return None


#: 绘图统一色板（浅色，打印友好）
C_LINE = "#1f6feb"      # 主数据序列
C_ALT = "#9a6700"       # 对照序列
C_BAD = "#cf222e"       # 警示 / 上限
C_OK = "#1a7f37"        # 正向
C_GRAY = "#9aa1ab"      # 次要参考线
C_TEXT = "#1f2328"
C_TICK = "#4b5563"
C_GRID = "#e5e7eb"
C_AXIS = "#c9ced6"
C_PAPER = "#ffffff"
#: EDCA 四级灰阶：越深 = 优先级越高（论文 / Visio 风格，不靠颜色表意）
GRAYS = ("#1f2328", "#4b5563", "#7b8794", "#adb5bd")


# ================================================================ 数据计算
def dcf_sweep(stations: Tuple[int, ...] = (1, 2, 4, 8, 12, 16),
              frames: int = 150) -> Dict[str, List]:
    """站点数扫描：吞吐 / 碰撞率 / 短时公平性。"""
    xs: List[int] = []
    thru: List[float] = []
    coll: List[float] = []
    jain_short: List[float] = []
    jain_long: List[float] = []
    for n in stations:
        pb = engine.run_dcf_sweep(n_stations=n, frames_per_station=frames)
        m = pb.metrics
        xs.append(n)
        thru.append(m["throughput_mbps"])
        coll.append(m["collision_rate"] * 100)
        jain_short.append(m["jain_fairness_short_term"])
        jain_long.append(m["jain_fairness"])
    return dict(xs=xs, thru=thru, coll=coll, jain_short=jain_short,
                jain_long=jain_long)


def rts_gain_matrix(rates=(6.0, 12.0, 24.0, 54.0), sizes=(200, 500, 1000,
                                                           1500, 2304),
                    n_stations: int = 8, frames: int = 80,
                    seed: int = 13) -> Tuple[List[float], List[int],
                                             List[List[float]]]:
    """RTS/CTS 增益 = 启用时的吞吐 / 未启用时的吞吐。>1 表示划算。"""
    matrix: List[List[float]] = []
    for rate in rates:
        row: List[float] = []
        for size in sizes:
            vals: Dict[bool, float] = {}
            for use_rts in (False, True):
                pb = engine.run_hidden_ring(
                    n_stations=n_stations, frame_len=size,
                    frames_per_station=frames, rate_mbps=rate,
                    use_rts=use_rts, seed=seed)
                vals[use_rts] = pb.metrics["throughput_mbps"]
            row.append(vals[True] / vals[False] if vals[False] else 0.0)
        matrix.append(row)
    return list(rates), list(sizes), matrix


def edca_delays(n_stations: int = 3, frames: int = 30,
                seed: int = 5) -> Tuple[List[str], List[float],
                                        Dict[str, float], float]:
    """四类接入类别的平均时延（完整 EDCA）。

    返回 ``(名称列表, 时延 ms, 每类明细, VO/BK 时延比)``。
    顺序按优先级从高到低排（VO 在前），不要依赖 ``E.ALL_ACS`` 的原始顺序——
    那个顺序是反的，直接按索引取会把时延比算反。
    """
    sim, ap, stas = E.build_edca_bss(n_stations=n_stations, seed=seed)
    for name in stas:
        for ac, tid in ((E.AC_VO, 6), (E.AC_VI, 5), (E.AC_BE, 0),
                        (E.AC_BK, 2)):
            for _ in range(frames):
                sim.enqueue(name, ac, ap, 1000, tid=tid)
    r = sim.run()
    ordered = ("AC_VO", "AC_VI", "AC_BE", "AC_BK")
    names = list(ordered)
    delays = [r["per_ac"][k]["avg_delay_us"] / 1000.0 for k in ordered]
    ratio = delays[3] / max(delays[0], 1e-9)
    return names, delays, {k: r["per_ac"][k] for k in ordered}, ratio


def airtime_scan(sizes=(64, 128, 256, 512, 1024, 1500, 2304),
                 rate: float = 54.0) -> Tuple[List[int], List[float],
                                               List[float]]:
    """帧长 → 裸空口有效吞吐 与 含竞争的有效吞吐。"""
    sizes = list(sizes)
    bare = [phy.airtime_us(s, rate) for s in sizes]
    return (sizes,
            [s * 8 / (t * 1e-6) / 1e6 for s, t in zip(sizes, bare)],
            [phy.goodput_mbps(s, rate) for s in sizes])


# ================================================================ 绘图
def _mk_fig(w: float, h: float) -> Tuple[Figure, object]:
    fig = Figure(figsize=(w, h), dpi=100)
    ax = fig.add_subplot(111)
    fig.patch.set_facecolor(C_PAPER)
    ax.set_facecolor(C_PAPER)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    for s in ax.spines.values():
        s.set_color(C_AXIS)
    ax.tick_params(colors=C_TICK, labelsize=9)
    ax.grid(color=C_GRID, alpha=1.0, linewidth=0.8)
    ax.set_axisbelow(True)
    return fig, ax


def draw_dcf(parent: tk.Widget, data: Dict[str, List]) -> None:
    fig, ax = _mk_fig(6.4, 3.4)
    xs = data["xs"]
    ax.plot(xs, data["thru"], "o-", color=C_LINE, lw=2, label="吞吐量 (Mbps)")
    ax.plot(xs, data["coll"], "s--", color=C_BAD, lw=1.8,
            label="碰撞率 (%)")
    ax.plot(xs, [j * 100 for j in data["jain_short"]], "^-", color=C_OK,
            lw=1.8, label="短时 Jain ×100")
    ax.plot(xs, [j * 100 for j in data["jain_long"]], ":", color=C_GRAY,
            lw=1.8, label="长时 Jain ×100")
    imax = max(data["thru"])
    ax.annotate(f"峰值 {imax:.1f} Mbps\n@ {xs[data['thru'].index(imax)]} 站点",
                xy=(xs[data["thru"].index(imax)], imax),
                xytext=(4, -30), textcoords="offset points",
                color=C_LINE, fontsize=9,
                arrowprops=dict(arrowstyle="->", color=C_LINE))
    ax.set_xlabel("站点数", color=C_TICK)
    ax.set_ylabel("Mbps / %", color=C_TICK)
    ax.set_title("DCF：站点数对吞吐 / 碰撞率 / 公平性的影响",
                 color=C_TEXT, fontsize=11)
    ax.legend(facecolor=C_PAPER, edgecolor=C_AXIS, fontsize=8,
              labelcolor=C_TEXT)
    fig.tight_layout()
    _embed(parent, fig)


def draw_gain(parent: tk.Widget, rates: List[float], sizes: List[int],
              matrix: List[List[float]]) -> None:
    fig, ax = _mk_fig(6.4, 3.2)
    im = ax.imshow(matrix, cmap="RdYlGn", aspect="auto", vmin=0.6, vmax=2.0)
    ax.set_xticks(range(len(sizes)))
    ax.set_xticklabels([str(s) for s in sizes])
    ax.set_yticks(range(len(rates)))
    ax.set_yticklabels([f"{r:g} Mbps" for r in rates])
    for i in range(len(rates)):
        for j in range(len(sizes)):
            v = matrix[i][j]
            ax.text(j, i, f"{v:.2f}", ha="center", va="center",
                    fontsize=8,
                    color=C_TEXT if 0.8 < v < 1.7 else "#ffffff",
                    fontweight="bold")
    for i in range(len(rates)):
        ax.axhline(i - 0.5, color=C_PAPER, lw=1.2, alpha=0.9)
    for j in range(len(sizes)):
        ax.axvline(j - 0.5, color=C_PAPER, lw=1.2, alpha=0.9)
    cb = fig.colorbar(im, ax=ax, fraction=0.035, pad=0.03)
    cb.ax.tick_params(colors=C_TICK, labelsize=8)
    cb.outline.set_edgecolor(C_AXIS)
    ax.set_xlabel("帧长（字节）", color=C_TICK)
    ax.set_ylabel("物理层速率", color=C_TICK)
    ax.set_title("RTS/CTS 吞吐增益（8 个隐藏终端，>1 表示划算）",
                 color=C_TEXT, fontsize=11)
    fig.tight_layout()
    _embed(parent, fig)


def draw_edca(parent: tk.Widget, names: List[str], delays: List[float],
              per_ac: Dict[str, Dict[str, object]]) -> None:
    fig, ax = _mk_fig(6.4, 3.2)
    bars = ax.bar(names, delays, color=list(GRAYS[:len(names)]),
                  edgecolor=C_TEXT, linewidth=0.8, width=0.58)
    for bar, v, g in zip(bars, delays, GRAYS):
        ax.text(bar.get_x() + bar.get_width() / 2, v + max(delays) * 0.015,
                f"{v:.1f} ms", ha="center", color=C_TEXT, fontsize=9,
                fontweight="bold")
    ratio = delays[3] / max(delays[0], 1e-9)
    ax.annotate(f"VO / BK 时延比 = {ratio:.2f}×",
                xy=(0.5, 0.92), xycoords="axes fraction", ha="center",
                color=C_TEXT, fontsize=10, fontweight="bold")
    ax.set_ylabel("平均时延 (ms)", color=C_TICK)
    ax.set_title("EDCA：四类接入类别的时延分层（灰阶越深 = 优先级越高）",
                 color=C_TEXT, fontsize=11)
    ax.set_ylim(0, max(delays) * 1.18)
    fig.tight_layout()
    _embed(parent, fig)


def draw_airtime(parent: tk.Widget, sizes: List[int], bare: List[float],
                 good: List[float]) -> None:
    fig, ax = _mk_fig(6.4, 3.2)
    ax.plot(sizes, bare, "o-", color=C_LINE, lw=2, label="裸空口吞吐")
    ax.plot(sizes, good, "s--", color=C_ALT, lw=2,
            label="含退避/DIFS/SIFS/ACK")
    ax.axhline(54.0, color=C_BAD, lw=1.2, ls=":",
               label="物理层速率 54 Mbps")
    for s, b, g in zip(sizes, bare, good):
        if s in (64, 1500, 2304):
            ax.annotate(f"{g:.1f}", xy=(s, g), xytext=(2, -12),
                        textcoords="offset points", color=C_ALT,
                        fontsize=8)
    ax.set_xlabel("帧长（字节）", color=C_TICK)
    ax.set_ylabel("有效吞吐 (Mbps)", color=C_TICK)
    ax.set_title("54 Mbps 网卡为什么实测只有 30 Mbps：空口时间去哪了",
                 color=C_TEXT, fontsize=11)
    ax.legend(facecolor=C_PAPER, edgecolor=C_AXIS, fontsize=8,
              labelcolor=C_TEXT)
    fig.tight_layout()
    _embed(parent, fig)


def _embed(parent: tk.Widget, fig: Figure) -> None:
    for child in parent.winfo_children():
        child.destroy()
    canvas = FigureCanvasTkAgg(fig, master=parent)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True, padx=6, pady=6)


# ================================================================ 图表页
_PAGE_DEFS = [
    ("DCF 站点数扫描", "xs"),
    ("RTS/CTS 增益热力图", "matrix"),
    ("EDCA 四类时延", "edca"),
    ("空口时间分析", "airtime"),
]


class ChartsTab(tk.Frame):
    """四个实验图表的标签页，数据现场计算。"""

    def __init__(self, master: tk.Misc, jobs: "Jobs") -> None:
        self._jobs = jobs
        super().__init__(master, bg=T_BG)
        top = tk.Frame(self, bg=T_BG)
        top.pack(fill="x", padx=10, pady=(8, 4))
        self._btn = ttk.Button(top, text="⟳  现场计算全部图表",
                               command=self.recompute, style="Accent.TButton",
                               width=20)
        self._btn.pack(side="left")
        self._status = tk.Label(top, text="", bg=T_BG, fg=T_FG_MUTED,
                                font=("TkDefaultFont", 9))
        self._status.pack(side="left", padx=12)

        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._pages: Dict[str, tk.Frame] = {}
        for title, key in _PAGE_DEFS:
            page = tk.Frame(self._notebook, bg=C_PAPER)
            tk.Label(page, text="点左上角「现场计算全部图表」",
                     bg=C_PAPER, fg=T_FAINT,
                     font=("TkDefaultFont", 11)).pack(expand=True)
            self._notebook.add(page, text=f"  {title}  ")
            self._pages[key] = page

        self._data: Dict[str, object] = {}
        self._busy = False

    def _compute(self):
        """全部四张图的原始数据（耗时约 1-2 秒，放后台线程跑）。"""
        dcf = dcf_sweep()
        rates, sizes, matrix = rts_gain_matrix()
        names, delays, per_ac, vo_bk = edca_delays()
        asizes, bare, good = airtime_scan()
        return (dcf, (rates, sizes, matrix),
                (names, delays, per_ac, vo_bk), (asizes, bare, good))

    def recompute(self) -> None:
        if self._busy:
            return
        self._busy = True
        self._btn.config(state="disabled", text="计算中…")
        self._status.config(text="仿真计算中，请稍候…")
        self._jobs.submit(self._compute, on_ok=self._finish, tag="图表计算")

    def compute_sync(self) -> None:
        """同步算一遍并出图（截图工具用，不进主循环）。"""
        self._finish(self._compute())

    def _finish(self, payload) -> None:
        dcf, gain, edca, air = payload
        self._data = {"xs": dcf, "matrix": gain, "edca": edca, "airtime": air}
        draw_dcf(self._pages["xs"], dcf)
        draw_gain(self._pages["matrix"], *gain)
        edca_names, edca_delays, edca_detail, vo_bk = edca
        draw_edca(self._pages["edca"], edca_names, edca_delays, edca_detail)
        draw_airtime(self._pages["airtime"], *air)
        m = dcf["thru"]
        peak_n = dcf["xs"][m.index(max(m))]
        best = max(gain[2][0])
        self._status.config(
            text=f"吞吐峰值 {max(m):.1f} Mbps @ {peak_n} 站点 · "
                 f"VO/BK 时延比 {vo_bk:.2f}× · "
                 f"RTS 最大增益 {best:.2f}×")
        self._busy = False
        self._btn.config(state="normal", text="⟳  重新计算全部图表")
