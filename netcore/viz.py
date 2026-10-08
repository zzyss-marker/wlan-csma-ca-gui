"""可视化工具：统一中文字体、统一风格、统一输出。

所有项目共用这里的绘图入口，保证 20 个项目的图表风格一致、中文不乱码。
输出统一落在 ``<项目>/out/`` 下，方便直接贴进答辩 PPT。
"""

from __future__ import annotations

import os

os.environ.setdefault("MPLBACKEND", "Agg")

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402

_CJK_CANDIDATES = [
    "PingFang SC", "Heiti TC", "Hiragino Sans GB", "Arial Unicode MS",
    "Songti SC", "STHeiti", "Noto Sans CJK SC", "Source Han Sans SC",
    "Microsoft YaHei", "SimHei", "WenQuanYi Micro Hei",
]

_font_name: str | None = None


def setup_style(dpi: int = 130) -> str | None:
    """初始化绘图风格与中文字体，返回实际选中的字体名。"""
    global _font_name
    if _font_name is None:
        available = {f.name for f in font_manager.fontManager.ttflist}
        for cand in _CJK_CANDIDATES:
            if cand in available:
                _font_name = cand
                break
        else:
            _font_name = ""
    if _font_name:
        plt.rcParams["font.sans-serif"] = [_font_name] + list(plt.rcParams["font.sans-serif"])
    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams["figure.dpi"] = dpi
    plt.rcParams["savefig.bbox"] = "tight"
    plt.rcParams["axes.grid"] = True
    plt.rcParams["grid.alpha"] = 0.3
    plt.rcParams["axes.axisbelow"] = True
    return _font_name or None


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def save(fig, path: str) -> str:
    """保存图像并关闭，返回绝对路径。

    显式给 ``pad_inches`` 留白：只靠 ``savefig.bbox="tight"`` 时，
    中文标题在某些 matplotlib 版本上会被裁掉顶部一两行像素。
    """
    ensure_dir(os.path.dirname(os.path.abspath(path)))
    fig.savefig(path, bbox_inches="tight", pad_inches=0.28)
    plt.close(fig)
    return os.path.abspath(path)


# ------------------------------------------------------------------ 常用图
def line_plot(series: dict, path: str, title: str = "", xlabel: str = "",
              ylabel: str = "", x=None, figsize=(9, 4.5), logy: bool = False):
    """多序列折线图。``series = {"名称": [y...]}``。"""
    setup_style()
    fig, ax = plt.subplots(figsize=figsize)
    for name, ys in series.items():
        xs = x if x is not None else list(range(len(ys)))
        ax.plot(xs, ys, label=name, linewidth=1.6)
    if logy:
        ax.set_yscale("log")
    ax.set_title(title, pad=12)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    if len(series) > 1:
        ax.legend(loc="best", fontsize=9)
    return save(fig, path)


def bar_plot(labels, values, path: str, title: str = "", ylabel: str = "",
             figsize=(8, 4.2), annotate: bool = True, color=None):
    setup_style()
    fig, ax = plt.subplots(figsize=figsize)
    bars = ax.bar(labels, values, color=color)
    if annotate:
        for rect, v in zip(bars, values):
            ax.annotate(f"{v:.3g}", (rect.get_x() + rect.get_width() / 2, rect.get_height()),
                        ha="center", va="bottom", fontsize=8)
    ax.set_title(title, pad=12)
    ax.set_ylabel(ylabel)
    plt.setp(ax.get_xticklabels(), rotation=20, ha="right")
    return save(fig, path)


def heatmap(matrix, path: str, xticks=None, yticks=None, title: str = "",
            xlabel: str = "", ylabel: str = "", cmap: str = "viridis",
            figsize=(7.5, 5.5)):
    setup_style()
    fig, ax = plt.subplots(figsize=figsize)
    im = ax.imshow(matrix, cmap=cmap, aspect="auto")
    ax.set_xticks(range(len(xticks or [])))
    ax.set_xticklabels(xticks or [], rotation=30, ha="right", fontsize=8)
    ax.set_yticks(range(len(yticks or [])))
    ax.set_yticklabels(yticks or [], fontsize=8)
    ax.set_title(title, pad=12)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    fig.colorbar(im, ax=ax)
    return save(fig, path)


def scatter_plot(points, path: str, title: str = "", xlabel: str = "",
                 ylabel: str = "", labels=None, figsize=(8, 5)):
    """``points = [(x, y), ...]``。"""
    setup_style()
    fig, ax = plt.subplots(figsize=figsize)
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    ax.scatter(xs, ys, s=28, alpha=0.8)
    if labels:
        for (x, y), lab in zip(points, labels):
            ax.annotate(lab, (x, y), fontsize=8, xytext=(4, 4), textcoords="offset points")
    ax.set_title(title, pad=12)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    return save(fig, path)
