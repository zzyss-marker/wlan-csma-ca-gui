"""空口舞台：把帧交换过程画成动画 + 一条空口时间轴。

这一层只做「回放与绘制」，不做任何仿真。所有数值都来自
:class:`gui.engine.Playback`：

* 帧的飞行轨迹 ← ``events``
* 站点的退避计数器 / CW / NAV 冻结时刻 ← ``trace``
  （仿真器每轮步进前后记的真实内部状态，不是重新推导的近似值）

舞台刻意保留了几种「真实抓包里看不见」的可视化元素：

* 碰撞时**双方的帧都画出来**（两个红点同时涌向接收端），接收端爆红，
  参与碰撞的站点描红边，画面里用一句大白话点名解释发生了什么
* NAV 冻结时站点罩上浅蓝底
* 每个站点的退避计数器实时跳动

画布底部是一条**空口时间轴**：数据 / RTS / CTS / ACK / 碰撞各占一行，
整个回放从左到右铺开，播放指针实时移动，点击任意位置即可跳转。
它回答的是舞台动画回答不了的问题——「这次碰撞发生在整个实验的哪里、
前后和哪些传输重叠」。碰撞块与数据块在时间上严格对齐，
「两个传输在时间上重叠 → 在接收端撞毁」不需要任何想象。

这些东西在真实网卡上连完整帧都收不到，只有在仿真里才画得出来——
它们正是这个项目用来「讲清楚协议」的部分。

图例直接画在画布内，不依赖外部说明：截图拿进报告也自带解释。
"""

from __future__ import annotations

import math
import tkinter as tk
import tkinter.font as tkfont
from typing import Callable, Dict, List, Optional, Set, Tuple

from . import theme as T
from .engine import EventView, Playback

KIND_LABEL = {
    "data": "数据帧", "rts": "RTS", "cts": "CTS", "ack": "ACK",
    "collision": "碰撞",
}
#: 同一时刻可能有多帧在飞，状态栏报告优先级最高的那个
_KIND_PRIO = {"collision": 5, "data": 4, "ack": 3, "cts": 2, "rts": 1}

#: 倍速预设：值为「每毫秒墙钟推进多少微秒仿真时间」
SPEEDS: Dict[str, int] = {
    "慢放 1×": 1500,
    "标准 5×": 8000,
    "快 25×": 40000,
    "极速 250×": 400000,
}

TICK_MS = 16                 # ~60 FPS
COLLISION_FLASH_US = 900     # 碰撞爆红的余晖时长
_LINK_LIMIT = 12             # 站点数超过这个值就不再画关系线，否则糊成一团

# ---------------------------------------------------------------- 空口时间轴
#: 底部时间轴条带高度（像素）。舞台地图只占用它上方的区域。
TIMELINE_H = 86
_TL_LEFT = 56.0              # 左侧行标签列宽
_TL_RIGHT = 14.0             # 右侧留白
_TL_HEAD = 20.0              # 条带内顶部标题行高度
_TL_AXIS = 16.0              # 条带内底部时间刻度高度
_N_ROWS = 5
#: 教科书式分层：数据 / RTS / CTS / ACK / 碰撞 各占一行，
#  碰撞块与数据块在时间上对得齐齐整整——「碰撞发生在哪一段传输里」一眼可见。
_TL_ROWS: Dict[str, int] = {"data": 0, "rts": 1, "cts": 2, "ack": 3,
                            "collision": 4}
_TL_ROW_LABEL = ("数据帧", "RTS", "CTS", "ACK", "碰撞")


def _nice_step(dur_us: float) -> float:
    """挑一个「好看」的时间刻度步长（目标：整条轴 6~9 个刻度）。"""
    for step in (25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000,
                 50000, 100000, 250000, 500000):
        if dur_us / step <= 9:
            return float(step)
    return 1000000.0


class StagePanel(tk.Frame):
    """空口舞台（画布）+ 回放控制条。"""

    def __init__(self, master: tk.Misc,
                 on_state: Optional[Callable[[float, Optional[EventView]],
                                             None]] = None,
                 on_progress: Optional[Callable[[float, float], None]] = None,
                 ) -> None:
        super().__init__(master, bg=T.PANEL)
        self._on_state = on_state
        self._on_progress = on_progress
        self._pb: Optional[Playback] = None
        self._t = 0.0
        self._speed = SPEEDS["标准 5×"]
        self._running = False
        self._after_id: Optional[int] = None
        self._focus: Optional[str] = None
        # 时间轴位图缓存：事件在回放中不变，只在换回放 / 改窗口尺寸时重画
        self._tl_img: Optional[tk.PhotoImage] = None
        self._tl_img_key: Optional[Tuple[float, int, int]] = None
        self._status_font = tkfont.Font(font=T.mono(8))

        # 所有 Tk 变量都在这里当实例属性创建，绝不放在类体里
        self._speed_var = tk.StringVar(value="标准 5×")
        self._clock_var = tk.StringVar(value="t = 0 us")
        self._hint_var = tk.StringVar(value="尚未运行：点右下「▶ 运行场景」开始")
        self._show_range = tk.BooleanVar(value=False)
        self._show_nav = tk.BooleanVar(value=True)
        self._show_backoff = tk.BooleanVar(value=True)
        self._show_links = tk.BooleanVar(value=True)
        self._show_labels = tk.BooleanVar(value=True)

        self._canvas = tk.Canvas(self, bg=T.STAGE["canvas"],
                                 highlightthickness=1,
                                 highlightbackground=T.BORDER,
                                 cursor="hand2")
        self._canvas.pack(side="top", fill="both", expand=True)

        self._build_bar()
        self._bind_canvas()

    # ================================================================ 控制条
    def _build_bar(self) -> None:
        bar = tk.Frame(self, bg=T.PANEL)
        bar.pack(side="bottom", fill="x")
        tk.Frame(bar, bg=T.BORDER, height=1).pack(fill="x")

        inner = tk.Frame(bar, bg=T.PANEL)
        inner.pack(fill="x", padx=10, pady=6)

        def sep() -> None:
            tk.Frame(inner, bg=T.BORDER, width=1).pack(
                side="left", fill="y", padx=9, pady=1)

        for text, cmd, style in (
                ("▶ 播放", self.play, "Accent.TButton"),
                ("⏸ 暂停", self.pause, "TButton"),
                ("⟲ 重置", self.reset, "TButton"),
                ("⏭ 下一个碰撞", self.jump_next_collision, "TButton")):
            from tkinter import ttk
            ttk.Button(inner, text=text, command=cmd, style=style,
                       width=12 if text != "⟲ 重置" else 8).pack(side="left")

        sep()
        tk.Label(inner, text="倍速", bg=T.PANEL, fg=T.FG_MUTED,
                 font=T.font(8)).pack(side="left", padx=(0, 4))
        from tkinter import ttk
        for name in SPEEDS:
            ttk.Radiobutton(inner, text=name, value=name,
                            variable=self._speed_var,
                            command=self._apply_speed
                            ).pack(side="left", padx=(0, 2))

        sep()
        for text, var in (("通信半径", self._show_range),
                          ("隐藏关系线", self._show_links),
                          ("NAV 冻结", self._show_nav),
                          ("退避计数器", self._show_backoff),
                          ("站点名", self._show_labels)):
            ttk.Checkbutton(inner, text=text, variable=var,
                            command=self.redraw).pack(side="left", padx=(0, 2))

        tk.Label(inner, textvariable=self._clock_var, bg=T.PANEL,
                 fg=T.ACCENT, font=T.mono(9, bold=True)
                 ).pack(side="right", padx=(8, 0))

    # ================================================================ 绑定
    def _bind_canvas(self) -> None:
        self._canvas.bind("<Button-1>", self._on_click)
        self._canvas.bind("<Configure>", self._on_configure)

    def _on_configure(self, _e: tk.Event) -> None:
        self._tl_img = None          # 尺寸变了，时间轴位图要重画
        self.redraw()

    def _on_click(self, event: tk.Event) -> None:
        """点时间轴跳到对应时刻；点站点跳到它的下一次传输。"""
        if self._pb is None:
            return
        h = float(self._canvas.winfo_height())
        if event.y >= h - TIMELINE_H:
            top = h - TIMELINE_H
            if event.y < top + _TL_HEAD:
                return               # 标题行不响应，避免误触
            x0 = _TL_LEFT
            x1 = float(self._canvas.winfo_width()) - _TL_RIGHT
            frac = min(1.0, max(0.0, (event.x - x0) / max(1.0, x1 - x0)))
            self.pause()
            self.goto(frac * self._pb.duration_us)
            return
        hit = self._nearest_station(event.x, event.y, 34)
        if hit is None:
            return
        for e in self._pb.events:
            if e.t_start >= self._t and (e.src_name == hit
                                         or e.dst_name == hit):
                self._t = e.t_start
                self.redraw()
                self._emit()
                return

    # ================================================================ 控制
    def set_playback(self, pb: Playback) -> None:
        self._pb = pb
        self._t = 0.0
        self._tl_img = None          # 换了回放，时间轴位图要重画
        self.pause()
        self.redraw()
        self._emit()

    def set_focus(self, name: Optional[str]) -> None:
        """圈出一个重点站点，帮零基础的人找到该看谁。"""
        if self._focus != name:
            self._focus = name
            self.redraw()

    def set_flags(self, *, links: Optional[bool] = None,
                  backoff: Optional[bool] = None,
                  nav: Optional[bool] = None,
                  range: Optional[bool] = None) -> None:
        """一次性开关若干图层（讲解脚本用它把画面调成想要的样子）。"""
        if links is not None:
            self._show_links.set(links)
        if backoff is not None:
            self._show_backoff.set(backoff)
        if nav is not None:
            self._show_nav.set(nav)
        if range is not None:
            self._show_range.set(range)
        self.redraw()

    def play(self) -> None:
        if self._pb is None or self._running:
            return
        if self._t >= self._pb.duration_us:
            self._t = 0.0
        self._running = True
        self._tick()

    def pause(self) -> None:
        self._running = False
        if self._after_id is not None:
            self.after_cancel(self._after_id)
            self._after_id = None

    @property
    def running(self) -> bool:
        return self._running

    def reset(self) -> None:
        self.pause()
        self._t = 0.0
        self.redraw()
        self._emit()

    def set_speed(self, name: str) -> None:
        if name in SPEEDS:
            self._speed = SPEEDS[name]
            self._speed_var.set(name)

    def _apply_speed(self) -> None:
        name = self._speed_var.get()
        if name in SPEEDS:
            self._speed = SPEEDS[name]

    def jump_next_collision(self) -> bool:
        """跳到下一次碰撞发生的瞬间。

        碰撞事件与对应那次数据帧传输**从同一时刻 t0 开始**（仿真器里
        两者由同一个分支写出），所以停在这一刻，画面里既有正在飞行的
        数据帧，也有刚亮起的红闪。不往回挪时间——回挪会让进度倒退，
        看起来像 bug。
        """
        if self._pb is None:
            return False
        for e in self._pb.collision_events():
            if e.t_start > self._t:
                self._t = e.t_start
                self.redraw()
                self._emit()
                return True
        return False

    def goto(self, t_us: float) -> None:
        """跳到任意时刻（讲解模式用）。"""
        if self._pb is None:
            return
        self._t = max(0.0, min(t_us, self._pb.duration_us))
        self.redraw()
        self._emit()

    @property
    def time_us(self) -> float:
        return self._t

    @property
    def playback(self) -> Optional[Playback]:
        return self._pb

    def _tick(self) -> None:
        if not self._running or self._pb is None:
            return
        self._t += self._speed * TICK_MS / 1000.0
        if self._t >= self._pb.duration_us:
            self._t = self._pb.duration_us
            self.redraw()
            self._emit()
            self.pause()
            return
        self.redraw()
        self._emit()
        self._after_id = self.after(TICK_MS, self._tick)

    def _emit(self) -> None:
        if self._pb is None:
            return
        if self._on_progress is not None:
            self._on_progress(self._t, self._pb.duration_us)
        if self._on_state is None:
            return
        cur: Optional[EventView] = None
        for e in self._pb.events:
            # 碰撞的「有效窗口」要和画布上爆红的窗口完全一致：
            # 画布会在碰撞结束后再保留 COLLISION_FLASH_US 的余晖，
            # 如果这里只用 [t_start, t_end)，就会出现「画布在爆红、
            # 右栏却写信道空闲」的矛盾——正是本项目承诺要避免的事。
            tail = COLLISION_FLASH_US if e.kind == "collision" else 0.0
            if e.t_start <= self._t < e.t_end + tail:
                if cur is None or _KIND_PRIO.get(e.kind, 0) > _KIND_PRIO.get(
                        cur.kind, 0):
                    cur = e
        self._on_state(self._t, cur)

    # ================================================================ 坐标
    def _bounds(self) -> Tuple[float, float, float, float]:
        if self._pb is None:
            return -50.0, 50.0, -50.0, 50.0
        xs = [s.x for s in self._pb.stations]
        ys = [s.y for s in self._pb.stations]
        m = self._pb.range_m * 0.35   # 留一点边距，不把圆塞满
        return min(xs) - m, max(xs) + m, min(ys) - m, max(ys) + m

    def _project(self, x: float, y: float) -> Tuple[float, float]:
        w = max(1.0, float(self._canvas.winfo_width()))
        # 底部留给空口时间轴，地图只投影到它上方的区域
        h = max(1.0, float(self._canvas.winfo_height()) - TIMELINE_H)
        x0, x1, y0, y1 = self._bounds()
        pad = 58.0
        scale = min((w - 2 * pad) / (x1 - x0), (h - 2 * pad) / (y1 - y0))
        cx = (x0 + x1) / 2
        cy = (y0 + y1) / 2
        return (x - cx) * scale + w / 2, cy - y * scale + h / 2

    def _scale(self) -> float:
        w = max(1.0, float(self._canvas.winfo_width()))
        h = max(1.0, float(self._canvas.winfo_height()) - TIMELINE_H)
        x0, x1, y0, y1 = self._bounds()
        pad = 58.0
        return min((w - 2 * pad) / (x1 - x0), (h - 2 * pad) / (y1 - y0))

    def _nearest_station(self, x: float, y: float,
                         tol_px: float) -> Optional[str]:
        if self._pb is None:
            return None
        best: Optional[str] = None
        best_d = tol_px
        for s in self._pb.stations:
            px, py = self._project(s.x, s.y)
            d = math.hypot(px - x, py - y)
            if d <= best_d:
                best, best_d = s.name, d
        return best

    # ================================================================ 绘制
    def redraw(self) -> None:
        c = self._canvas
        c.delete("all")
        if self._pb is None:
            w = max(1.0, float(c.winfo_width()))
            h = max(1.0, float(c.winfo_height()))
            c.create_text(w / 2, h / 2 - 12, text="空口舞台",
                          fill=T.STAGE["faint_text"], font=T.font(18, True))
            c.create_text(w / 2, h / 2 + 18,
                          text="点右下角「▶ 运行场景」开始一次仿真",
                          fill=T.STAGE["faint_text"], font=T.font(11))
            self._clock_var.set("t = 0 us")
            return
        t = self._t
        self._draw_grid()
        self._draw_range_circles()
        self._draw_links()
        self._draw_nav_zones(t)
        self._draw_frames(t)
        self._draw_collisions(t)
        self._draw_stations(t)
        self._draw_focus_ring()
        self._draw_hud(t)
        self._draw_timeline(t)

        self._clock_var.set(f"t = {t:,.0f} us   ({t / 1000:.2f} ms)")

    # ---- 画布内 HUD（解释 + 图例 + 时钟）
    def _draw_hud(self, t: float) -> None:
        self._draw_callout(t)
        self._draw_legend()

    def _draw_callout(self, t: float) -> None:
        """碰撞发生时，在画面里直接写一句人话解释。

        零基础的人看到红色爆闪不会自动联想到「两帧叠加」，
        所以解释必须写在画面上，而不是只写在说明文档里。
        参与者不写「另一站点」这种模糊说法——把同时发射的站点
        名字点出来，讲解的人就不用再猜「是哪两个在撞」。
        """
        if self._pb is None:
            return
        active = [e for e in self._pb.collision_events()
                  if e.t_start <= t < e.t_end + COLLISION_FLASH_US]
        if not active:
            return
        names: List[str] = []
        for e in sorted(active, key=lambda e: e.t_start):
            if e.src_name not in names:
                names.append(e.src_name)
        who = " 与 ".join(names[:2])
        if len(names) > 2:
            who += f" 等 {len(names)} 个站点"
        c = self._canvas
        text = (f"碰撞 · {who} 同时发射，两路信号在空中叠加\n"
                "接入点收到乱码，双方都收不到 ACK → 退避窗口翻倍后重传"
                "（对应底部时间轴的红色块）")
        x0, y0 = 12, 12
        x1, y1 = min(float(c.winfo_width()) - 12, 540), 66
        c.create_rectangle(x0, y0, x1, y1, fill=T.DANGER_SOFT,
                           outline=T.DANGER, width=2)
        c.create_text(x0 + 12, (y0 + y1) / 2, text=text, anchor="w",
                      justify="left", fill="#8c1a24", font=T.font(9))

    def _draw_legend(self) -> None:
        """图例：色块直接用真实颜色画小样，不靠纯文字。"""
        c = self._canvas
        w = float(c.winfo_width())
        h = float(c.winfo_height())
        y = h - TIMELINE_H - 12.0
        x = 14.0

        def line_sample(color: str, label: str, dashed: bool = False,
                        width: float = 1.6) -> None:
            nonlocal x
            if dashed:
                c.create_line(x, y, x + 20, y, fill=color, width=width,
                              dash=(4, 3))
            else:
                c.create_line(x, y, x + 20, y, fill=color, width=width)
            c.create_text(x + 25, y, text=label, anchor="w",
                          fill=T.STAGE["muted_text"], font=T.font(8))
            x += 25 + len(label) * 11 + 18

        def circle_sample(fill: str, edge: str, label: str,
                          out_w: int = 2) -> None:
            nonlocal x
            c.create_oval(x, y - 6, x + 13, y + 7, fill=fill, outline=edge,
                          width=out_w)
            c.create_text(x + 18, y, text=label, anchor="w",
                          fill=T.STAGE["muted_text"], font=T.font(8))
            x += 18 + len(label) * 11 + 18

        line_sample(T.STAGE["hidden"], "互相隐藏", dashed=True)
        line_sample(T.STAGE["visible"], "互相可闻")
        circle_sample(T.STAGE["nav_fill"], T.STAGE["nav_edge"], "NAV 冻结",
                      out_w=1)
        circle_sample("#ffffff", T.STAGE["tx_edge"], "正在发送")
        if self._pb is not None:
            m = self._pb.metrics
            if m.get("pair_hidden"):
                c.create_text(x, y, fill="#8c1a24", anchor="w",
                              text=f"隐藏对 {m['pair_hidden']}/{m['pair_total']}",
                              font=T.font(8, True))
        # 帧类型圆点靠右排一横行
        items = [
            ("data", "数据帧"), ("rts", "RTS"), ("cts", "CTS"),
            ("ack", "ACK"), ("collision", "碰撞"),
        ]
        total = sum(len(n) * 10 + 34 for _, n in items)
        x = max(14.0, w - total - 14)
        for kind, name in items:
            col = T.kind_color(kind)
            c.create_oval(x, y - 5, x + 10, y + 5, fill=col, outline=col)
            c.create_text(x + 15, y, text=name, anchor="w",
                          fill=T.STAGE["muted_text"], font=T.font(8))
            x += len(name) * 10 + 34

    # ---- 静态图层
    def _draw_grid(self) -> None:
        c = self._canvas
        w = float(c.winfo_width())
        h = float(c.winfo_height())
        for x in range(0, int(w), 40):
            c.create_line(x, 0, x, h, fill=T.STAGE["grid"])
        for y in range(0, int(h), 40):
            c.create_line(0, y, w, y, fill=T.STAGE["grid"])

    def _draw_range_circles(self) -> None:
        if not self._show_range.get() or self._pb is None:
            return
        c = self._canvas
        r_px = self._pb.range_m * self._scale()
        for s in self._pb.stations:
            px, py = self._project(s.x, s.y)
            col = (T.STAGE["range_ap"] if s.is_ap
                   else T.STAGE["range_sta"])
            c.create_oval(px - r_px, py - r_px, px + r_px, py + r_px,
                          outline=col, width=1.4,
                          dash=(6, 4) if not s.is_ap else None)

    def _collision_participants(self, t: float) -> Set[str]:
        """当前碰撞窗口（含余晖）里正在发射的站点名。"""
        if self._pb is None:
            return set()
        out: Set[str] = set()
        for e in self._pb.collision_events():
            if e.t_start <= t < e.t_end + COLLISION_FLASH_US:
                out.add(e.src_name)
        return out

    def _draw_links(self) -> None:
        """站点之间的「互相可闻 / 互相隐藏」关系线。

        8 个站点两两一共 28 对线，全画出来就是一张蛛网，谁都看不清。
        做了三层取舍：

        * 站点↔AP 的可闻线永远画（浅绿细线）——「人人都听得到 AP」
          是隐藏终端拓扑成立的前提，必须一眼可见；
        * 站点↔站点：小场景（≤5 站）全画保证教学完整；大场景只画
          **互相隐藏**的对（浅红虚线）——它们才是故事主线；
          「互相可闻」在大场景里是默认预期，画了只是噪声；
        * 碰撞发生的瞬间，参与者之间的隐藏对临时加粗成深红——
          把「因为互相听不到，所以会撞」这条因果链直接画在画面上。
        """
        if not self._show_links.get() or self._pb is None:
            return
        pb = self._pb
        stas = pb.stations[1:]
        if len(stas) > _LINK_LIMIT:
            return
        c = self._canvas
        ap = pb.stations[0]
        if ap is not None:
            ax, ay = self._project(ap.x, ap.y)
            for s in stas:
                bx, by = self._project(s.x, s.y)
                c.create_line(ax, ay, bx, by,
                              fill=T.STAGE["visible_soft"], width=1.0)
        coll = self._collision_participants(self._t)
        small = len(stas) <= 5
        for i in range(len(stas)):
            for j in range(i + 1, len(stas)):
                a, b = stas[i], stas[j]
                d = math.hypot(a.x - b.x, a.y - b.y)
                hidden = d > pb.range_m
                if not hidden and not small:
                    continue
                ax, ay = self._project(a.x, a.y)
                bx, by = self._project(b.x, b.y)
                if hidden:
                    hot = a.name in coll and b.name in coll
                    c.create_line(ax, ay, bx, by,
                                  fill=(T.STAGE["hidden"] if hot
                                        else T.STAGE["hidden_soft"]),
                                  width=2.4 if hot else 1.1, dash=(5, 4))
                else:
                    c.create_line(ax, ay, bx, by, fill=T.STAGE["visible"],
                                  width=1.1)

    def _draw_nav_zones(self, t: float) -> None:
        """NAV 冻结的站点罩一个浅蓝底，并标出「NAV」。"""
        if not self._show_nav.get() or self._pb is None:
            return
        c = self._canvas
        for name, _cw, _bo, defer, _pending, _qlen in self._pb.state_at(t):
            if defer <= t:
                continue
            sv = self._pb.by_name(name)
            if sv is None:
                continue
            px, py = self._project(sv.x, sv.y)
            r = 27.0 if sv.is_ap else 22.0
            c.create_oval(px - r, py - r, px + r, py + r,
                          fill=T.STAGE["nav_fill"],
                          outline=T.STAGE["nav_edge"], width=1.6)
            c.create_text(px, py - r - 8, text="NAV", fill=T.STAGE["nav_text"],
                          font=T.font(8, True))

    def _draw_frames(self, t: float) -> None:
        """画正在飞行的帧。

        碰撞事件也要画：每次碰撞在事件日志里是**每人一条**记录
        （赢家一条、每个闯入者各一条），把它们的轨迹都画出来，
        观众才能亲眼看到「两个红点同时涌向接入点」——
        只画一个红爆闪是讲不清碰撞的成因的。
        """
        if self._pb is None:
            return
        c = self._canvas
        pb = self._pb
        for e in pb.events:
            if not (e.t_start <= t < e.t_end):
                continue
            src = pb.by_name(e.src_name)
            dst = pb.by_name(e.dst_name)
            if src is None or dst is None:
                continue
            ax, ay = self._project(src.x, src.y)
            bx, by = self._project(dst.x, dst.y)
            p = (t - e.t_start) / max(1.0, e.duration_us)
            hx, hy = ax + (bx - ax) * p, ay + (by - ay) * p
            if e.kind == "collision":
                col, lw, size = T.DANGER, 3.0, 7
                lbl = "被撞毁"
            else:
                col = T.kind_color(e.kind)
                lw = 3.4 if e.kind == "data" else 2.2
                size = 8 if e.kind == "data" else 5
                lbl = KIND_LABEL.get(e.kind, e.kind)
            if e.retry:
                lbl += " 重传"
            c.create_line(ax, ay, hx, hy, fill=col, width=lw)
            c.create_oval(hx - size, hy - size, hx + size, hy + size,
                          fill=col, outline=T.PANEL, width=1.4)
            c.create_text(hx, hy - 15, text=lbl, fill=col,
                          font=T.font(8, True))

    def _draw_collisions(self, t: float) -> None:
        """碰撞事件在接收端画红色爆闪。"""
        if self._pb is None:
            return
        c = self._canvas
        for e in self._pb.collision_events():
            lo = e.t_start
            hi = e.t_end + COLLISION_FLASH_US
            if not (lo <= t < hi):
                continue
            fade = 1.0 if t <= e.t_end else (hi - t) / COLLISION_FLASH_US
            dst = self._pb.by_name(e.dst_name)
            if dst is None:
                continue
            px, py = self._project(dst.x, dst.y)
            r = 18.0 + 24.0 * fade
            c.create_oval(px - r, py - r, px + r, py + r,
                          outline=T.DANGER, width=2.6)
            r2 = r * 0.56
            c.create_oval(px - r2, py - r2, px + r2, py + r2,
                          outline="#e8898f", width=1.6)
            c.create_text(px, py - r - 11, text="碰撞",
                          fill=T.DANGER, font=T.font(9, True))

    def _draw_focus_ring(self) -> None:
        """讲解模式的「重点站点」虚线圈。"""
        if not self._focus or self._pb is None:
            return
        sv = self._pb.by_name(self._focus)
        if sv is None:
            return
        c = self._canvas
        px, py = self._project(sv.x, sv.y)
        r = 26.0
        c.create_oval(px - r, py - r, px + r, py + r, outline=T.ACCENT,
                      width=2, dash=(5, 4))
        c.create_text(px, py - r - 12, text="看这里", fill=T.ACCENT,
                      font=T.font(9, True))

    def _draw_stations(self, t: float) -> None:
        if self._pb is None:
            return
        c = self._canvas
        pb = self._pb
        tx_names = {e.src_name for e in pb.events if e.t_start <= t < e.t_end}
        coll_names = self._collision_participants(t)

        for name, cw, backoff, defer, _pending, _qlen in pb.state_at(t):
            sv = pb.by_name(name)
            if sv is None:
                continue
            px, py = self._project(sv.x, sv.y)
            is_tx = name in tx_names
            is_coll = name in coll_names
            is_nav = defer > t
            r = 16.0 if sv.is_ap else 11.0

            fill = T.STAGE["ap_fill"] if sv.is_ap else T.STAGE["sta_fill"]
            if sv.is_ap:
                outline = T.STAGE["ap_edge"]
            elif is_coll:
                outline = T.DANGER        # 碰撞参与者：红边，和爆闪同色系
            elif is_tx:
                outline = T.STAGE["tx_edge"]
            elif is_nav:
                outline = T.STAGE["nav_edge"]
            else:
                outline = T.STAGE["sta_edge"]
            c.create_oval(px - r, py - r, px + r, py + r, fill=fill,
                          outline=outline,
                          width=3 if (is_tx or is_coll) else 2)
            c.create_text(px, py, text="AP" if sv.is_ap else name[-1],
                          fill=(T.STAGE["ap_text"] if sv.is_ap
                                else T.STAGE["sta_text"]),
                          font=T.font(9 if sv.is_ap else 8, True))
            if self._show_labels.get() or sv.is_ap:
                c.create_text(px, py + r + 9,
                              text="接入点" if sv.is_ap else name,
                              fill=T.STAGE["muted_text"], font=T.font(8))

            if sv.is_ap or not self._show_backoff.get():
                continue
            # 只显示「有意义」的状态，不显示空值：
            # · CW 只在碰撞后增长时才出现（默认 15 不显示）
            # · 正在发送时退避计数器本来就不存在，写「发送中」而不是「—」
            # · 倒计时期间显示真实数值，它会逐时隙递减
            bits: List[str] = []
            if cw > 15:
                bits.append(f"CW={cw}")
            if is_tx:
                bits.append("发送中")
            elif backoff is not None:
                bits.append(f"退避={backoff}")
            if is_nav:
                bits.append("冻结")
            if not bits:
                continue
            if is_coll:
                col = T.DANGER
            elif is_tx:
                col = T.STAGE["tx_text"]
            elif is_nav:
                col = T.STAGE["nav_text"]
            else:
                col = T.STAGE["faint_text"]
            # 状态文字加一层白底衬，压在关系线上也读得清
            txt = " · ".join(bits)
            ty = py + r + 24
            tw = self._status_font.measure(txt)
            c.create_rectangle(px - tw / 2 - 3, ty - 8, px + tw / 2 + 3,
                               ty + 8, fill=T.PANEL, outline="")
            c.create_text(px, ty, text=txt, fill=col, font=T.mono(8))

    # ================================================================ 空口时间轴
    def _render_timeline_image(self) -> None:
        """把整条时间轴预渲染成一张位图。

        一次回放有几千个空口事件（默认场景 2878 个），逐帧画几千个
        矩形会把 Tk 拖垮；而事件在回放过程中不会变化，所以只在
        「换了回放 / 窗口尺寸变了」时用 ``PhotoImage.put`` 画一次位图，
        每帧只需要叠画播放指针等少数几个动态元素。
        """
        w = max(1, int(self._canvas.winfo_width()))
        img = tk.PhotoImage(master=self._canvas, width=w, height=TIMELINE_H)
        img.put(T.STAGE["tl_bg"], to=(0, 0, w, TIMELINE_H))
        if self._pb is not None:
            pb = self._pb
            dur = max(1.0, pb.duration_us)
            # 画布还没完成布局时 winfo_width 可能是 1，钳住右边界避免负坐标
            x0 = int(_TL_LEFT)
            x1 = max(x0 + 1, w - int(_TL_RIGHT))
            row_h = (TIMELINE_H - _TL_HEAD - _TL_AXIS) / _N_ROWS
            # 行基线（空闲时段就是基线本身）
            for i in range(_N_ROWS):
                cy = int(_TL_HEAD + row_h * (i + 0.5))
                img.put(T.STAGE["tl_row"], to=(x0, cy, x1, cy + 1))
            # 时间刻度竖线
            step = _nice_step(dur)
            tu = step
            while tu < dur:
                px = int(x0 + (x1 - x0) * tu / dur)
                img.put(T.STAGE["tl_tick"],
                        to=(px, int(_TL_HEAD), px + 1,
                            int(TIMELINE_H - _TL_AXIS)))
                tu += step
            # 事件块。碰撞块浅红填充 + 深红上下沿；重传的数据帧
            # 顶部压一条深蓝刻痕，让「重传」在时间轴上也能被指出来。
            for e in pb.events:
                row = _TL_ROWS.get(e.kind)
                if row is None:
                    continue
                cy = int(_TL_HEAD + row_h * (row + 0.5))
                bh = 4
                bx0 = int(x0 + (x1 - x0) * (e.t_start / dur))
                bx1 = int(x0 + (x1 - x0) * (e.t_end / dur))
                if bx1 <= bx0:
                    bx1 = bx0 + 1
                bx0 = max(bx0, x0)
                bx1 = min(bx1, x1)
                if e.kind == "collision":
                    img.put(T.STAGE["tl_collision"],
                            to=(bx0, cy - bh, bx1, cy + bh))
                    img.put(T.STAGE["tl_collision_edge"],
                            to=(bx0, cy - bh, bx1, cy - bh + 1))
                    img.put(T.STAGE["tl_collision_edge"],
                            to=(bx0, cy + bh - 1, bx1, cy + bh))
                else:
                    img.put(T.kind_color(e.kind),
                            to=(bx0, cy - bh, bx1, cy + bh))
                    if e.kind == "data" and e.retry:
                        img.put(T.STAGE["tl_retry"],
                                to=(bx0, cy - bh, bx1, cy - bh + 1))
        self._tl_img = img      # PhotoImage 必须持有引用，否则会被回收
        self._tl_img_key = (round(self._pb.duration_us, 1) if self._pb else 0.0,
                            len(self._pb.events) if self._pb else 0, w)

    def _draw_timeline(self, t: float) -> None:
        if self._pb is None:
            return
        c = self._canvas
        w = float(c.winfo_width())
        h = float(c.winfo_height())
        key = (round(self._pb.duration_us, 1), len(self._pb.events), int(w))
        if self._tl_img is None or self._tl_img_key != key:
            self._render_timeline_image()
        top = h - TIMELINE_H
        c.create_image(0, top, anchor="nw", image=self._tl_img)
        x0, x1 = _TL_LEFT, w - _TL_RIGHT
        dur = max(1.0, self._pb.duration_us)
        row_h = (TIMELINE_H - _TL_HEAD - _TL_AXIS) / _N_ROWS
        # 标题与行标签（文字进不了位图，每帧画，数量固定只有 8 个）
        c.create_text(10, top + 9, text="空口时间轴", anchor="w",
                      fill=T.FG_MUTED, font=T.font(8, True))
        c.create_text(x1, top + 9, text="点击任意位置跳转 · 深蓝刻痕=重传",
                      anchor="e", fill=T.STAGE["faint_text"], font=T.font(7))
        for i, label in enumerate(_TL_ROW_LABEL):
            c.create_text(_TL_LEFT - 8, top + _TL_HEAD + row_h * (i + 0.5),
                          text=label, anchor="e", fill=T.FG_MUTED,
                          font=T.font(7))
        # 底部时间刻度数字
        step = _nice_step(dur)
        tu = step
        while tu < dur:
            px = x0 + (x1 - x0) * tu / dur
            c.create_text(px, h - 8, text=f"{tu / 1000:g} ms",
                          fill=T.FG_FAINT, font=T.font(7))
            tu += step
        # 播放指针 + 当前时刻
        px = x0 + (x1 - x0) * min(t, dur) / dur
        c.create_line(px, top + _TL_HEAD - 2, px, h - _TL_AXIS + 2,
                      fill=T.FG, width=1)
        if px > x0 + 64:
            c.create_text(px + 4, top + 9, text=f"{t / 1000:.2f} ms",
                          anchor="w", fill=T.FG, font=T.mono(7, True))
        # 正在发生的碰撞：在时间轴上把对应红块描一遍深红边框，
        # 让「画面在爆红」和「时间轴在指红块」严格同步
        cy = top + _TL_HEAD + row_h * (_TL_ROWS["collision"] + 0.5)
        for e in self._pb.collision_events():
            if e.t_start <= t < e.t_end + COLLISION_FLASH_US:
                bx0 = x0 + (x1 - x0) * (e.t_start / dur)
                bx1 = x0 + (x1 - x0) * (e.t_end / dur)
                c.create_rectangle(bx0, cy - 5.5, max(bx1, bx0 + 2), cy + 5.5,
                                   outline=T.STAGE["tl_collision_edge"],
                                   width=1.2)
