"""回放引擎：跑一次仿真，产出界面需要的「可播放模型」。

界面不直接碰仿真器。这里把仿真的结果整理成一份只读快照
:class:`Playback`，包含四样东西：

* ``stations``  —— 站点及其物理坐标（画舞台要用）
* ``events``    —— 空口事件日志（画帧的飞行轨迹要用）
* ``trace``     —— 每个站点在每轮仿真步进前后的**真实内部状态**
                   （CW、退避计数器、NAV 冻结时刻、队列长度）
* ``metrics``   —— 吞吐 / 碰撞率 / 短时公平性等统计

``trace`` 是靠 :class:`TracedSimulator` 拿到的——它没有改动
``wlanlab.dcf`` 的任何一行代码，只是在每轮 ``_step()`` 前后各记一份
快照。界面显示的退避计数器和 NAV 冻结状态因此**和仿真器内部完全一致**，
不是重新推导的近似值。
"""

from __future__ import annotations

import bisect
import math
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT = os.path.abspath(os.path.join(_HERE, ".."))
_REPO = os.path.abspath(os.path.join(_PROJECT, "..", ".."))
for _p in (_PROJECT, _REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from wlanlab import dcf as D  # noqa: E402


# ---------------------------------------------------------------- 视图模型
@dataclass
class StationView:
    """一个站点在界面里的静态信息。"""

    name: str
    mac: str
    x: float
    y: float
    is_ap: bool = False


@dataclass
class EventView:
    """一次空口事件（帧传输或碰撞）。"""

    index: int
    t_start: float
    t_end: float
    kind: str          # data / rts / cts / ack / collision
    src_name: str
    dst_name: str
    length: int
    rate_mbps: float
    retry: bool
    tid: int
    ok: bool           # False 表示这次传输被碰撞毁掉了

    @property
    def duration_us(self) -> float:
        return self.t_end - self.t_start


@dataclass
class Playback:
    """一次仿真的完整回放模型（界面唯一的数据来源）。"""

    topology: str
    seed: int
    stations: List[StationView]
    events: List[EventView]
    trace: List[Tuple[float, List[Tuple[float, int, Optional[int], float,
                                      bool, int]]]]
    metrics: Dict[str, object]
    range_m: float
    rate_mbps: float
    frame_len: int
    duration_us: float
    n_frames: int
    use_rts: bool = False
    params: Dict[str, object] = field(default_factory=dict)
    #: trace 时间轴的缓存（二分查找用），不参与相等比较
    _trace_times: Optional[List[float]] = field(default=None, repr=False,
                                                compare=False)

    # ---------------------------------------------------------- 查询
    def by_name(self, name: str) -> Optional[StationView]:
        for s in self.stations:
            if s.name == name:
                return s
        return None

    def collision_events(self) -> List[EventView]:
        return [e for e in self.events if e.kind == "collision"]

    def data_events(self) -> List[EventView]:
        return [e for e in self.events if e.kind == "data"]

    def state_at(self, t_us: float) -> List[Tuple[float, int, Optional[int],
                                                  float, bool, int]]:
        """取时刻 ``t_us`` 各站点的真实内部状态。

        返回 ``[(name, cw, backoff, defer_until, pending, qlen), ...]``。

        用二分查找定位最近一次快照。轨迹改成时隙级以后条数到了万级，
        而重绘一帧要查 5 次、每秒 60 帧——线性扫描会明显拖慢动画。
        """
        if not self.trace:
            return []
        if self._trace_times is None:
            self._trace_times = [t for t, _ in self.trace]
        i = bisect.bisect_right(self._trace_times, t_us) - 1
        if i < 0:
            i = 0
        return self.trace[i][1]


# ---------------------------------------------------------------- 带轨迹的仿真器
class TracedSimulator(D.DcfSimulator):
    """带内部状态轨迹的仿真器。

    只重写 ``_active()``，不碰 ``wlanlab.dcf`` 的任何一行代码。

    为什么挂在 ``_active()`` 上：``DcfSimulator._step()`` 里的退避倒计时是
    一个**逐时隙**循环 ——::

        while True:
            for s in self._active():     # ← 每个时隙调用一次
                ... s.backoff -= 1 ...
            if ready: break
            self.now += self.slot_us     # 9 us

    ``_active()`` 恰好在这个循环里**每 9 微秒被调用一次**，而且是在该时隙
    递减**之前**调用。所以只要在 ``_active()`` 里记一份快照，就能拿到
    时隙级的真实退避计数器轨迹，界面上的计数器才是「跳动的」而不是
    「跳变的」。挂在这里的另一个好处是它天然不改变仿真语义。
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.trace: List[Tuple[float, List[Tuple[float, int, Optional[int],
                                                float, bool, int]]]] = []

    def _snapshot(self) -> None:
        self.trace.append((
            self.now,
            [(s.name, s.cw, s.backoff, s.defer_until, s.pending, len(s.queue))
             for s in self.stations],
        ))

    def _active(self) -> List[object]:
        self._snapshot()
        return super()._active()  # type: ignore[return-value]

    def _step(self) -> None:
        super()._step()
        self._snapshot()      # 一次传输结束后的收尾状态


# ---------------------------------------------------------------- 拓扑构造
def build_compact_circle(n_stations: int, radius_m: float = 40.0,
                         seed: int = 42, **kwargs: object
                         ) -> Tuple[TracedSimulator, List[StationView]]:
    """紧凑圆形拓扑：所有站点互相听得到，用于 DCF 站点数扫描。

    半径 40m、相邻间距 ``2·40·sin(π/n)``：
    n=16 时 15.7m，n=4 时 56.6m——都远小于 100m 通信半径，
    所以**任意两个站点互相可闻、也都听得到 AP**。
    这样「碰撞」就纯粹来自 DCF 的退避竞争，与隐藏终端无关。
    """
    sim = TracedSimulator(seed=seed, **kwargs)  # type: ignore[arg-type]
    ap = sim.add_station("AP", "02:00:00:00:00:ff", x=0.0, y=0.0, is_ap=True)
    views = [StationView(ap.name, ap.mac, ap.x, ap.y, ap.is_ap)]
    for i in range(n_stations):
        ang = 2 * math.pi * i / n_stations
        st = sim.add_station(
            f"STA-{i + 1}", f"02:00:00:00:00:{i + 1:02x}",
            x=radius_m * math.cos(ang), y=radius_m * math.sin(ang))
        views.append(StationView(st.name, st.mac, st.x, st.y, st.is_ap))
    return sim, views


# ---------------------------------------------------------------- 场景运行
def run_hidden_ring(n_stations: int = 8, frame_len: int = 1500,
                    frames_per_station: int = 150, rate_mbps: float = 54.0,
                    use_rts: bool = False, radius_m: float = 80.0,
                    range_m: float = 100.0, seed: int = 11,
                    ) -> Playback:
    """跑隐藏终端环形拓扑，产出回放模型。"""
    sim, views = _make_ring_view(
        n_stations, radius_m, range_m, rate_mbps, seed,
        use_rts=use_rts, rts_threshold=0 if use_rts else 500)
    ap_mac = sim.stations[0].mac
    for s in sim.stations[1:]:
        for _ in range(frames_per_station):
            sim.enqueue(s, ap_mac, frame_len)
    sim.run()
    return _to_playback(
        sim, views, "环形隐藏终端", n_stations=n_stations, frame_len=frame_len,
        n_frames=frames_per_station, rate_mbps=rate_mbps, range_m=range_m,
        topology_desc=describe_ring(n_stations, radius_m, range_m, views))


def _make_ring_view(n_stations: int, radius_m: float, range_m: float,
                    rate_mbps: float, seed: int,
                    **kwargs: object) -> Tuple[TracedSimulator,
                                                List[StationView]]:
    sim = TracedSimulator(seed=seed, range_m=range_m, rate_mbps=rate_mbps,
                          **kwargs)  # type: ignore[arg-type]
    ap = sim.add_station("AP", "02:00:00:00:00:ff", x=0.0, y=0.0, is_ap=True)
    views = [StationView(ap.name, ap.mac, ap.x, ap.y, ap.is_ap)]
    for i in range(n_stations):
        ang = 2 * math.pi * i / n_stations
        st = sim.add_station(
            f"STA-{i + 1}", f"02:00:00:00:00:{i + 1:02x}",
            x=radius_m * math.cos(ang), y=radius_m * math.sin(ang))
        views.append(StationView(st.name, st.mac, st.x, st.y, st.is_ap))
    return sim, views


def run_dcf_sweep(n_stations: int = 8, frame_len: int = 1500,
                  frames_per_station: int = 40, rate_mbps: float = 54.0,
                  seed: int = 42) -> Playback:
    """跑紧凑圆形 DCF 拓扑，用于观察站点数对吞吐与公平性的影响。"""
    sim, views = build_compact_circle(n_stations, seed=seed,
                                      rate_mbps=rate_mbps)
    ap_mac = sim.stations[0].mac
    for s in sim.stations[1:]:
        for _ in range(frames_per_station):
            sim.enqueue(s, ap_mac, frame_len)
    sim.run()
    total, hidden = connectivity(views, 100.0)
    return _to_playback(
        sim, views, "DCF 站点数扫描", n_stations=n_stations, frame_len=frame_len,
        n_frames=frames_per_station, rate_mbps=rate_mbps, range_m=100.0,
        topology_desc=f"{n_stations} 站点紧凑环形，站点半径 40m，"
                      f"最远两点 80m < 通信半径 100m，"
                      f"{total} 对站点中隐藏对数 = {hidden}（无隐藏终端）")


def _to_playback(sim: TracedSimulator, views: Sequence[StationView],
                 topology: str, *, n_stations: int, frame_len: int,
                 n_frames: int, rate_mbps: float, range_m: float,
                 topology_desc: str) -> Playback:
    name_of = {s.mac: s.name for s in sim.stations}
    # 仿真器产出的事件不保证按时间有序（同一次 _step 里可能先后追加两个
    # 起点相同的事件），而界面要「跳到下一个碰撞」、状态栏要取「当前时刻
    # 正在飞的那一帧」——两者都依赖时间有序。这里统一排一次。
    ordered = sorted(sim.events, key=lambda e: (e.t_start, e.t_end))
    events: List[EventView] = []
    for i, e in enumerate(ordered):
        events.append(EventView(
            index=i, t_start=e.t_start, t_end=e.t_end, kind=e.kind,
            src_name=name_of.get(e.src, e.src), dst_name=name_of.get(e.dst, e.dst),
            length=e.length, rate_mbps=e.rate_mbps, retry=e.retry,
            tid=e.tid, ok=e.ok))
    metrics = dict(sim.result())
    metrics["topology_desc"] = topology_desc
    metrics["trace_points"] = len(sim.trace)
    pair_total, pair_hidden = connectivity(views, range_m)
    metrics["pair_total"] = pair_total
    metrics["pair_hidden"] = pair_hidden
    metrics["hidden_ratio"] = (round(pair_hidden / pair_total, 3)
                               if pair_total else 0.0)
    return Playback(
        topology=topology, seed=sim.seed, stations=list(views), events=events,
        trace=sim.trace, metrics=metrics, range_m=range_m,
        rate_mbps=rate_mbps, frame_len=frame_len,
        duration_us=sim.now, n_frames=n_frames, use_rts=sim.use_rts,
        params={"station_count": n_stations, "frame_len": frame_len,
                "frames_per_station": n_frames, "rate_mbps": rate_mbps})


def connectivity(views: Sequence[StationView], range_m: float
                 ) -> Tuple[int, int]:
    """统计站点之间的「可闻对」与「隐藏对」。

    返回 ``(总对数, 互相隐藏的对数)``，只统计非 AP 站点。
    这个数字很重要：环形布局里「隐藏」不是全有或全无——
    n=4、r=80 时 6/6 对全部隐藏，n=8、r=80 时只有 20/28 对隐藏
    （相邻的 8 对能互相听到）。把拓扑说成「全部互相隐藏」在 n≥6 时是错的。
    """
    stas = [s for s in views if not s.is_ap]
    total = hidden = 0
    for i in range(len(stas)):
        for j in range(i + 1, len(stas)):
            total += 1
            a, b = stas[i], stas[j]
            if math.hypot(a.x - b.x, a.y - b.y) > range_m:
                hidden += 1
    return total, hidden


def describe_ring(n: int, radius_m: float, range_m: float,
                  views: Sequence[StationView]) -> str:
    """给环形布局写一句**准确**的描述。"""
    spacing = 2 * radius_m * math.sin(math.pi / n)
    total, hidden = connectivity(views, range_m)
    adj = "相邻站点互相隐藏" if spacing > range_m else "相邻站点能互相听到"
    return (f"{n} 站点环形布局，站点半径 {radius_m:.0f}m，"
            f"相邻间距 {spacing:.0f}m；"
            f"{total} 对站点中有 {hidden} 对互相隐藏（{hidden / max(total, 1):.0%}），"
            f"{adj}")


# ---------------------------------------------------------------- 演示配置
#: 界面默认场景。
#: 每站 150 帧、seed=11 是刻意选的：它精确复现报告正文里那张环形拓扑表
#: （无 RTS/CTS 丢包 30、短时 Jain 0.525 → 启用 RTS/CTS 丢包 0、Jain 0.840），
#: 而且这组结论在 seed 7/11/13/21/42 五个种子上方向都一致，不是挑种子挑出来的。
DEFAULT_CONFIG = dict(n_stations=8, frame_len=1500, frames_per_station=150,
                      rate_mbps=54.0, use_rts=False, seed=11)


def run_default(use_rts: bool = False, n_stations: int = 8) -> Playback:
    """跑界面默认场景。"""
    return run_hidden_ring(n_stations=n_stations, use_rts=use_rts,
                           **{k: v for k, v in DEFAULT_CONFIG.items()
                              if k not in ("n_stations", "use_rts")})


# ================================================================ 统一入口
TOPOLOGY_DESC = {
    "line3": "A 与 C 相距 160m > 通信半径 100m，互相隐藏；AP 在 x=80m 处",
    "compact": "站点排在小圆上，任意两点都互相可闻（无隐藏终端）",
    "ring": "站点环形布局，相邻站点互相隐藏，但都听得到 AP",
}


def run_cfg(config: Dict[str, object]) -> Playback:
    """按配置跑一个场景，返回回放模型。

    ``config`` 的字段与界面右栏参数一一对应，这样界面上调的任何旋钮
    都真的会改变仿真结果。
    """
    topo = str(config["topology"])
    n = int(config["n_stations"])
    frames = int(config["frames_per_station"])
    size = int(config["frame_len"])
    rate = float(config["rate_mbps"])
    rng_m = float(config["range_m"])
    seed = int(config["seed"])
    use_rts = bool(config["use_rts"])
    radius = float(config.get("radius_m", 80.0))

    if topo == "line3":
        return run_line3(frame_len=size, frames_per_station=frames,
                         rate_mbps=rate, use_rts=use_rts,
                         rts_threshold=0 if use_rts else 500,
                         range_m=rng_m, seed=seed)

    if topo == "compact":
        return run_dcf_sweep(n_stations=n, frame_len=size,
                             frames_per_station=frames, rate_mbps=rate,
                             seed=seed)

    return run_hidden_ring(n_stations=n, frame_len=size,
                           frames_per_station=frames, rate_mbps=rate,
                           use_rts=use_rts,
                           radius_m=radius, range_m=rng_m, seed=seed)


def run_line3(frame_len: int = 1500, frames_per_station: int = 60,
              rate_mbps: float = 54.0, use_rts: bool = False,
              rts_threshold: int = 500, range_m: float = 100.0,
              seed: int = 7) -> Playback:
    """三节点隐藏终端：A—AP—C，A 与 C 相距 160m 互相听不到。"""
    sim = TracedSimulator(seed=seed, range_m=range_m, rate_mbps=rate_mbps,
                          use_rts=use_rts, rts_threshold=rts_threshold)
    ap = sim.add_station("AP", "02:00:00:00:00:ff", x=80.0, is_ap=True)
    a = sim.add_station("STA-A", "02:00:00:00:00:01", x=0.0)
    c = sim.add_station("STA-C", "02:00:00:00:00:03", x=160.0)
    views = [StationView(s.name, s.mac, s.x, s.y, s.is_ap)
             for s in sim.stations]
    for s in (a, c):
        for _ in range(frames_per_station):
            sim.enqueue(s, ap.mac, frame_len)
    sim.run()
    return _to_playback(sim, views, "三节点隐藏终端", n_stations=2,
                        frame_len=frame_len, n_frames=frames_per_station,
                        rate_mbps=rate_mbps, range_m=range_m,
                        topology_desc=TOPOLOGY_DESC["line3"])


def export_pcap(config: Dict[str, object],
                rel_path: str = "out/lab_live.pcap") -> str:
    """按当前配置导出 linktype 127 的 pcap，交给 Wireshark 交叉验证。

    碰撞帧会在 Radiotap Flags 里置 Bad FCS 位，
    重传帧会置 802.11 Frame Control 的 Retry 位——
    这是「碰撞在抓包里长什么样」的整个演示所依赖的机制。
    """
    from netcore.pcap import PcapWriter

    from .paths import project_root

    project = project_root()
    os.makedirs(os.path.join(project, "out"), exist_ok=True)
    path = os.path.join(project, rel_path)

    sim = _build_and_run(config)
    with PcapWriter(path, linktype=127) as w:
        for t_sec, raw in sim.pcap_frames():
            w.write(raw, t_sec)
    return path


def _build_and_run(config: Dict[str, object]) -> TracedSimulator:
    """只跑仿真不整理视图，供导出 pcap 复用同一份配置。"""
    topo = str(config["topology"])
    n = int(config["n_stations"])
    frames = int(config["frames_per_station"])
    size = int(config["frame_len"])
    rate = float(config["rate_mbps"])
    rng_m = float(config["range_m"])
    seed = int(config["seed"])
    use_rts = bool(config["use_rts"])
    radius = float(config.get("radius_m", 80.0))
    rts_threshold = 0 if use_rts else 500

    if topo == "line3":
        sim = TracedSimulator(seed=seed, range_m=rng_m, rate_mbps=rate,
                              use_rts=use_rts, rts_threshold=rts_threshold)
        ap = sim.add_station("AP", "02:00:00:00:00:ff", x=80.0, is_ap=True)
        a = sim.add_station("STA-A", "02:00:00:00:00:01", x=0.0)
        c = sim.add_station("STA-C", "02:00:00:00:00:03", x=160.0)
        for s in (a, c):
            for _ in range(frames):
                sim.enqueue(s, ap.mac, size)
        sim.run()
        return sim

    if topo == "compact":
        sim, _ = build_compact_circle(n, seed=seed, rate_mbps=rate)
        ap_mac = sim.stations[0].mac
        for s in sim.stations[1:]:
            for _ in range(frames):
                sim.enqueue(s, ap_mac, size)
        sim.run()
        return sim

    sim, _ = _make_ring_view(n, radius, rng_m, rate, seed,
                             use_rts=use_rts, rts_threshold=rts_threshold)
    ap_mac = sim.stations[0].mac
    for s in sim.stations[1:]:
        for _ in range(frames):
            sim.enqueue(s, ap_mac, size)
    sim.run()
    return sim
