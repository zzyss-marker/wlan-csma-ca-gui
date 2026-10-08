"""IEEE 802.11 DCF（分布式协调功能）离散事件仿真。

DCF 是 WiFi 的**强制**接入机制（CSMA/CA）。本模块从零实现它：

1. **载波侦听（CS）**：发送前先听信道；空闲持续 DIFS 才能开始退避。
2. **随机退避（CA）**：在 ``[0, CW]`` 里均匀抽一个整数，每个空闲时隙减 1，
   减到 0 才发送。这就是"避免冲突"的核心——把同时到达的发送需求错开。
3. **二进制指数退避（BEB）**：冲突后 ``CW = min(2*CW + 1, CWmax)``，
   成功后退回 ``CWmin``。
4. **确认（ACK）**：接收方等 SIFS（比 DIFS 短）后立刻回 ACK。
   SIFS < DIFS 保证 ACK 有最高优先级，不会被其他站点抢走。
5. **RTS/CTS**：大帧先握手，用短控制帧"预约"信道，解决隐藏终端。
6. **虚拟载波侦听（NAV）**：帧头的 Duration 字段告诉其他站点信道要占用多久。

**隐藏终端问题**：A 和 C 互相听不到，但都能听到 AP。
A 发数据时 C 听不到（以为信道空闲），也发数据 → 在 AP 处碰撞。
RTS/CTS 能解决：AP 回的 CTS 会被 A 和 C 都听到，
C 从 CTS 的 Duration 里知道信道被占用，于是退避。

本模块用**确定性随机种子**，所以任何一次实验都可以完整复现。
"""

from __future__ import annotations

import heapq
import math
import random
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import frame as F
from . import phy

# ---------------------------------------------------------------- 站点
@dataclass
class PendingFrame:
    """一个等待发送的帧。"""

    src: str
    dst: str
    payload: bytes
    enqueue_time: float = 0.0
    tid: int = 0
    is_ack: bool = False

    @property
    def mac_len(self) -> int:
        return 26 + len(self.payload)      # QoS 数据帧头 26 字节


@dataclass
class Station:
    """一个 802.11 站点（STA 或 AP）。"""

    name: str
    mac: str
    x: float = 0.0
    y: float = 0.0
    is_ap: bool = False
    queue: deque = field(default_factory=deque)
    cw: int = F.CW_MIN
    backoff: Optional[int] = None
    retries: int = 0
    #: 虚拟载波侦听（NAV）冻结到的时刻；在此之前该站点不参与竞争
    defer_until: float = 0.0
    #: 被 NAV 冻结的累计时长（用于统计）
    nav_frozen_us: float = 0.0
    # 统计
    tx_attempts: int = 0
    successes: int = 0
    collisions: int = 0
    retransmits: int = 0
    backoff_slots_total: int = 0
    backoff_draws: List[int] = field(default_factory=list)
    delays_us: List[float] = field(default_factory=list)
    airtime_us: float = 0.0
    dropped: int = 0

    def distance_to(self, other: "Station") -> float:
        return math.hypot(self.x - other.x, self.y - other.y)

    def enqueue(self, frame: PendingFrame, now: float) -> None:
        frame.enqueue_time = now
        self.queue.append(frame)

    @property
    def pending(self) -> bool:
        return len(self.queue) > 0

    def draw_backoff(self, rng: random.Random) -> int:
        self.backoff = rng.randint(0, self.cw)
        self.backoff_draws.append(self.backoff)
        return self.backoff

    def on_collision(self) -> None:
        self.collisions += 1
        self.retries += 1
        self.retransmits += 1
        self.cw = min(2 * self.cw + 1, F.CW_MAX)
        self.backoff = None

    def on_success(self) -> None:
        self.successes += 1
        self.cw = F.CW_MIN
        self.backoff = None
        self.retries = 0

    def stats(self) -> Dict[str, object]:
        n = self.successes + self.collisions
        return {
            "station": self.name,
            "successes": self.successes,
            "collisions": self.collisions,
            "retransmits": self.retransmits,
            "tx_attempts": self.tx_attempts,
            "collision_rate": round(self.collisions / n, 4) if n else 0.0,
            "avg_backoff_slots": (round(sum(self.backoff_draws)
                                        / len(self.backoff_draws), 2)
                                  if self.backoff_draws else 0.0),
            "max_backoff": max(self.backoff_draws) if self.backoff_draws else 0,
            "avg_delay_us": (round(sum(self.delays_us) / len(self.delays_us), 2)
                             if self.delays_us else 0.0),
            "airtime_us": round(self.airtime_us, 1),
            "nav_frozen_us": round(self.nav_frozen_us, 1),
            "dropped": self.dropped,
        }


# ---------------------------------------------------------------- 事件日志
@dataclass
class AirEvent:
    """一次空口事件（用于生成 pcap 与时间线图）。"""

    t_start: float
    t_end: float
    kind: str                   # "data" / "rts" / "cts" / "ack" / "collision"
    src: str
    dst: str
    length: int = 0
    rate_mbps: float = 54.0
    retry: bool = False
    tid: int = 0
    seq: int = 0
    payload: bytes = b""
    ok: bool = True             # False 表示这次传输被碰撞毁掉了

    @property
    def duration_us(self) -> float:
        return self.t_end - self.t_start


# ---------------------------------------------------------------- 仿真器
class DcfSimulator:
    """DCF 信道仿真器。

    用法::

        sim = DcfSimulator(seed=42)
        ap = sim.add_station("AP", "02:00:00:00:00:ff", is_ap=True)
        a = sim.add_station("STA-A", "02:00:00:00:00:01", x=0)
        b = sim.add_station("STA-B", "02:00:00:00:00:02", x=40)
        for _ in range(200):
            sim.enqueue(a, b.mac, 1500)
            sim.enqueue(b, a.mac, 1500)
        result = sim.run()
    """

    def __init__(self, seed: int = 42, rate_mbps: float = 54.0,
                 ctrl_rate_mbps: float = 24.0, range_m: float = 100.0,
                 slot_us: float = F.SLOT_TIME, sifs_us: float = F.SIFS,
                 difs_us: float = F.DIFS, eifs_us: float = F.EIFS,
                 use_rts: bool = False, rts_threshold: int = 500,
                 preamble_us: float = phy.PREAMBLE_LONG_US,
                 ack_timeout_us: float = 0.0,
                 max_retries: int = F.A_RETRY_LIMIT) -> None:
        self.rng = random.Random(seed)
        self.seed = seed
        self.rate_mbps = rate_mbps
        self.ctrl_rate_mbps = ctrl_rate_mbps
        self.range_m = range_m
        self.slot_us = slot_us
        self.sifs_us = sifs_us
        self.difs_us = difs_us
        self.eifs_us = eifs_us
        self.use_rts = use_rts
        self.rts_threshold = rts_threshold
        self.preamble_us = preamble_us
        self.max_retries = max_retries
        self.stations: List[Station] = []
        self.now = 0.0
        self.events: List[AirEvent] = []
        self.channel_busy_us = 0.0
        self.idle_slots = 0
        self.busy_periods = 0
        self._seq = 0
        self._completed = 0
        self._finished = 0     # 成功 + 因超过重传上限而丢弃
        self._target = 0
        self._collision_trace: List[Dict[str, object]] = []

    # ---------------------------------------------------------- 配置
    def add_station(self, name: str, mac: str, x: float = 0.0, y: float = 0.0,
                    is_ap: bool = False) -> Station:
        st = Station(name=name, mac=mac, x=x, y=y, is_ap=is_ap)
        self.stations.append(st)
        return st

    def enqueue(self, station: Station, dst_mac: str, payload_len: int,
                tid: int = 0) -> None:
        station.enqueue(PendingFrame(src=station.mac, dst=dst_mac,
                                     payload=b"\x00" * payload_len,
                                     tid=tid), self.now)
        self._target += 1

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) % 4096
        return self._seq

    # ---------------------------------------------------------- 信道模型
    def can_hear(self, a: Station, b: Station) -> bool:
        """a 发出的信号能否被 b 听到（自由空间距离模型）。"""
        if a is b:
            return False
        return a.distance_to(b) <= self.range_m

    def _receivers(self, tx: Station) -> List[Station]:
        return [s for s in self.stations if self.can_hear(tx, s)]

    def _collides(self, contenders: Sequence[Station]) -> bool:
        """多个并发发送是否在某个接收方处碰撞。

        判据：存在一个站点，能同时听到 >= 2 个发送方。
        如果两个发送方互相隐藏、且没有共同接收方，则**不碰撞**
        （这是空间复用，不是隐藏终端问题）。
        """
        heard: Dict[str, int] = {}
        for tx in contenders:
            for rx in self._receivers(tx):
                heard[rx.mac] = heard.get(rx.mac, 0) + 1
        return any(v >= 2 for v in heard.values())

    # ---------------------------------------------------------- 空口时间
    def data_airtime(self, nbytes: int) -> float:
        return phy.airtime_us(nbytes, self.rate_mbps, self.preamble_us)

    def ack_airtime(self) -> float:
        return phy.ack_airtime_us(self.ctrl_rate_mbps, self.preamble_us)

    def rts_airtime(self) -> float:
        return phy.rts_airtime_us(self.ctrl_rate_mbps, self.preamble_us)

    def cts_airtime(self) -> float:
        return phy.cts_airtime_us(self.ctrl_rate_mbps, self.preamble_us)

    # ---------------------------------------------------------- 主循环
    def run(self, max_time_us: float = 5e7) -> Dict[str, object]:
        """跑到所有帧发完（或超时）。"""
        while self._finished < self._target and self.now < max_time_us:
            self._step()
        return self.result()

    def _active(self) -> List[Station]:
        return [s for s in self.stations if s.pending]

    def _station_by_mac(self, mac: str) -> Optional[Station]:
        for s in self.stations:
            if s.mac == mac:
                return s
        return None

    def _step(self) -> None:
        active = self._active()
        if not active:
            return

        # ---- 1) 信道空闲 DIFS
        self.now += self.difs_us

        # ---- 2) 退避倒计时（处于 NAV 冻结期的站点跳过，不递减计数器）
        while True:
            for s in self._active():
                if s.defer_until > self.now:
                    continue
                if s.backoff is None:
                    s.draw_backoff(self.rng)
                if s.backoff > 0:
                    s.backoff -= 1
                    s.backoff_slots_total += 1
            ready = [s for s in self._active()
                     if s.backoff == 0 and s.defer_until <= self.now]
            if ready:
                break
            self.now += self.slot_us
            self.idle_slots += 1

        # ---- 3) 发送
        for s in ready:
            s.tx_attempts += 1
        if len(ready) == 1:
            self._transmit(ready[0])
        elif self._collides(ready):
            self._transmit_collision(ready)
        else:
            # 互相听不到且没有共同接收方：空间复用，各自成功
            for s in ready:
                self._transmit(s, peers=ready)

    # ---------------------------------------------------------- 一次传输
    def _transmit(self, st: Station, peers: Sequence[Station] = ()) -> None:
        """一次发送尝试。

        与"教科书版"DCF 最大的不同：本方法会检查**隐藏终端**。
        听不到本次传输的站点会继续倒计时；如果它的退避计数器在数据帧
        结束前归零，它就会"插进来"发送，在接收方处造成碰撞。
        """
        pf = st.queue[0]
        t0 = self.now
        use_rts = self.use_rts and pf.mac_len > self.rts_threshold
        rx = self._station_by_mac(pf.dst)

        # ---- 时间轴
        if use_rts:
            rts_end = t0 + self.rts_airtime()
            cts_start = rts_end + self.sifs_us
            cts_end = cts_start + self.cts_airtime()
            data_start = cts_end + self.sifs_us
        else:
            rts_end = cts_start = cts_end = None
            data_start = t0
        data_end = data_start + self.data_airtime(pf.mac_len)
        ack_start = data_end + self.sifs_us
        ack_end = ack_start + self.ack_airtime()

        # ---- 载波侦听：谁能听到？什么时候开始听到？
        freeze_at: Dict[str, float] = {}
        for s in self._receivers(st):
            freeze_at[s.mac] = t0                 # 听到 RTS / 数据帧前导
        if use_rts and rx is not None:
            for s in self._receivers(rx):
                # 听到 AP 回的 CTS 才知道信道被占用 —— 隐藏终端获救的时刻
                freeze_at.setdefault(s.mac, cts_start)

        for mac, t_freeze in freeze_at.items():
            s = self._station_by_mac(mac)
            if s is None or s is st:
                continue
            until = cts_end if (use_rts and t_freeze < cts_start) else ack_end
            s.defer_until = max(s.defer_until, until)
            s.nav_frozen_us += max(0.0, until - t_freeze)

        # ---- 隐藏终端检测
        peer_macs = {p.mac for p in peers}
        intruders: List[Tuple[Station, float]] = []
        for s in self._active():
            if s is st or s.mac in freeze_at or s.mac in peer_macs:
                continue
            if s.backoff is None:
                s.draw_backoff(self.rng)
            if s.backoff <= 0:
                continue
            t_ready = t0 + s.backoff * self.slot_us
            if t_ready < data_end:
                intruders.append((s, t_ready))

        if intruders:
            self._hidden_collision(st, intruders, t0, rts_end, cts_start,
                                   data_end, use_rts)
            return

        # ---- 真正发送
        seq = self._next_seq()
        if use_rts:
            self.events.append(AirEvent(t0, rts_end, "rts", st.mac, pf.dst, 20,
                                        self.ctrl_rate_mbps))
            self.events.append(AirEvent(cts_start, cts_end, "cts", pf.dst,
                                        st.mac, 14, self.ctrl_rate_mbps))
        self.events.append(AirEvent(data_start, data_end, "data", st.mac, pf.dst,
                                    pf.mac_len, self.rate_mbps,
                                    retry=st.retries > 0, tid=pf.tid, seq=seq,
                                    payload=pf.payload))
        self.events.append(AirEvent(ack_start, ack_end, "ack", pf.dst, st.mac,
                                    14, self.ctrl_rate_mbps))
        st.airtime_us += data_end - data_start
        self.now = ack_end
        st.delays_us.append(self.now - pf.enqueue_time)
        st.queue.popleft()
        st.on_success()
        self._completed += 1
        self._finished += 1
        self.channel_busy_us += self.now - t0
        self.busy_periods += 1

    def _hidden_collision(self, winner: Station,
                          intruders: Sequence[Tuple[Station, float]],
                          t0: float, rts_end: Optional[float],
                          cts_start: Optional[float], data_end: float,
                          use_rts: bool) -> None:
        """隐藏终端碰撞：赢家发到一半，被听不到它的站点打断。

        如果启用了 RTS/CTS 且所有"闯入者"都在 CTS 发出之前醒来，
        碰撞就只发生在**短小的 RTS 帧**上，代价远小于整个数据帧。
        """
        rts_phase = bool(use_rts) and all(
            t < (cts_start or 0) for _, t in intruders)
        if rts_phase:
            end = rts_end or t0
            longest = end - t0
        else:
            longest = data_end - t0
            for s, t in intruders:
                longest = max(longest, t - t0 + self.data_airtime(s.queue[0].mac_len))
            end = t0 + longest

        self.events.append(AirEvent(t0, min(end, t0 + longest), "collision",
                                    winner.mac, winner.queue[0].dst,
                                    winner.queue[0].mac_len, self.rate_mbps,
                                    retry=winner.retries > 0,
                                    tid=winner.queue[0].tid,
                                    payload=winner.queue[0].payload, ok=False))
        winner.airtime_us += min(end, t0 + longest) - t0
        for s, t in intruders:
            dur = self.data_airtime(s.queue[0].mac_len)
            self.events.append(AirEvent(t, t + dur, "collision", s.mac,
                                        s.queue[0].dst, s.queue[0].mac_len,
                                        self.rate_mbps,
                                        retry=s.retries > 0,
                                        tid=s.queue[0].tid,
                                        payload=s.queue[0].payload, ok=False))
            s.airtime_us += dur

        self.now = end
        self._collision_trace.append({
            "t_us": round(t0, 2),
            "stations": [winner.name] + [s.name for s, _ in intruders],
            "reason": "rts_phase" if rts_phase else "hidden_terminal",
            "longest_us": round(longest, 2),
        })
        self._apply_collision_backoff([winner] + [s for s, _ in intruders])
        self.now += self.eifs_us
        self.channel_busy_us += self.now - t0
        self.busy_periods += 1

    def _apply_collision_backoff(self, participants: Sequence[Station]) -> None:
        for st in participants:
            st.on_collision()
            if st.retries > self.max_retries:
                st.queue.popleft()
                st.dropped += 1
                st.on_success()
                st.successes -= 1          # 不计入成功
                self._finished += 1        # 但这一帧确实"了结"了

    def _transmit_collision(self, contenders: Sequence[Station]) -> None:
        """多个站点在**同一时隙**同时开始发送造成的碰撞。"""
        start = self.now
        longest = 0.0
        for st in contenders:
            pf = st.queue[0]
            data_us = self.data_airtime(pf.mac_len)
            longest = max(longest, data_us)
            self.events.append(AirEvent(start, start + data_us, "collision",
                                        st.mac, pf.dst, pf.mac_len,
                                        self.rate_mbps,
                                        retry=st.retries > 0,
                                        tid=pf.tid,
                                        payload=pf.payload, ok=False))
            st.airtime_us += data_us
        self.now = start + longest
        self._collision_trace.append({
            "t_us": round(start, 2),
            "stations": [s.name for s in contenders],
            "reason": "same_slot",
            "longest_us": round(longest, 2),
        })
        self._apply_collision_backoff(contenders)
        self.now += self.eifs_us
        self.channel_busy_us += self.now - start
        self.busy_periods += 1

    # ---------------------------------------------------------- 结果
    def result(self) -> Dict[str, object]:
        total_success = sum(s.successes for s in self.stations)
        total_coll = sum(s.collisions for s in self.stations)
        total_attempts = total_success + total_coll
        total_bytes = sum(
            e.length for e in self.events if e.kind == "data" and e.ok)
        wasted_us = sum(e.duration_us for e in self.events if not e.ok)
        elapsed_us = self.now
        per_station = [s.stats() for s in self.stations]
        succ = [s.successes for s in self.stations if not s.is_ap]
        return {
            "seed": self.seed,
            "stations": len(self.stations),
            "target_frames": self._target,
            "completed_frames": total_success,
            "dropped_frames": sum(s.dropped for s in self.stations),
            "elapsed_us": round(elapsed_us, 1),
            "elapsed_s": round(elapsed_us / 1e6, 6),
            "throughput_mbps": round(
                total_bytes * 8 / (elapsed_us * 1e-6) / 1e6, 4)
                if elapsed_us else 0.0,
            "channel_utilization": round(
                self.channel_busy_us / elapsed_us, 4) if elapsed_us else 0.0,
            "collisions": total_coll,
            "collision_rate": round(total_coll / total_attempts, 4)
                if total_attempts else 0.0,
            "attempts": total_attempts,
            "wasted_us": round(wasted_us, 1),
            "wasted_ratio": round(wasted_us / elapsed_us, 4) if elapsed_us else 0.0,
            "idle_slots": self.idle_slots,
            "busy_periods": self.busy_periods,
            "jain_fairness": round(jain(succ), 6),
            "jain_fairness_short_term": round(self.short_term_fairness(), 6),
            "per_station": per_station,
            "rts_cts": self.use_rts,
        }

    def short_term_fairness(self, fraction: float = 0.25) -> float:
        """**短时间尺度**公平性。

        长时间尺度上每个站点最终都会把队列发完，Jain 指数必然是 1.0，
        看不出任何问题。真正的公平性要看**前若干次成功传输**里
        各站点占了多少——这才反映 DCF 的瞬时抢占行为。
        """
        ok = [e for e in self.events if e.kind == "data"]
        if not ok:
            return 0.0
        window = ok[:max(1, int(len(ok) * fraction))]
        counts: Dict[str, int] = {}
        for e in window:
            counts[e.src] = counts.get(e.src, 0) + 1
        return jain(list(counts.values()))

    def pcap_frames(self) -> List[Tuple[float, bytes]]:
        """把空口事件转成 ``[(时间秒, Radiotap+802.11 字节), ...]``。

        碰撞帧的 Radiotap Flags 里会置 **Bad FCS** 位，
        这样在 Wireshark 里能一眼看出哪些帧是碰撞的。
        重传帧的 802.11 Frame Control 里会置 **Retry** 位。
        """
        out: List[Tuple[float, bytes]] = []
        for e in self.events:
            flags = F.RT_FLAG_FCS
            if e.kind == "collision":
                flags |= F.RT_FLAG_BAD_FCS
            radio = F.Radiotap(tsft=int(e.t_start), flags=flags,
                               rate_mbps=e.rate_mbps, channel=6,
                               signal_dbm=-45)
            if e.kind == "data":
                mf = F.data_frame(e.src, e.dst, e.dst, e.payload,
                                  seq=e.seq, tid=e.tid, retry=int(e.retry))
            elif e.kind == "collision":
                mf = F.data_frame(e.src, e.dst, e.dst, e.payload,
                                  seq=0, tid=e.tid, retry=int(e.retry))
            elif e.kind == "ack":
                mf = F.ack_frame(e.dst)
            elif e.kind == "cts":
                mf = F.cts_frame(e.dst)
            elif e.kind == "rts":
                mf = F.rts_frame(e.dst, e.src)
            else:
                continue
            out.append((e.t_start / 1e6, F.build_frame(mf, radio)))
        return out

    def timeline(self) -> List[Dict[str, object]]:
        return [{
            "t_start_us": round(e.t_start, 2),
            "t_end_us": round(e.t_end, 2),
            "kind": e.kind,
            "src": e.src,
            "dst": e.dst,
            "length": e.length,
        } for e in self.events]


def jain(values: Sequence[float]) -> float:
    """Jain 公平指数：1 表示完全公平，1/n 表示完全被一个流独占。"""
    vals = [float(v) for v in values]
    if not vals or sum(vals) == 0:
        return 0.0
    return (sum(vals) ** 2) / (len(vals) * sum(v * v for v in vals))


# ---------------------------------------------------------------- 场景便捷函数
def build_bss(n_stations: int = 4, spacing_m: float = 20.0,
              seed: int = 42, **kwargs) -> Tuple[DcfSimulator, Station,
                                                 List[Station]]:
    """构造一个基础服务集（BSS）：1 个 AP + n 个 STA 排成一行。"""
    sim = DcfSimulator(seed=seed, **kwargs)
    ap = sim.add_station("AP", "02:00:00:00:00:ff", x=0.0, is_ap=True)
    stas = []
    for i in range(n_stations):
        stas.append(sim.add_station(
            f"STA-{chr(ord('A') + i)}",
            f"02:00:00:00:00:{i + 1:02x}",
            x=(i + 1) * spacing_m))
    return sim, ap, stas


def build_hidden_terminal(seed: int = 42, range_m: float = 100.0,
                          **kwargs) -> Tuple[DcfSimulator, Station,
                                             Station, Station]:
    """隐藏终端拓扑：A 与 C 相距 160m（互相听不到），AP 在中间。

    ``range_m=100`` 时：A<->AP 80m ✓，C<->AP 80m ✓，A<->C 160m ✗。
    这正是隐藏终端问题的经典配置。
    """
    sim = DcfSimulator(seed=seed, range_m=range_m, **kwargs)
    ap = sim.add_station("AP", "02:00:00:00:00:ff", x=80.0, is_ap=True)
    a = sim.add_station("STA-A", "02:00:00:00:00:01", x=0.0)
    c = sim.add_station("STA-C", "02:00:00:00:00:03", x=160.0)
    return sim, ap, a, c


def build_hidden_ring(n_stations: int = 4, radius_m: float = 80.0,
                      seed: int = 42, **kwargs) -> Tuple[DcfSimulator,
                                                          Station,
                                                          List[Station]]:
    """**隐藏终端农场**：n 个站点均匀分布在一个圆上，AP 在圆心。

    ``range_m=100``、``radius_m=80`` 时：

    * 每个站点到 AP 的距离都是 80m ✓ 能听到 AP
    * 相邻站点间距 ``2*80*sin(pi/n)``：n=4 时 113m ✗ 互相听不到

    于是任意两个站点同时发送都会在 AP 处碰撞，而且**没有任何站点
    能通过物理载波侦听发现对方**。这才是 RTS/CTS 真正的主场。
    """
    sim = DcfSimulator(seed=seed, **kwargs)
    ap = sim.add_station("AP", "02:00:00:00:00:ff", x=0.0, y=0.0, is_ap=True)
    stas = []
    for i in range(n_stations):
        ang = 2 * math.pi * i / n_stations
        stas.append(sim.add_station(
            f"STA-{i + 1}",
            f"02:00:00:00:00:{i + 1:02x}",
            x=radius_m * math.cos(ang),
            y=radius_m * math.sin(ang)))
    return sim, ap, stas
