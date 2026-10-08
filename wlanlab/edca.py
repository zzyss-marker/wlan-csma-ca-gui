"""IEEE 802.11e EDCA（增强分布式信道接入）仿真。

DCF 对所有流量一视同仁，这在"语音 + 视频 + 下载 + 后台同步"混跑时
是灾难：VoIP 的一个 200 字节包要排在 1500 字节的 BT 下载包后面等
好几个毫秒，抖动直接爆掉。

802.11e 用 **四个接入类别（Access Category, AC）** 解决这个问题。
每个 AC 是一个独立的"虚拟站点"，有自己的三个参数：

===========  ======  ========  ========  ============  ============
AC           AIFSN   CWmin     CWmax     TXOP (a/g)    典型业务
===========  ======  ========  ========  ============  ============
AC_VO (3)    2       3         7         1.504 ms      语音
AC_VI (2)    2       7         15        3.008 ms      视频
AC_BE (0)    3       15        1023      0             尽力而为
AC_BK (1)    7       15        1023      0             后台
===========  ======  ========  ========  ============  ============

三个机制共同制造优先级：

1. **AIFS 更短**：``AIFS = SIFS + AIFSN * slot``。AC_VO 的 AIFSN=2
   正好等于 DIFS（34us），AC_BK 的 AIFSN=7 要等 79us。
   高优先级 AC 比低优先级**早 45us 开始倒计时**。
2. **CW 更小**：AC_VO 的 CWmin=3，平均退避 1.5 个时隙；
   AC_BK 的 CWmin=15，平均 7.5 个时隙。差了 5 倍。
3. **TXOP 突发**：AC_VI/VO 抢到信道后可以在 TXOP 窗口内连续发多帧，
   帧间隔只用 SIFS（16us），不需要重新竞争。

**虚拟碰撞（virtual collision）**：同一个站点内部两个 AC 同时倒计时到 0 时，
高优先级的那个赢得"内部竞争"去占用空口，低优先级的那个当作发生了一次
碰撞（CW 翻倍、重新抽退避）。这是 EDCA 里最容易被忽略、也最容易考到的点。

本模块从零实现上述全部机制，输出每个 AC 的吞吐 / 时延 / 抖动 / 公平性。
"""

from __future__ import annotations

import math
import random
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import frame as F
from . import phy
from .dcf import AirEvent, jain

# ---------------------------------------------------------------- 接入类别
@dataclass(frozen=True)
class AccessCategory:
    """一个接入类别的全部参数。"""

    index: int
    name: str
    aifsn: int
    cw_min: int
    cw_max: int
    txop_us: float
    priority: int
    traffic: str

    def aifs_us(self, slot_us: float = F.SLOT_TIME,
                sifs_us: float = F.SIFS) -> float:
        return sifs_us + self.aifsn * slot_us

    def describe(self) -> str:
        return (f"{self.name}(AIFSN={self.aifsn}, CW={self.cw_min}-"
                f"{self.cw_max}, TXOP={self.txop_us:.0f}us)")


AC_BK = AccessCategory(1, "AC_BK", aifsn=7, cw_min=15, cw_max=1023,
                       txop_us=0.0, priority=0, traffic="后台/下载")
AC_BE = AccessCategory(0, "AC_BE", aifsn=3, cw_min=15, cw_max=1023,
                       txop_us=0.0, priority=1, traffic="尽力而为")
AC_VI = AccessCategory(2, "AC_VI", aifsn=2, cw_min=7, cw_max=15,
                       txop_us=3008.0, priority=2, traffic="视频")
AC_VO = AccessCategory(3, "AC_VO", aifsn=2, cw_min=3, cw_max=7,
                       txop_us=1504.0, priority=3, traffic="语音")

ALL_ACS: Tuple[AccessCategory, ...] = (AC_BK, AC_BE, AC_VI, AC_VO)
AC_BY_NAME: Dict[str, AccessCategory] = {a.name: a for a in ALL_ACS}

#: 802.11 的 TID → AC 映射（RFC 8320 / 802.11 Table 10-1）
AC_BY_TID: Dict[int, AccessCategory] = {
    1: AC_BK, 2: AC_BK,
    0: AC_BE, 3: AC_BE,
    4: AC_VI, 5: AC_VI,
    6: AC_VO, 7: AC_VO,
}

#: 802.11 用户优先级（UP）→ AC
AC_BY_UP: Dict[int, AccessCategory] = {
    1: AC_BK, 2: AC_BK,
    0: AC_BE, 3: AC_BE,
    4: AC_VI, 5: AC_VI,
    6: AC_VO, 7: AC_VO,
}


def ac_for_tid(tid: int) -> AccessCategory:
    return AC_BY_TID.get(tid & 0x7, AC_BE)


def ac_for_dscp(dscp: int) -> AccessCategory:
    """把 IP DSCP 映射到 AC（WMM 规范附录 B 的简化版）。

    EF(46) / CS6(48) → 语音；AF4x(34-38) / CS4(32) / AF3x → 视频；
    CS1(8) / AF1x → 后台；其余 → 尽力而为。
    """
    if dscp in (46, 48, 56):
        return AC_VO
    if dscp in (32, 34, 36, 38):
        return AC_VI
    if dscp in (8, 10, 12, 14):
        return AC_BK
    return AC_BE


# ---------------------------------------------------------------- 队列
@dataclass
class AcQueue:
    """一个 (站点, AC) 组合 —— EDCA 里就是一个"虚拟站点"。"""

    station: str
    mac: str
    ac: AccessCategory
    frames: deque = field(default_factory=deque)
    cw: int = 0
    backoff: Optional[int] = None
    defer_until: float = 0.0
    count_start: float = 0.0
    # 统计
    tx_attempts: int = 0
    successes: int = 0
    collisions: int = 0
    virtual_collisions: int = 0
    retransmits: int = 0
    dropped: int = 0
    delays_us: List[float] = field(default_factory=list)
    jitter_us: List[float] = field(default_factory=list)
    airtime_us: float = 0.0
    txop_bursts: int = 0

    def __post_init__(self) -> None:
        if not self.cw:
            self.cw = self.ac.cw_min

    @property
    def key(self) -> str:
        return f"{self.station}/{self.ac.name}"

    @property
    def pending(self) -> bool:
        return len(self.frames) > 0

    def draw_backoff(self, rng: random.Random) -> int:
        self.backoff = rng.randint(0, self.cw)
        return self.backoff

    def on_collision(self) -> None:
        self.collisions += 1
        self.retransmits += 1
        self.cw = min(2 * self.cw + 1, self.ac.cw_max)
        self.backoff = None

    def on_virtual_collision(self) -> None:
        """内部竞争输给同站点的高优先级 AC。"""
        self.virtual_collisions += 1
        self.cw = min(2 * self.cw + 1, self.ac.cw_max)
        self.backoff = None

    def on_success(self) -> None:
        self.successes += 1
        self.cw = self.ac.cw_min
        self.backoff = None

    def record_delay(self, d: float) -> None:
        if self.delays_us:
            self.jitter_us.append(abs(d - self.delays_us[-1]))
        self.delays_us.append(d)

    def stats(self) -> Dict[str, object]:
        n = self.successes + self.collisions
        d = self.delays_us
        return {
            "station": self.station,
            "ac": self.ac.name,
            "priority": self.ac.priority,
            "successes": self.successes,
            "collisions": self.collisions,
            "virtual_collisions": self.virtual_collisions,
            "tx_attempts": self.tx_attempts,
            "collision_rate": round(self.collisions / n, 4) if n else 0.0,
            "avg_delay_us": round(sum(d) / len(d), 2) if d else 0.0,
            "max_delay_us": round(max(d), 2) if d else 0.0,
            "p95_delay_us": round(_percentile(d, 0.95), 2) if d else 0.0,
            "avg_jitter_us": (round(sum(self.jitter_us) / len(self.jitter_us), 2)
                              if self.jitter_us else 0.0),
            "airtime_us": round(self.airtime_us, 1),
            "txop_bursts": self.txop_bursts,
            "dropped": self.dropped,
        }


def _percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    pos = q * (len(xs) - 1)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(xs) - 1)
    frac = pos - lo
    return xs[lo] * (1 - frac) + xs[hi] * frac


# ---------------------------------------------------------------- 仿真器
@dataclass
class PendingAcFrame:
    src: str
    dst: str
    payload: bytes
    enqueue_time: float = 0.0
    tid: int = 0

    @property
    def mac_len(self) -> int:
        return 26 + len(self.payload)


class EdcaSimulator:
    """EDCA 信道仿真器。

    用法::

        sim = EdcaSimulator(seed=1)
        sta = sim.add_station("STA-A", "02:00:00:00:00:01")
        sim.enqueue(sta, AC_VO, ap_mac, 160)
        sim.enqueue(sta, AC_BE, ap_mac, 1500)
        result = sim.run()
    """

    def __init__(self, seed: int = 42, rate_mbps: float = 54.0,
                 ctrl_rate_mbps: float = 24.0, range_m: float = 100.0,
                 slot_us: float = F.SLOT_TIME, sifs_us: float = F.SIFS,
                 preamble_us: float = phy.PREAMBLE_LONG_US,
                 max_retries: int = F.A_RETRY_LIMIT,
                 enable_txop: bool = True,
                 enable_aifs: bool = True,
                 enable_cw: bool = True,
                 homogeneous: bool = False) -> None:
        self.rng = random.Random(seed)
        self.seed = seed
        self.rate_mbps = rate_mbps
        self.ctrl_rate_mbps = ctrl_rate_mbps
        self.range_m = range_m
        self.slot_us = slot_us
        self.sifs_us = sifs_us
        self.preamble_us = preamble_us
        self.max_retries = max_retries
        # 三个"消融开关"：关掉某个机制就能看出它单独贡献了多少
        self.enable_txop = enable_txop
        self.enable_aifs = enable_aifs
        self.enable_cw = enable_cw
        self.homogeneous = homogeneous
        self.queues: List[AcQueue] = []
        self.macs: Dict[str, str] = {}
        self.positions: Dict[str, Tuple[float, float]] = {}
        self.now = 0.0
        self.events: List[AirEvent] = []
        self.channel_busy_us = 0.0
        self.idle_slots = 0
        self._seq = 0
        self._target = 0
        self._finished = 0
        self._collision_trace: List[Dict[str, object]] = []

    # ---------------------------------------------------------- 配置
    def add_station(self, name: str, mac: str, x: float = 0.0,
                    y: float = 0.0) -> str:
        self.positions[name] = (x, y)
        self.macs[name] = mac
        return name

    def _ac(self, ac: AccessCategory) -> AccessCategory:
        """应用消融开关：把某个机制"关掉"，看它单独贡献了多少。

        ``homogeneous=True`` 等价于三个开关全关 —— 四个 AC 参数完全相同，
        退化成"四个 DCF 队列"，此时优先级应该完全消失。
        """
        if self.homogeneous:
            return AccessCategory(ac.index, ac.name, AC_BE.aifsn,
                                  AC_BE.cw_min, AC_BE.cw_max, 0.0,
                                  ac.priority, ac.traffic)
        return AccessCategory(
            ac.index, ac.name,
            ac.aifsn if self.enable_aifs else AC_BE.aifsn,
            ac.cw_min if self.enable_cw else AC_BE.cw_min,
            ac.cw_max if self.enable_cw else AC_BE.cw_max,
            ac.txop_us if self.enable_txop else 0.0,
            ac.priority, ac.traffic)

    def queue_for(self, station: str, ac: AccessCategory) -> AcQueue:
        for q in self.queues:
            if q.station == station and q.ac.name == ac.name:
                return q
        q = AcQueue(station=station, mac=self._mac_of(station),
                    ac=self._ac(ac))
        self.queues.append(q)
        return q

    def _mac_of(self, station: str) -> str:
        return self.macs.get(station, "")

    def enqueue(self, station: str, ac: AccessCategory, dst_mac: str,
                payload_len: int, tid: Optional[int] = None) -> AcQueue:
        q = self.queue_for(station, ac)
        q.frames.append(PendingAcFrame(
            src=q.mac, dst=dst_mac, payload=b"\x00" * payload_len,
            enqueue_time=self.now,
            tid=ac.index if tid is None else tid))
        self._target += 1
        return q

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) % 4096
        return self._seq

    # ---------------------------------------------------------- 信道
    def distance(self, a: str, b: str) -> float:
        ax, ay = self.positions[a]
        bx, by = self.positions[b]
        return math.hypot(ax - bx, ay - by)

    def can_hear(self, a: str, b: str) -> bool:
        if a == b:
            return False
        return self.distance(a, b) <= self.range_m

    # ---------------------------------------------------------- 空口时间
    def data_airtime(self, nbytes: int) -> float:
        return phy.airtime_us(nbytes, self.rate_mbps, self.preamble_us)

    def ack_airtime(self) -> float:
        return phy.ack_airtime_us(self.ctrl_rate_mbps, self.preamble_us)

    def aifs_us(self, ac: AccessCategory) -> float:
        return self._ac(ac).aifs_us(self.slot_us, self.sifs_us)

    # ---------------------------------------------------------- 主循环
    def run(self, max_time_us: float = 5e7) -> Dict[str, object]:
        while self._finished < self._target and self.now < max_time_us:
            self._step()
        return self.result()

    def _active(self) -> List[AcQueue]:
        return [q for q in self.queues if q.pending]

    def _step(self) -> None:
        active = self._active()
        if not active:
            return

        # ---- 1) 信道空闲：各 AC 按自己的 AIFS 决定何时开始倒计时
        t_idle = self.now
        for q in active:
            if q.count_start < t_idle:
                q.count_start = t_idle + self.aifs_us(q.ac)

        # ---- 2) 倒计时
        guard = 0
        while True:
            guard += 1
            if guard > 2_000_000:
                raise RuntimeError("EDCA 倒计时未收敛")
            for q in self._active():
                if self.now < q.count_start or q.defer_until > self.now:
                    continue
                if q.backoff is None:
                    q.draw_backoff(self.rng)
                if q.backoff > 0:
                    q.backoff -= 1
            ready = [q for q in self._active()
                     if q.backoff == 0 and self.now >= q.count_start
                     and q.defer_until <= self.now]
            if ready:
                break
            self.now += self.slot_us
            self.idle_slots += 1

        # ---- 3) 虚拟碰撞：同站点内高优先级 AC 胜出
        winners: List[AcQueue] = []
        by_station: Dict[str, List[AcQueue]] = {}
        for q in ready:
            by_station.setdefault(q.station, []).append(q)
        for station, group in by_station.items():
            if len(group) == 1:
                winners.append(group[0])
                continue
            group.sort(key=lambda q: (-q.ac.priority, q.ac.index))
            winners.append(group[0])
            for loser in group[1:]:
                loser.on_virtual_collision()
                self._collision_trace.append({
                    "t_us": round(self.now, 2),
                    "stations": [loser.key],
                    "reason": "virtual_collision",
                    "winner": group[0].key,
                })

        for q in winners:
            q.tx_attempts += 1

        # ---- 4) 空口竞争
        if len(winners) == 1:
            self._transmit(winners[0])
        else:
            if self._collides(winners):
                self._transmit_collision(winners)
            else:
                for q in winners:
                    self._transmit(q, peers=winners)

    def _collides(self, contenders: Sequence[AcQueue]) -> bool:
        heard: Dict[str, int] = {}
        for q in contenders:
            for other in self.queues:
                if other.station == q.station:
                    continue
                if self.can_hear(q.station, other.station):
                    heard[other.station] = heard.get(other.station, 0) + 1
        return any(v >= 2 for v in heard.values())

    # ---------------------------------------------------------- 传输
    def _transmit(self, q: AcQueue, peers: Sequence[AcQueue] = ()) -> None:
        pf = q.frames[0]
        t0 = self.now
        data_us = self.data_airtime(pf.mac_len)
        data_end = t0 + data_us
        ack_start = data_end + self.sifs_us
        ack_end = ack_start + self.ack_airtime()

        # 载波侦听：能听到的站点被冻结
        frozen = set()
        for other in self.queues:
            if other.station == q.station:
                continue
            if self.can_hear(q.station, other.station):
                frozen.add(other.station)
                other.defer_until = max(other.defer_until, ack_end)

        # 隐藏终端
        peer_stations = {p.station for p in peers}
        intruders: List[Tuple[AcQueue, float]] = []
        for other in self._active():
            if other.station == q.station or other.station in frozen:
                continue
            if other.station in peer_stations:
                continue
            if other.backoff is None:
                other.draw_backoff(self.rng)
            if other.backoff <= 0:
                continue
            t_ready = t0 + other.backoff * self.slot_us
            if t_ready < data_end:
                intruders.append((other, t_ready))

        if intruders:
            self._hidden_collision(q, intruders, t0, data_end)
            return

        seq = self._next_seq()
        self.events.append(AirEvent(t0, data_end, "data", q.mac, pf.dst,
                                    pf.mac_len, self.rate_mbps,
                                    retry=q.retransmits > 0, tid=pf.tid,
                                    seq=seq, payload=pf.payload))
        self.events.append(AirEvent(ack_start, ack_end, "ack", pf.dst, q.mac,
                                    14, self.ctrl_rate_mbps))
        q.airtime_us += data_us
        self.now = ack_end
        q.record_delay(self.now - pf.enqueue_time)
        q.frames.popleft()
        q.on_success()
        self._finished += 1
        self.channel_busy_us += self.now - t0

        # ---- TXOP 突发：SIFS 之后继续发，不用重新竞争
        if self.enable_txop and q.ac.txop_us > 0:
            self._txop_burst(q, t0)

    def _txop_burst(self, q: AcQueue, txop_start: float) -> None:
        """在 TXOP 窗口内连续发送（帧间隔只用 SIFS）。"""
        limit = txop_start + q.ac.txop_us
        while q.frames:
            pf = q.frames[0]
            data_us = self.data_airtime(pf.mac_len)
            ack_us = self.ack_airtime()
            need = self.sifs_us + data_us + self.sifs_us + ack_us
            if self.now + need > limit:
                break
            start = self.now + self.sifs_us
            end = start + data_us
            self.events.append(AirEvent(start, end, "data", q.mac, pf.dst,
                                        pf.mac_len, self.rate_mbps,
                                        tid=pf.tid, seq=self._next_seq(),
                                        payload=pf.payload))
            self.events.append(AirEvent(end + self.sifs_us,
                                        end + self.sifs_us + ack_us, "ack",
                                        pf.dst, q.mac, 14, self.ctrl_rate_mbps))
            q.airtime_us += data_us
            self.now = end + self.sifs_us + ack_us
            q.record_delay(self.now - pf.enqueue_time)
            q.frames.popleft()
            q.successes += 1
            self._finished += 1
            self.channel_busy_us += self.now - start
        q.txop_bursts += 1

    def _hidden_collision(self, winner: AcQueue,
                          intruders: Sequence[Tuple[AcQueue, float]],
                          t0: float, data_end: float) -> None:
        longest = data_end - t0
        for q, t in intruders:
            longest = max(longest, t - t0 + self.data_airtime(q.frames[0].mac_len))
        end = t0 + longest
        self.events.append(AirEvent(t0, min(end, data_end), "collision",
                                    winner.mac, winner.frames[0].dst,
                                    winner.frames[0].mac_len, self.rate_mbps,
                                    tid=winner.frames[0].tid,
                                    payload=winner.frames[0].payload, ok=False))
        winner.airtime_us += min(end, data_end) - t0
        for q, t in intruders:
            dur = self.data_airtime(q.frames[0].mac_len)
            self.events.append(AirEvent(t, t + dur, "collision", q.mac,
                                        q.frames[0].dst, q.frames[0].mac_len,
                                        self.rate_mbps, tid=q.frames[0].tid,
                                        payload=q.frames[0].payload, ok=False))
            q.airtime_us += dur
        self.now = end
        self._collision_trace.append({
            "t_us": round(t0, 2),
            "stations": [winner.key] + [q.key for q, _ in intruders],
            "reason": "hidden_terminal",
            "longest_us": round(longest, 2),
        })
        self._apply_collision_backoff([winner] + [q for q, _ in intruders])
        self.now += F.EIFS
        self.channel_busy_us += self.now - t0

    def _apply_collision_backoff(self, participants: Sequence[AcQueue]) -> None:
        for q in participants:
            q.on_collision()
            if q.retransmits > self.max_retries:
                q.frames.popleft()
                q.dropped += 1
                q.on_success()
                q.successes -= 1
                self._finished += 1

    def _transmit_collision(self, contenders: Sequence[AcQueue]) -> None:
        start = self.now
        longest = 0.0
        for q in contenders:
            dur = self.data_airtime(q.frames[0].mac_len)
            longest = max(longest, dur)
            self.events.append(AirEvent(start, start + dur, "collision", q.mac,
                                        q.frames[0].dst, q.frames[0].mac_len,
                                        self.rate_mbps, tid=q.frames[0].tid,
                                        payload=q.frames[0].payload, ok=False))
            q.airtime_us += dur
        self.now = start + longest
        self._collision_trace.append({
            "t_us": round(start, 2),
            "stations": [q.key for q in contenders],
            "reason": "same_slot",
            "longest_us": round(longest, 2),
        })
        self._apply_collision_backoff(contenders)
        self.now += F.EIFS
        self.channel_busy_us += self.now - start

    # ---------------------------------------------------------- 结果
    def result(self) -> Dict[str, object]:
        elapsed = self.now
        per_ac: Dict[str, Dict[str, object]] = {}
        for ac in ALL_ACS:
            qs = [q for q in self.queues if q.ac.name == ac.name]
            if not qs:
                continue
            succ = sum(q.successes for q in qs)
            coll = sum(q.collisions for q in qs)
            vcoll = sum(q.virtual_collisions for q in qs)
            delays: List[float] = []
            jitters: List[float] = []
            for q in qs:
                delays.extend(q.delays_us)
                jitters.extend(q.jitter_us)
            bytes_ok = sum(e.length for e in self.events
                           if e.kind == "data" and e.ok
                           and ac_for_tid(e.tid).name == ac.name)
            per_ac[ac.name] = {
                "ac": ac.name,
                "priority": ac.priority,
                "traffic": ac.traffic,
                "aifs_us": round(self.aifs_us(ac), 1),
                "cw_min": self._ac(ac).cw_min,
                "txop_us": self._ac(ac).txop_us,
                "successes": succ,
                "collisions": coll,
                "virtual_collisions": vcoll,
                "collision_rate": round(coll / (succ + coll), 4)
                    if (succ + coll) else 0.0,
                "throughput_mbps": round(bytes_ok * 8 / (elapsed * 1e-6) / 1e6, 4)
                    if elapsed else 0.0,
                "avg_delay_us": round(sum(delays) / len(delays), 2)
                    if delays else 0.0,
                "p95_delay_us": round(_percentile(delays, 0.95), 2)
                    if delays else 0.0,
                "max_delay_us": round(max(delays), 2) if delays else 0.0,
                "avg_jitter_us": round(sum(jitters) / len(jitters), 2)
                    if jitters else 0.0,
                "txop_bursts": sum(q.txop_bursts for q in qs),
                "dropped": sum(q.dropped for q in qs),
            }
        return {
            "seed": self.seed,
            "elapsed_us": round(elapsed, 1),
            "target_frames": self._target,
            "completed_frames": sum(q.successes for q in self.queues),
            "dropped_frames": sum(q.dropped for q in self.queues),
            "throughput_mbps": round(
                sum(e.length for e in self.events if e.kind == "data" and e.ok)
                * 8 / (elapsed * 1e-6) / 1e6, 4) if elapsed else 0.0,
            "channel_utilization": round(self.channel_busy_us / elapsed, 4)
                if elapsed else 0.0,
            "idle_slots": self.idle_slots,
            "per_ac": per_ac,
            "per_queue": [q.stats() for q in self.queues],
            "collision_trace": list(self._collision_trace),
        }

    def timeline(self) -> List[Dict[str, object]]:
        return [{
            "t_start_us": round(e.t_start, 2),
            "t_end_us": round(e.t_end, 2),
            "kind": e.kind,
            "src": e.src,
            "dst": e.dst,
            "length": e.length,
            "tid": e.tid,
            "ok": e.ok,
        } for e in self.events]

    def pcap_frames(self) -> List[Tuple[float, bytes]]:
        """导出 Radiotap + 802.11 pcap 帧（linktype 127）。

        每个 AC 的数据帧带自己的 TID，Wireshark 里可以用
        ``wlan.qos.tid`` 过滤出某一个接入类别。
        """
        out: List[Tuple[float, bytes]] = []
        for e in self.events:
            flags = F.RT_FLAG_FCS
            if not e.ok:
                flags |= F.RT_FLAG_BAD_FCS
            radio = F.Radiotap(tsft=int(e.t_start), flags=flags,
                               rate_mbps=e.rate_mbps, channel=6,
                               signal_dbm=-45)
            if e.kind == "data":
                mf = F.data_frame(e.src, e.dst, e.dst, e.payload,
                                  seq=e.seq, tid=e.tid,
                                  retry=int(e.retry))
            elif e.kind == "collision":
                mf = F.data_frame(e.src, e.dst, e.dst, e.payload,
                                  seq=0, tid=e.tid, retry=int(e.retry))
            elif e.kind == "ack":
                mf = F.ack_frame(e.dst)
            else:
                continue
            out.append((e.t_start / 1e6, F.build_frame(mf, radio)))
        return out


# ---------------------------------------------------------------- 场景
def build_edca_bss(n_stations: int = 3, seed: int = 42, **kwargs
                   ) -> Tuple[EdcaSimulator, str, List[str]]:
    """构造一个多业务 BSS：每个站点同时跑 VO/VI/BE/BK 四种流量。"""
    sim = EdcaSimulator(seed=seed, **kwargs)
    ap = sim.add_station("AP", "02:00:00:00:00:ff", x=0.0)
    sim.macs[ap] = "02:00:00:00:00:ff"
    stas = []
    for i in range(n_stations):
        name = f"STA-{chr(ord('A') + i)}"
        mac = f"02:00:00:00:00:{i + 1:02x}"
        sim.add_station(name, mac, x=(i + 1) * 20.0)
        sim.macs[name] = mac
        stas.append(name)
    return sim, ap, stas


def traffic_mix(sim: EdcaSimulator, stas: Sequence[str], dst_mac: str,
                n_vo: int = 100, n_vi: int = 60, n_be: int = 40,
                n_bk: int = 20) -> None:
    """给每个站点灌入混合业务。"""
    for name in stas:
        for _ in range(n_vo):
            sim.enqueue(name, AC_VO, dst_mac, 160, tid=6)
        for _ in range(n_vi):
            sim.enqueue(name, AC_VI, dst_mac, 1280, tid=5)
        for _ in range(n_be):
            sim.enqueue(name, AC_BE, dst_mac, 1500, tid=0)
        for _ in range(n_bk):
            sim.enqueue(name, AC_BK, dst_mac, 1500, tid=2)
