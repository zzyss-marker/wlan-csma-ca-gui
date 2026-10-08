"""802.11 物理层参数与"空口时间"（airtime）计算。

**为什么空口时间比速率更重要**：
802.11 是共享介质，一个帧占用的时间 = 前导码 + PLCP 头 + 数据符号 + 帧间间隔。
在 54 Mbps 下，一个 1500 字节的帧只需要 222 us 传数据，但要额外花
20 us 前导码 + 4 us SIGNAL + 16 us SIFS + 44 us ACK ≈ 84 us 的固定开销。
**固定开销占了 27%**——这就是为什么小包在 WiFi 上效率极低。

本模块提供：

* 802.11a/g OFDM 的 8 个速率与每符号比特数（NDBPS）
* 802.11n HT 单空间流的 8 个 MCS
* :func:`airtime_us` —— 一个帧在空口上占用的微秒数
* :func:`ack_airtime_us` / :func:`rts_cts_airtime_us`
* :func:`efficiency` —— 有效吞吐 / 标称速率
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------- OFDM 参数
PREAMBLE_LONG_US = 20.0        # 长前导码
PREAMBLE_SHORT_US = 16.0       # 短前导码（ERP-OFDM short slot）
SIGNAL_FIELD_US = 4.0          # PLCP SIGNAL 字段（24 bit @ 6 Mbps）
OFDM_SYMBOL_US = 4.0           # OFDM 符号时长
SERVICE_TAIL_BITS = 22         # 16 bit SERVICE + 6 bit tail
FCS_BYTES = 4

#: 速率(Mbps) -> 每符号数据比特数（NDBPS）
NDBPS: Dict[float, int] = {
    6.0: 24, 9.0: 36, 12.0: 48, 18.0: 72,
    24.0: 96, 36.0: 144, 48.0: 192, 54.0: 216,
}

#: 802.11n HT20 单空间流 MCS -> (速率 Mbps, NDBPS)，800ns GI
HT_MCS: Dict[int, Tuple[float, int]] = {
    0: (6.5, 26), 1: (13.0, 52), 2: (19.5, 78), 3: (26.0, 104),
    4: (39.0, 156), 5: (52.0, 208), 6: (58.5, 234), 7: (65.0, 260),
}


def rate_name(rate_mbps: float) -> str:
    if rate_mbps in NDBPS:
        return f"{rate_mbps:g} Mbps (legacy OFDM)"
    for mcs, (r, _n) in HT_MCS.items():
        if abs(r - rate_mbps) < 1e-6:
            return f"MCS{mcs} HT20 {r:g} Mbps"
    return f"{rate_mbps:g} Mbps"


def airtime_us(length_bytes: int, rate_mbps: float = 54.0,
               preamble_us: float = PREAMBLE_LONG_US,
               include_fcs: bool = True) -> float:
    """一个 PSDU 在空口上占用的微秒数。

    ``length_bytes`` 是 MAC 帧长度（不含 FCS 时由 ``include_fcs`` 决定是否加 4）。
    """
    if rate_mbps in NDBPS:
        ndbps = NDBPS[rate_mbps]
    else:
        ndbps = None
        for _mcs, (r, n) in HT_MCS.items():
            if abs(r - rate_mbps) < 1e-6:
                ndbps = n
                break
        if ndbps is None:
            raise ValueError(f"未知速率 {rate_mbps} Mbps")
    n = length_bytes + (FCS_BYTES if include_fcs else 0)
    bits = SERVICE_TAIL_BITS + 8 * n
    symbols = math.ceil(bits / ndbps)
    return preamble_us + SIGNAL_FIELD_US + symbols * OFDM_SYMBOL_US


def ack_airtime_us(rate_mbps: float = 24.0,
                   preamble_us: float = PREAMBLE_LONG_US) -> float:
    """ACK 控制帧（14 字节）的空口时间。

    802.11 规定 ACK 用**基本速率集**里的一种速率发送，通常 24 Mbps 或 6 Mbps。
    """
    return airtime_us(14, rate_mbps, preamble_us)


def cts_airtime_us(rate_mbps: float = 24.0,
                   preamble_us: float = PREAMBLE_LONG_US) -> float:
    return airtime_us(14, rate_mbps, preamble_us)


def rts_airtime_us(rate_mbps: float = 24.0,
                   preamble_us: float = PREAMBLE_LONG_US) -> float:
    return airtime_us(20, rate_mbps, preamble_us)


def efficiency(length_bytes: int, rate_mbps: float = 54.0,
               slot_us: float = 9.0, sifs_us: float = 16.0,
               difs_us: float = 34.0, backoff_slots: float = 7.5,
               ack_rate_mbps: float = 24.0) -> float:
    """单帧的"有效吞吐 / 标称速率"。

    分母 = 退避均值 + DIFS + 数据空口时间 + SIFS + ACK 空口时间。
    ``backoff_slots`` 默认取 CWmin/2 = 7.5（饱和条件下的平均值）。
    """
    data_us = airtime_us(length_bytes, rate_mbps)
    ack_us = ack_airtime_us(ack_rate_mbps)
    total = (backoff_slots * slot_us + difs_us + data_us + sifs_us + ack_us)
    goodput_mbps = (length_bytes * 8) / (total * 1e-6) / 1e6
    return goodput_mbps / rate_mbps


def goodput_mbps(length_bytes: int, rate_mbps: float = 54.0,
                 **kwargs) -> float:
    """单帧的有效吞吐（Mbps）。"""
    eff = efficiency(length_bytes, rate_mbps, **kwargs)
    return eff * rate_mbps


@dataclass
class FrameTiming:
    """一次完整的数据帧交换（含 ACK）的时间分解。"""

    data_us: float
    ack_us: float
    sifs_us: float
    difs_us: float
    backoff_us: float

    @property
    def total_us(self) -> float:
        return (self.data_us + self.ack_us + self.sifs_us + self.difs_us
                + self.backoff_us)

    def describe(self) -> str:
        return (f"data={self.data_us:.1f}us ack={self.ack_us:.1f}us "
                f"sifs={self.sifs_us:.1f} difs={self.difs_us:.1f} "
                f"backoff={self.backoff_us:.1f} -> total={self.total_us:.1f}us")


def timing_breakdown(length_bytes: int, rate_mbps: float = 54.0,
                     backoff_slots: float = 7.5, slot_us: float = 9.0,
                     sifs_us: float = 16.0, difs_us: float = 34.0,
                     ack_rate_mbps: float = 24.0) -> FrameTiming:
    return FrameTiming(
        data_us=airtime_us(length_bytes, rate_mbps),
        ack_us=ack_airtime_us(ack_rate_mbps),
        sifs_us=sifs_us,
        difs_us=difs_us,
        backoff_us=backoff_slots * slot_us,
    )


def rts_cts_overhead_us(data_len: int, rate_mbps: float = 54.0,
                        ctrl_rate_mbps: float = 24.0,
                        sifs_us: float = 16.0,
                        rts_threshold: int = 2347) -> float:
    """RTS/CTS 相对基本接入方式**额外**增加的空口时间（us）。

    返回正数表示 RTS/CTS 更慢；返回 0 表示不启用。
    """
    if data_len <= rts_threshold:
        return 0.0
    return (rts_airtime_us(ctrl_rate_mbps) + sifs_us
            + cts_airtime_us(ctrl_rate_mbps) + sifs_us)


def rate_scan(length_bytes: int = 1500,
              rates: Optional[List[float]] = None) -> List[Tuple[float, float, float]]:
    """扫描各速率，返回 ``[(速率, 空口时间us, 有效吞吐Mbps), ...]``。"""
    rates = rates or sorted(NDBPS)
    out = []
    for r in rates:
        t = airtime_us(length_bytes, r)
        good = (length_bytes * 8) / (t * 1e-6) / 1e6
        out.append((r, t, good))
    return out


def size_scan(sizes: Optional[List[int]] = None,
              rate_mbps: float = 54.0) -> List[Tuple[int, float, float]]:
    """扫描帧长，返回 ``[(帧长, 空口时间us, 有效吞吐Mbps), ...]``。"""
    sizes = sizes or [64, 128, 256, 512, 1024, 1500, 2304]
    out = []
    for s in sizes:
        t = airtime_us(s, rate_mbps)
        good = (s * 8) / (t * 1e-6) / 1e6
        out.append((s, t, good))
    return out


def aggregation_gain(n_frames: int, frame_len: int = 1500,
                     rate_mbps: float = 65.0) -> float:
    """A-MPDU 聚合的吞吐增益：n 个帧共用一个前导码 + PLCP 头。

    返回 ``聚合后吞吐 / 单帧逐个发送吞吐``。
    """
    if n_frames < 1:
        raise ValueError("n_frames 必须 >= 1")
    single = airtime_us(frame_len, rate_mbps)
    agg = airtime_us(n_frames * frame_len, rate_mbps)
    return (single * n_frames) / agg
