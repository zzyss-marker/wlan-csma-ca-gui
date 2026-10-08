"""链路层仿真：传播时延 / 抖动 / 丢包 / 限速 / 排队 / AQM / 重排。

模型采用**流化串行服务器 + 有限缓冲队列**，这是网络测量与传输层研究中
最常用的抽象（与 ns-3 的 ``PointToPointNetDevice`` + ``DropTailQueue`` 同构）：

1. 分组到达链路后先排队。队列按字节计量，占用长度等于
   ``尚未开始串行化的数据量`` = ``(busy_until - now) * rate``。
2. 队列溢出即丢包（tail drop），或交给 AQM（CoDel / RED）提前丢弃，
   用于演示 **bufferbloat** 及其缓解。
3. 串行化时延 = ``len(frame) * 8 / rate``；传播时延 = ``delay + jitter``。
4. 可选 Gilbert-Elliott 突发丢包模型，模拟无线链路的成簇丢包。

所有时间都走 :class:`netcore.clock.SimClock`，因此仿真完全可复现。
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional


@dataclass
class LinkStats:
    """链路累计统计。"""

    sent: int = 0
    delivered: int = 0
    dropped_loss: int = 0
    dropped_queue: int = 0
    dropped_aqm: int = 0
    bytes_sent: int = 0
    bytes_delivered: int = 0
    max_queue_bytes: float = 0.0
    sum_queue_delay: float = 0.0

    @property
    def loss_rate(self) -> float:
        return (self.dropped_loss + self.dropped_queue + self.dropped_aqm) / self.sent if self.sent else 0.0

    @property
    def mean_queue_delay(self) -> float:
        return self.sum_queue_delay / self.delivered if self.delivered else 0.0


class GilbertElliott:
    """两状态突发丢包模型（好状态/坏状态马尔可夫链）。"""

    def __init__(self, p_good_to_bad: float, p_bad_to_good: float,
                 loss_good: float, loss_bad: float, rng: random.Random) -> None:
        self.p_gb = p_good_to_bad
        self.p_bg = p_bad_to_good
        self.loss_good = loss_good
        self.loss_bad = loss_bad
        self.rng = rng
        self.bad = False

    def drop(self) -> bool:
        if self.bad:
            if self.rng.random() < self.p_bg:
                self.bad = False
        else:
            if self.rng.random() < self.p_gb:
                self.bad = True
        p = self.loss_bad if self.bad else self.loss_good
        return self.rng.random() < p


class CoDel:
    """CoDel AQM（RFC 8289 的简化实现）。

    核心思想：只要**排队时延**持续超过 ``target`` 达 ``interval`` 秒，
    就进入丢弃状态并按 ``1/sqrt(count)`` 的节奏丢包，从而在不牺牲吞吐的前提下
    把 standing queue 压掉。用于演示 bufferbloat 的解法。
    """

    def __init__(self, target: float = 0.005, interval: float = 0.1,
                 max_drop_rate: float = 0.5) -> None:
        self.target = target
        self.interval = interval
        self.max_drop_rate = max_drop_rate
        self._first_above: Optional[float] = None
        self._drop_next: Optional[float] = None
        self._count = 0
        self.dropping = False

    def should_drop(self, now: float, sojourn: float) -> bool:
        if sojourn < self.target:
            self._first_above = None
            self.dropping = False
            self._count = 0
            return False
        if self._first_above is None:
            self._first_above = now
        if now - self._first_above < self.interval:
            return False
        if not self.dropping:
            self.dropping = True
            self._count = 1
            self._drop_next = now
            return True
        if self._drop_next is not None and now >= self._drop_next:
            self._count += 1
            gap = self.interval / (self._count ** 0.5)
            gap = max(gap, 1.0 / self.max_drop_rate * 0.0 + 0.0005)
            self._drop_next = now + gap
            return True
        return False


class Link:
    """单向链路。``on_deliver(data, meta)`` 在分组到达对端时被调用。"""

    def __init__(
        self,
        clock,
        rate_bps: float = 10_000_000,
        delay: float = 0.01,
        jitter: float = 0.0,
        loss: float = 0.0,
        queue_bytes: float = 64_000,
        reorder: float = 0.0,
        seed: int = 1,
        name: str = "link",
        on_deliver: Optional[Callable[[bytes, dict], None]] = None,
        aqm: str = "tail",
        burst: Optional[Dict[str, float]] = None,
    ) -> None:
        self.clock = clock
        self.rate_bps = float(rate_bps)
        self.delay = float(delay)
        self.jitter = float(jitter)
        self.loss = float(loss)
        self.queue_bytes = float(queue_bytes)
        self.reorder = float(reorder)
        self.name = name
        self.on_deliver = on_deliver
        self.rng = random.Random(seed)
        self.stats = LinkStats()
        self._busy_until = 0.0
        self._ge = GilbertElliott(**burst, rng=self.rng) if burst else None
        self.aqm = CoDel() if aqm == "codel" else None
        self.aqm_name = aqm

    # ---------------------------------------------------------------- 属性
    @property
    def rate_bytes(self) -> float:
        return self.rate_bps / 8.0

    def queue_occupancy(self, now: Optional[float] = None) -> float:
        """当前排队字节数（尚未开始串行化的数据）。"""
        now = self.clock.now if now is None else now
        return max(0.0, self._busy_until - now) * self.rate_bytes

    def queue_delay(self, now: Optional[float] = None) -> float:
        """当前排队时延（秒）。"""
        now = self.clock.now if now is None else now
        return max(0.0, self._busy_until - now)

    # ---------------------------------------------------------------- 发送
    def send(self, data: bytes, meta: Optional[dict] = None) -> bool:
        """把 ``data`` 交给链路。返回 False 表示被丢弃。"""
        now = self.clock.now
        size = len(data)
        self.stats.sent += 1
        self.stats.bytes_sent += size

        # 1) 队列检查（tail drop）
        backlog = self.queue_occupancy(now)
        if backlog + size > self.queue_bytes:
            self.stats.dropped_queue += 1
            return False

        # 2) AQM 检查
        if self.aqm is not None and self.aqm.should_drop(now, backlog / self.rate_bytes):
            self.stats.dropped_aqm += 1
            return False

        # 3) 随机丢包
        dropped = self._ge.drop() if self._ge is not None else (self.rng.random() < self.loss)
        if dropped:
            self.stats.dropped_loss += 1
            return False

        # 4) 串行化 + 传播
        start = max(now, self._busy_until)
        serialize = size / self.rate_bytes
        self._busy_until = start + serialize
        queue_delay = start - now
        self.stats.sum_queue_delay += queue_delay
        self.stats.max_queue_bytes = max(self.stats.max_queue_bytes, backlog + size)

        prop = self.delay
        if self.jitter:
            prop += self.rng.uniform(-self.jitter, self.jitter)
        if prop < 0:
            prop = 0.0
        if self.reorder and self.rng.random() < self.reorder:
            prop += self.rng.uniform(0.0, max(self.delay, 0.001))

        arrival_delay = (start + serialize + prop) - now

        info = dict(meta or {})
        info.update({"queue_delay": queue_delay, "prop_delay": prop,
                     "link": self.name, "size": size})

        def _deliver() -> None:
            self.stats.delivered += 1
            self.stats.bytes_delivered += size
            if self.on_deliver is not None:
                self.on_deliver(data, info)

        self.clock.schedule(arrival_delay, _deliver)
        return True


class LinkPair:
    """双向链路，两个方向参数可独立配置。"""

    def __init__(self, clock, seed: int = 1, **kwargs) -> None:
        ab_kwargs = dict(kwargs)
        ba_kwargs = dict(kwargs)
        ba_kwargs["seed"] = seed + 1
        self.ab = Link(clock, name="A->B", seed=seed, **ab_kwargs)
        self.ba = Link(clock, name="B->A", **ba_kwargs)

    @property
    def rtt(self) -> float:
        """基础往返传播时延（不含排队）。"""
        return self.ab.delay + self.ba.delay

    @property
    def bandwidth(self) -> float:
        """瓶颈带宽（bps）。"""
        return min(self.ab.rate_bps, self.ba.rate_bps)

    @property
    def bdp_bytes(self) -> float:
        """带宽时延积（字节）。"""
        return self.bandwidth / 8.0 * self.rtt

    def stats(self) -> Dict[str, LinkStats]:
        return {"A->B": self.ab.stats, "B->A": self.ba.stats}
