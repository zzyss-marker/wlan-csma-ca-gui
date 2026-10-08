"""虚拟时钟与事件调度器。

整个实验平台是**事件驱动**的：协议栈不占用任何线程，所有定时器
（重传超时 RTO、延迟 ACK、pacing、TIME_WAIT）都通过 :meth:`SimClock.schedule`
注册回调。这样做有三个直接好处：

1. **可复现**——同一随机种子下，仿真逐包、逐时刻完全一致，实验结果可被复现；
2. **快**——虚拟时间可以跑得比真实时间快几个数量级，便于做参数扫描；
3. **同一份协议栈代码**既能跑在虚拟链路上，也能跑在真实 UDP 隧道上（见 ``link.py``）。

虚拟时间用 ``float`` 秒表示，绝对精度足够（双精度在 1e6 秒量级仍有 ~1e-10 分辨率）。
"""

from __future__ import annotations

import heapq
import itertools
from typing import Callable, List, Optional


class Event:
    """事件队列中的一个待执行回调。"""

    __slots__ = ("time", "seq", "fn", "cancelled")

    def __init__(self, time: float, seq: int, fn: Callable[[], None]) -> None:
        self.time = time
        self.seq = seq
        self.fn = fn
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True

    def __lt__(self, other: "Event") -> bool:
        # 先比时间，再比注册序号，保证同刻事件 FIFO 且排序稳定
        return (self.time, self.seq) < (other.time, other.seq)

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"<Event t={self.time:.6f} #{self.seq} cancelled={self.cancelled}>"


class SimClock:
    """离散事件虚拟时钟。

    ``seq`` 单调递增，保证同一时刻的事件按注册顺序（FIFO）执行，
    避免堆排序不稳定导致的不可复现。
    """

    def __init__(self, epoch: float = 0.0) -> None:
        self._now: float = epoch
        self._queue: List[Event] = []
        self._seq = itertools.count()
        self.events_fired = 0

    # ------------------------------------------------------------------ 时间
    @property
    def now(self) -> float:
        """当前虚拟时间（秒）。"""
        return self._now

    # ------------------------------------------------------------------ 调度
    def schedule(self, delay: float, fn: Callable[[], None]) -> Event:
        """在 ``delay`` 虚拟秒之后执行 ``fn``。``delay <= 0`` 表示当前时刻的下一轮。"""
        ev = Event(self._now + (delay if delay > 0.0 else 0.0), next(self._seq), fn)
        heapq.heappush(self._queue, ev)
        return ev

    def call_at(self, when: float, fn: Callable[[], None]) -> Event:
        """在绝对虚拟时刻 ``when`` 执行 ``fn``。"""
        ev = Event(when if when > self._now else self._now, next(self._seq), fn)
        heapq.heappush(self._queue, ev)
        return ev

    def pending(self) -> int:
        """队列中尚未执行的事件数。"""
        return len(self._queue)

    # ------------------------------------------------------------------ 驱动
    def run(self, until: Optional[float] = None, max_events: int = 20_000_000) -> int:
        """推进虚拟时间，直到队列为空或超过 ``until``。返回实际执行的事件数。"""
        deadline = float("inf") if until is None else until
        fired = 0
        while self._queue:
            ev = self._queue[0]
            if ev.time > deadline:
                self._now = deadline
                break
            heapq.heappop(self._queue)
            if ev.cancelled:
                continue
            self._now = ev.time
            ev.fn()
            fired += 1
            if fired >= max_events:
                break
        self.events_fired += fired
        return fired
