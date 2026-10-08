"""把耗时计算安全送回 Tkinter 主线程的最小工具。

Tkinter **不是线程安全的**，两条红线：

1. 后台线程不能碰控件和变量。
2. 后台线程也不能直接调 ``widget.after`` —— 会抛
   ``RuntimeError: main thread is not in main loop``。

这里用 ``queue.Queue`` 做桥：后台线程只往队列里放结果，
主线程轮询 drain。

有一个容易踩的坑值得单独记一笔：如果 drain 只排一次 ``after``，
而计算耗时超过那个间隔（本项目的 pcap 导出要 1.8 秒、图表要 1.2 秒），
drain 会先跑到、看到队列是空的就返回，**结果就永远留在队列里没人取**。
所以 drain 必须自己继续排下一次，直到所有 job 都回来了。
"""

from __future__ import annotations

import queue
import threading
from typing import Any, Callable, Optional

_DONE = Callable[[Any], None]
_ERROR = Callable[[str], None]

_POLL_MS = 40


class Jobs:
    """一个主线程安全的后台任务调度器。"""

    def __init__(self, master: Any) -> None:
        self._master = master
        self._q: "queue.Queue[tuple]" = queue.Queue()
        self._pending = 0

    def submit(self, work: Callable[[], Any], on_ok: Optional[_DONE] = None,
               on_error: Optional[_ERROR] = None, tag: str = "") -> None:
        """在后台线程跑 ``work``，结果回主线程交给 ``on_ok``。"""
        self._pending += 1

        def run() -> None:
            try:
                self._q.put(("ok", on_ok, work()))
            except Exception as exc:  # noqa: BLE001 —— 线程不能静默死掉
                self._q.put(("err", on_error,
                             f"{tag}: {exc}" if tag else str(exc)))
            finally:
                # 先入队再减计数：drain 看到 _pending == 0 时，
                # 结果一定已经在队列里了。
                self._pending -= 1

        threading.Thread(target=run, daemon=True).start()
        self._master.after(_POLL_MS, self._drain)

    def _drain(self) -> None:
        while True:
            try:
                _kind, cb, payload = self._q.get_nowait()
            except queue.Empty:
                break
            if cb is not None:
                cb(payload)
        if self._pending > 0:
            self._master.after(_POLL_MS, self._drain)
