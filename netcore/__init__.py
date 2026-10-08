"""netcore —— 计算机网络课程设计共享核心库。

模块地图：

======================  ====================================================
:mod:`netcore.clock`    离散事件虚拟时钟（可复现仿真）
:mod:`netcore.packet`   Ethernet / IPv4 / TCP / UDP 报文编解码与校验和
:mod:`netcore.pcap`     pcap 读写 + Wireshark/tshark 集成
:mod:`netcore.dissect`  内置协议解析器（复刻 Wireshark TCP 分析）
:mod:`netcore.link`     链路仿真：时延 / 丢包 / 限速 / 队列 / AQM
:mod:`netcore.crypto`   密码学原语封装（AEAD / X25519 / HKDF）
:mod:`netcore.viz`      统一风格的可视化
:mod:`netcore.testkit`  测试与实验脚手架
======================  ====================================================
"""

__version__ = "1.0.0"

from .clock import SimClock, Event  # noqa: F401
from . import packet, pcap, dissect, link, crypto, viz, testkit  # noqa: F401

__all__ = [
    "SimClock", "Event",
    "packet", "pcap", "dissect", "link", "crypto", "viz", "testkit",
    "__version__",
]
