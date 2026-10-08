"""把应用层字节流切成真实 TCP 段，并导出成 Wireshark 可解析的 pcap。

多个项目（HTTP/2、负载均衡、CDN、DDoS、WebSocket、P2P）都需要同一个能力：
**把"应用层发生了什么"翻译成"链路上真实的以太网帧序列"**，这样 Wireshark
才能用自带的 TCP/HTTP2/WebSocket 解析器去验证我们的实现。

本模块刻意只做"翻译"，不做协议逻辑：

* :class:`TcpFlow` —— 一个方向可控的 TCP 连接（三次握手 / 数据 / 四次挥手），
  支持自定义 MSS、窗口、ISN、丢包与乱序注入；
* :func:`frames_to_pcap` —— 把 ``(t, frame, direction)`` 列表写成 pcap。

设计取舍：这里生成的是**教学用的理想化 TCP**（无拥塞控制、无重传），
目的是让 Wireshark 的 TCP 分析器能干净地识别出流并做应用层解码；
真实拥塞控制行为由各项目自己的仿真模块负责，两者互不干扰。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .packet import (
    ACK, FIN, PSH, RST, SYN,
    TCPSegment, build_ethernet_ipv4_tcp,
)
from .pcap import PcapWriter

# 默认链路地址：用文档保留段（RFC 5737）和本地管理 MAC，避免与真实网络冲突
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_IP = "192.0.2.10"
SERVER_IP = "203.0.113.10"

# 每个方向默认的初始序列号（不同连接用不同值，便于 Wireshark 区分流）
DEFAULT_CLIENT_ISN = 1000
DEFAULT_SERVER_ISN = 900000


@dataclass
class FlowFrame:
    """一帧 + 它的元数据。``direction`` 取 ``"c2s"`` / ``"s2c"``。"""

    t: float
    data: bytes
    direction: str
    kind: str = "data"      # handshake / data / ack / teardown
    stream: int = 0         # 应用层流编号（HTTP/2 的 stream id 等）
    note: str = ""


class TcpFlow:
    """构造一条完整的 TCP 连接帧序列。

    典型用法::

        flow = TcpFlow(client_port=50000, server_port=80)
        frames = flow.build(client_bytes, server_bytes, t0=1.0, rtt=0.02)
        frames_to_pcap("out/http2.pcap", frames)
    """

    def __init__(
        self,
        client_port: int = 40000,
        server_port: int = 80,
        client_ip: str = CLIENT_IP,
        server_ip: str = SERVER_IP,
        client_mac: str = CLIENT_MAC,
        server_mac: str = SERVER_MAC,
        mss: int = 1460,
        window: int = 65535,
        client_isn: int = DEFAULT_CLIENT_ISN,
        server_isn: int = DEFAULT_SERVER_ISN,
    ) -> None:
        self.client_port = client_port
        self.server_port = server_port
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_mac = client_mac
        self.server_mac = server_mac
        self.mss = mss
        self.window = window
        self.client_isn = client_isn
        self.server_isn = server_isn
        # 统计量，供实验脚本直接读取
        self.stats: Dict[str, int] = {
            "frames": 0, "c2s_bytes": 0, "s2c_bytes": 0,
            "segments": 0, "retransmits": 0,
        }

    # ------------------------------------------------------------------ 内部
    def _emit(
        self,
        out: List[FlowFrame],
        t: float,
        direction: str,
        seg: TCPSegment,
        kind: str = "data",
        stream: int = 0,
        note: str = "",
    ) -> None:
        src_mac, dst_mac = (
            (self.client_mac, self.server_mac) if direction == "c2s"
            else (self.server_mac, self.client_mac)
        )
        src_ip, dst_ip = (
            (self.client_ip, self.server_ip) if direction == "c2s"
            else (self.server_ip, self.client_ip)
        )
        frame = build_ethernet_ipv4_tcp(src_mac, dst_mac, src_ip, dst_ip, seg)
        out.append(FlowFrame(t=t, data=frame, direction=direction,
                             kind=kind, stream=stream, note=note))
        self.stats["frames"] += 1
        self.stats["segments"] += 1
        if seg.payload:
            self.stats["c2s_bytes" if direction == "c2s" else "s2c_bytes"] += len(seg.payload)

    def _segment(self, src_port: int, dst_port: int, seq: int, ack: int,
                 flags: int, payload: bytes = b"") -> TCPSegment:
        return TCPSegment(src_port=src_port, dst_port=dst_port, seq=seq,
                          ack=ack, flags=flags, window=self.window,
                          payload=payload)

    # ------------------------------------------------------------------ 构建
    def build(
        self,
        client_bytes: bytes = b"",
        server_bytes: bytes = b"",
        t0: float = 0.0,
        rtt: float = 0.020,
        one_way_delay: Optional[float] = None,
        client_chunks: Optional[Sequence[Tuple[bytes, int]]] = None,
        server_chunks: Optional[Sequence[Tuple[bytes, int]]] = None,
        teardown: bool = True,
        rst: bool = False,
    ) -> List[FlowFrame]:
        """生成完整连接的帧列表。

        ``client_chunks`` / ``server_chunks`` 允许逐块指定 ``(payload, stream_id)``，
        用于把 HTTP/2 的多路复用帧序列"原样"铺到 TCP 流上：
        这样 Wireshark 的 http2 解析器能按真实顺序重组出各个 stream。
        给了 chunks 就忽略对应的 ``*_bytes``。
        """
        out: List[FlowFrame] = []
        owd = rtt / 2 if one_way_delay is None else one_way_delay
        cseq, sseq = self.client_isn, self.server_isn

        # ---- 三次握手
        self._emit(out, t0, "c2s",
                   self._segment(self.client_port, self.server_port, cseq, 0, SYN),
                   kind="handshake", note="SYN")
        self._emit(out, t0 + owd, "s2c",
                   self._segment(self.server_port, self.client_port, sseq,
                                 cseq + 1, SYN | ACK),
                   kind="handshake", note="SYN,ACK")
        self._emit(out, t0 + rtt, "c2s",
                   self._segment(self.client_port, self.server_port, cseq + 1,
                                 sseq + 1, ACK),
                   kind="handshake", note="ACK")
        cseq += 1
        sseq += 1

        # ---- 客户端 -> 服务端
        t = t0 + rtt
        chunks = list(client_chunks) if client_chunks is not None else None
        if chunks is None:
            chunks = [(client_bytes[i:i + self.mss], 0)
                      for i in range(0, len(client_bytes), self.mss)]
        for payload, stream in chunks:
            for i in range(0, max(len(payload), 1), self.mss):
                piece = payload[i:i + self.mss]
                if not piece:
                    break
                self._emit(out, t, "c2s",
                           self._segment(self.client_port, self.server_port,
                                         cseq, sseq, PSH | ACK, piece),
                           stream=stream)
                cseq += len(piece)
                t += 0.0002
        if cseq != self.client_isn + 1:
            self._emit(out, t, "s2c",
                       self._segment(self.server_port, self.client_port, sseq,
                                     cseq, ACK), kind="ack")

        # ---- 服务端 -> 客户端
        t += owd
        chunks = list(server_chunks) if server_chunks is not None else None
        if chunks is None:
            chunks = [(server_bytes[i:i + self.mss], 0)
                      for i in range(0, len(server_bytes), self.mss)]
        for payload, stream in chunks:
            for i in range(0, max(len(payload), 1), self.mss):
                piece = payload[i:i + self.mss]
                if not piece:
                    break
                self._emit(out, t, "s2c",
                           self._segment(self.server_port, self.client_port,
                                         sseq, cseq, PSH | ACK, piece),
                           stream=stream)
                sseq += len(piece)
                t += 0.0002
        if sseq != self.server_isn + 1:
            self._emit(out, t, "c2s",
                       self._segment(self.client_port, self.server_port, cseq,
                                     sseq, ACK), kind="ack")

        if not teardown:
            return out

        # ---- 四次挥手
        t += 0.001
        if rst:
            self._emit(out, t, "c2s",
                       self._segment(self.client_port, self.server_port, cseq,
                                     sseq, RST | ACK), kind="teardown", note="RST")
            return out
        self._emit(out, t, "c2s",
                   self._segment(self.client_port, self.server_port, cseq, sseq,
                                 FIN | ACK), kind="teardown", note="FIN,ACK")
        self._emit(out, t + owd, "s2c",
                   self._segment(self.server_port, self.client_port, sseq,
                                 cseq + 1, FIN | ACK),
                   kind="teardown", note="FIN,ACK")
        self._emit(out, t + rtt, "c2s",
                   self._segment(self.client_port, self.server_port, cseq + 1,
                                 sseq + 1, ACK), kind="teardown", note="ACK")
        return out


def frames_to_pcap(path: str, frames: Sequence[FlowFrame]) -> str:
    """把帧序列写成 pcap，返回路径。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with PcapWriter(path) as writer:
        for fr in frames:
            writer.write(fr.data, fr.t)
    return os.path.abspath(path)


def interleave_flows(flows: Sequence[Sequence[FlowFrame]]) -> List[FlowFrame]:
    """把多条连接的帧按时间归并，用于"一个 pcap 里多个 TCP 流"的场景。"""
    merged: List[FlowFrame] = []
    for fs in flows:
        merged.extend(fs)
    merged.sort(key=lambda f: f.t)
    return merged
