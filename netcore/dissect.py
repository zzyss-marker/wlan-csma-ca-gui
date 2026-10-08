"""内置协议解析器 —— 用纯 Python 复刻 Wireshark 的核心分析能力。

为什么需要它？课程设计里"用 Wireshark 验证协议栈"通常靠肉眼看，
无法写进自动化测试。本模块把 Wireshark 的两项关键能力用 Python 复刻出来：

* :func:`summary_line` —— 复刻 Wireshark 报文列表的一行摘要；
* :func:`analyze_tcp` —— 复刻 ``tcp.analysis.flags``（重传 / 快速重传 /
  乱序 / 重复 ACK / 零窗口 / 窗口更新），并可导出 ``follow tcp stream``。

于是"协议实现是否正确"这件事可以写成断言，进入 CI。
真实 Wireshark 仍然可以用（见 :mod:`netcore.pcap` 的 tshark 集成），
两者互为交叉验证。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .packet import (
    ACK, FIN, PSH, RST, SYN, PROTO_TCP, PROTO_UDP,
    TCPSegment, UDPSegment, flags_to_str, parse_ethernet,
)
from .pcap import CapturedPacket, read_pcap


@dataclass
class Dissected:
    """一条报文的解析结果。"""

    index: int
    ts: float
    frame_len: int
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    proto: str = ""
    src_port: int = 0
    dst_port: int = 0
    tcp: Optional[TCPSegment] = None
    udp: Optional[UDPSegment] = None
    analysis: List[str] = field(default_factory=list)

    @property
    def flow_key(self) -> Tuple:
        """双向流的规范键（小端在前），用于把两个方向归到同一条流。"""
        a = (self.src_ip, self.src_port)
        b = (self.dst_ip, self.dst_port)
        return (a, b) if a <= b else (b, a)

    @property
    def direction_key(self) -> Tuple:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)


def dissect_packet(data: bytes, index: int = 0, ts: float = 0.0) -> Dissected:
    """解析一个以太网帧。"""
    d = Dissected(index=index, ts=ts, frame_len=len(data))
    frame, ip, seg = parse_ethernet(data)
    d.src_mac, d.dst_mac = frame.src_mac, frame.dst_mac
    if ip is None:
        d.proto = "NON-IP"
        return d
    d.src_ip, d.dst_ip = ip.src, ip.dst
    if ip.proto == PROTO_TCP and isinstance(seg, TCPSegment):
        d.proto, d.tcp = "TCP", seg
        d.src_port, d.dst_port = seg.src_port, seg.dst_port
    elif ip.proto == PROTO_UDP and isinstance(seg, UDPSegment):
        d.proto, d.udp = "UDP", seg
        d.src_port, d.dst_port = seg.src_port, seg.dst_port
    else:
        d.proto = f"IP/{ip.proto}"
    return d


def load_pcap(path: str) -> List[Dissected]:
    """读取 pcap 并解析成 :class:`Dissected` 列表。"""
    _lt, packets = read_pcap(path)
    return [dissect_packet(p.data, i + 1, p.ts) for i, p in enumerate(packets)]


# ------------------------------------------------------------------ 摘要行
def summary_line(d: Dissected) -> str:
    """输出 Wireshark 报文列表风格的摘要行。"""
    if d.proto == "TCP" and d.tcp is not None:
        s = d.tcp
        info = (f"{d.src_port} \u2192 {d.dst_port} [{flags_to_str(s.flags)}] "
                f"Seq={s.seq} Ack={s.ack} Win={s.window} Len={len(s.payload)}")
        opt = s.options.describe()
        if opt:
            info += " " + opt
        if d.analysis:
            info += "  \u3010" + " / ".join(d.analysis) + "\u3011"
        return (f"{d.index:5d} {d.ts:>12.6f} {d.src_ip:>15} \u2192 {d.dst_ip:<15} "
                f"TCP {d.frame_len:4d} {info}")
    if d.proto == "UDP" and d.udp is not None:
        info = f"{d.src_port} \u2192 {d.dst_port} Len={len(d.udp.payload)}"
        return (f"{d.index:5d} {d.ts:>12.6f} {d.src_ip:>15} \u2192 {d.dst_ip:<15} "
                f"UDP {d.frame_len:4d} {info}")
    return (f"{d.index:5d} {d.ts:>12.6f} {d.src_ip:>15} \u2192 {d.dst_ip:<15} "
            f"{d.proto} {d.frame_len:4d}")


def print_pcap(path: str, limit: int = 0, display_filter: str = "") -> int:
    """打印整个 pcap（类似 ``tshark -r``）。返回打印行数。"""
    items = load_pcap(path)
    if display_filter:
        items = [d for d in items if display_filter in summary_line(d)]
    n = 0
    for d in items:
        print(summary_line(d))
        n += 1
        if limit and n >= limit:
            break
    return n


# ------------------------------------------------------------------ TCP 分析
@dataclass
class FlowState:
    next_seq: int = 0
    max_seq: int = 0
    last_ack: int = 0
    dup_ack_count: int = 0
    seen_syn: bool = False
    seen_fin: bool = False
    zero_window: bool = False
    payload_bytes: int = 0
    segments: int = 0


def analyze_tcp(items: List[Dissected]) -> Dict[Tuple, Dict[str, FlowState]]:
    """复刻 Wireshark 的 TCP 流分析，就地写入 ``d.analysis``。

    返回 ``{flow_key: {direction_key: FlowState}}``。
    """
    flows: Dict[Tuple, Dict[Tuple, FlowState]] = {}
    for d in items:
        if d.proto != "TCP" or d.tcp is None:
            continue
        s = d.tcp
        flow = flows.setdefault(d.flow_key, {})
        st = flow.setdefault(d.direction_key, FlowState())

        if s.flags & SYN and not st.seen_syn:
            st.seen_syn = True
            st.next_seq = s.seq + 1
            st.max_seq = st.next_seq
        else:
            seq_len = s.seq_len
            if seq_len > 0:
                if s.seq == st.next_seq:
                    st.next_seq = s.seq + seq_len
                    st.max_seq = max(st.max_seq, st.next_seq)
                elif s.seq < st.next_seq:
                    # 序列号回退 -> 重传
                    if st.dup_ack_count >= 3:
                        d.analysis.append("Fast Retransmission")
                    else:
                        d.analysis.append("Retransmission")
                    st.max_seq = max(st.max_seq, s.seq + seq_len)
                else:  # s.seq > st.next_seq
                    if st.next_seq == 0:
                        st.next_seq = s.seq + seq_len
                    else:
                        d.analysis.append("Previous segment not captured")
                    st.max_seq = max(st.max_seq, s.seq + seq_len)
                st.payload_bytes += len(s.payload)
                st.segments += 1

        if s.flags & ACK:
            if len(s.payload) == 0 and s.ack == st.last_ack and not (s.flags & (SYN | FIN)):
                st.dup_ack_count += 1
                d.analysis.append("Duplicate ACK")
            else:
                if s.ack > st.last_ack:
                    st.dup_ack_count = 0
                st.last_ack = s.ack

        if s.window == 0:
            if not st.zero_window:
                d.analysis.append("Zero Window")
            st.zero_window = True
        elif st.zero_window:
            d.analysis.append("Window Update")
            st.zero_window = False

        if s.flags & RST:
            d.analysis.append("Connection Reset")
        if s.flags & FIN:
            st.seen_fin = True
    return flows


# ------------------------------------------------------------------ 流重组
def follow_tcp_stream(items: List[Dissected], flow_key: Tuple,
                      client: Optional[Tuple] = None) -> Dict[str, bytes]:
    """重组一条 TCP 流的双向字节流（等价于 Wireshark 的 Follow TCP Stream）。

    返回 ``{"client": bytes, "server": bytes}``，自动按端口/握手方向判定客户端。
    """
    segs = [d for d in items if d.proto == "TCP" and d.flow_key == flow_key]
    if not segs:
        return {"client": b"", "server": b""}
    if client is None:
        for d in segs:
            if d.tcp and (d.tcp.flags & SYN) and not (d.tcp.flags & ACK):
                client = d.direction_key
                break
        else:
            client = segs[0].direction_key

    out = {"client": bytearray(), "server": bytearray()}
    for d in segs:
        if not d.tcp or not d.tcp.payload:
            continue
        side = "client" if d.direction_key == client else "server"
        out[side] += d.tcp.payload
    return {k: bytes(v) for k, v in out.items()}


def tcp_stream_stats(items: List[Dissected]) -> Dict[str, object]:
    """汇总 TCP 层面的关键指标，用于实验报告与断言。"""
    tcp_items = [d for d in items if d.proto == "TCP"]
    retrans = sum(1 for d in tcp_items if "Retransmission" in d.analysis)
    fast = sum(1 for d in tcp_items if "Fast Retransmission" in d.analysis)
    dup = sum(1 for d in tcp_items if "Duplicate ACK" in d.analysis)
    ooo = sum(1 for d in tcp_items if "Previous segment not captured" in d.analysis)
    payload = sum(len(d.tcp.payload) for d in tcp_items if d.tcp)
    return {
        "segments": len(tcp_items),
        "payload_bytes": payload,
        "retransmissions": retrans,
        "fast_retransmissions": fast,
        "duplicate_acks": dup,
        "out_of_order": ooo,
        "handshake_ok": _handshake_ok(tcp_items),
        "teardown_ok": _teardown_ok(tcp_items),
    }


def _handshake_ok(tcp_items: List[Dissected]) -> bool:
    idx = [i for i, d in enumerate(tcp_items) if d.tcp]
    for i in range(len(idx) - 2):
        a, b, c = (tcp_items[idx[i + k]].tcp for k in range(3))
        if (a.flags & SYN and not a.flags & ACK) and (b.flags & SYN and b.flags & ACK) \
                and (c.flags & ACK and not c.flags & SYN):
            return True
    return False


def _teardown_ok(tcp_items: List[Dissected]) -> bool:
    return sum(1 for d in tcp_items if d.tcp and d.tcp.flags & FIN) >= 2
