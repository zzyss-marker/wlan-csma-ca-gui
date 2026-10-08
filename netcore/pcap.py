"""pcap 抓包文件读写 —— 与 Wireshark 的对接层。

本模块把协议栈在虚拟链路上收发的**每一个以太网帧**按标准 libpcap 格式落盘，
因此可以直接用 Wireshark / tshark 打开，得到完整的：

    Ethernet II -> IPv4 -> TCP

解析结果，包括三次握手、窗口缩放、SACK、重传、重复 ACK、乱序等
Wireshark 自带的 TCP 分析器能识别的一切。

支持两种链路类型：

* ``DLT_EN10MB = 1``   以太网帧（默认，最贴近真实网络，Wireshark 解析最完整）
* ``DLT_RAW = 101``    裸 IPv4（用于只看 IP 层的场景）

另外提供 :func:`tshark_available` / :func:`tshark_summary`，
方便在实验脚本里自动调用 tshark 做**机器可校验**的解析验证。
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 101

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAPNG_MAGIC = 0x0A0D0D0A


@dataclass
class CapturedPacket:
    """一条抓包记录。"""

    ts: float          # 相对抓包起点的秒数
    data: bytes        # 链路层原始字节
    direction: str = ""  # 可选：'tx' / 'rx' / 'fwd'，仅供自研分析使用
    comment: str = ""


class PcapWriter:
    """增量写出的 pcap 文件。

    用法::

        with PcapWriter("out.pcap") as w:
            w.write(frame_bytes, t=0.001)
    """

    def __init__(self, path: str, linktype: int = DLT_EN10MB,
                 snaplen: int = 262144, t0: float = 0.0) -> None:
        self.path = path
        self.linktype = linktype
        self.snaplen = snaplen
        self.t0 = t0
        self.count = 0
        self._fh = open(path, "wb")
        self._fh.write(struct.pack(
            "<IHHiIII",
            PCAP_MAGIC_LE, 2, 4, 0, 0, snaplen, linktype,
        ))

    def write(self, data: bytes, t: float) -> None:
        """写入一个链路层帧，``t`` 为相对 ``t0`` 的秒数。"""
        rel = t - self.t0
        if rel < 0:
            rel = 0.0
        sec = int(rel)
        usec = int(round((rel - sec) * 1_000_000))
        if usec >= 1_000_000:      # 浮点进位保护
            sec += 1
            usec -= 1_000_000
        payload = data[:self.snaplen]
        self._fh.write(struct.pack("<IIII", sec, usec, len(payload), len(data)))
        self._fh.write(payload)
        self.count += 1

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.flush()
            self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def read_pcap(path: str) -> Tuple[int, List[CapturedPacket]]:
    """读取 pcap，返回 ``(linktype, packets)``。"""
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 24:
        raise ValueError("pcap 文件过短")
    magic = struct.unpack("<I", blob[:4])[0]
    if magic == PCAP_MAGIC_LE:
        endian = "<"
    elif magic == PCAP_MAGIC_BE:
        endian = ">"
    elif magic == PCAPNG_MAGIC:
        raise ValueError("这是 pcapng 文件，请用 Wireshark 打开或用 pcapng 读取器")
    else:
        raise ValueError(f"无法识别的 pcap magic: 0x{magic:08x}")
    _m, _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "IHHiIII", blob[:24])
    packets: List[CapturedPacket] = []
    off = 24
    while off + 16 <= len(blob):
        sec, usec, incl, _orig = struct.unpack(endian + "IIII", blob[off:off + 16])
        off += 16
        data = blob[off:off + incl]
        off += incl
        packets.append(CapturedPacket(ts=sec + usec / 1_000_000.0, data=data))
    return linktype, packets


def pcap_to_ethernet_frames(path: str) -> Iterator[bytes]:
    """把 pcap 中的记录统一转成以太网帧字节串（DLT_RAW 会自动补一个假以太头）。"""
    linktype, packets = read_pcap(path)
    for pkt in packets:
        if linktype == DLT_EN10MB:
            yield pkt.data
        elif linktype == DLT_RAW:
            yield b"\x00" * 12 + b"\x08\x00" + pkt.data
        else:
            raise ValueError(f"暂不支持 linktype={linktype}")


# ------------------------------------------------------------------ tshark 集成
def tshark_path() -> Optional[str]:
    """返回 tshark 可执行文件路径（未安装则 None）。"""
    for name in ("tshark", "/Applications/Wireshark.app/Contents/MacOS/tshark"):
        found = shutil.which(name) if os.sep not in name else (name if os.path.exists(name) else None)
        if found:
            return found
    return None


def tshark_available() -> bool:
    return tshark_path() is not None


def tshark_summary(path: str, display_filter: str = "", limit: int = 0,
                   fields: Optional[List[str]] = None) -> List[str]:
    """调用 tshark 解析 pcap，返回每行一条的文本结果。

    这是"用真实工具验证自研协议栈"的关键：如果 tshark 能把我们生成的
    pcap 解析成合法的 TCP 报文，就说明线格式实现是正确的。
    """
    exe = tshark_path()
    if exe is None:
        raise RuntimeError("未找到 tshark，请安装 Wireshark 并勾选命令行工具")
    cmd = [exe, "-r", path, "-n"]
    if display_filter:
        cmd += ["-Y", display_filter]
    if fields:
        cmd += ["-T", "fields"]
        for f in fields:
            cmd += ["-e", f]
    else:
        cmd += ["-T", "fields", "-e", "frame.number", "-e", "frame.time_relative",
                "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.flags.str",
                "-e", "tcp.seq", "-e", "tcp.ack", "-e", "tcp.len",
                "-e", "tcp.analysis.flags"]
    if limit:
        cmd += ["-c", str(limit)]
    out = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise RuntimeError(f"tshark 执行失败：{out.stderr.strip()}")
    return [line for line in out.stdout.splitlines() if line.strip()]


def tshark_expert_info(path: str) -> List[str]:
    """返回 Wireshark 的"专家信息"（重传、乱序、零窗口等告警）。"""
    exe = tshark_path()
    if exe is None:
        raise RuntimeError("未找到 tshark")
    cmd = [exe, "-r", path, "-n", "-q", "-z", "expert"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return [line for line in out.stdout.splitlines() if line.strip()]
