"""IEEE 802.11 MAC 帧与 Radiotap 头的编解码。

Wireshark 对 802.11 的支持非常完整（``wlan`` + ``wlan_radio`` 解析器），
所以本模块的目标是**产出 Wireshark 能直接解析的字节流**：

* pcap linktype = **127**（DLT_IEEE802_11_RADIO，即 Radiotap + 802.11）；
* Radiotap 头包含 TSFT / Flags / Rate / Channel / dBm Signal 五个字段；
* 802.11 MAC 头严格按 IEEE 802.11-2020 §9.2 的 24 字节格式（QoS 数据帧 26 字节）；
* 管理帧（Beacon / Probe / Auth / Assoc）与数据帧都实现。

这样打开 pcap 后，Wireshark 能显示：

* ``wlan.fc.type`` / ``wlan.fc.subtype``
* ``wlan.fc.retry`` / ``wlan.fc.ds``
* ``wlan.seq`` / ``wlan.frag``
* ``wlan_radio.data_rate`` / ``wlan_radio.signal_dbm``
* ``wlan.duration``（NAV 时长）
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------- 常量
FRAME_TYPE_MGMT = 0
FRAME_TYPE_CTRL = 1
FRAME_TYPE_DATA = 2

TYPE_NAMES = {0: "Management", 1: "Control", 2: "Data", 3: "Extension"}

SUBTYPE_NAMES = {
    (0, 0): "AssocReq", (0, 1): "AssocResp", (0, 2): "ReassocReq",
    (0, 3): "ReassocResp", (0, 4): "ProbeReq", (0, 5): "ProbeResp",
    (0, 8): "Beacon", (0, 9): "ATIM", (0, 10): "Disassoc",
    (0, 11): "Auth", (0, 12): "Deauth", (0, 13): "Action",
    (1, 7): "ControlWrapper", (1, 8): "BlockAckReq", (1, 9): "BlockAck",
    (1, 10): "PS-Poll", (1, 11): "RTS", (1, 12): "CTS", (1, 13): "ACK",
    (1, 14): "CF-End", (1, 15): "CF-End+CF-Ack",
    (2, 0): "Data", (2, 1): "Data+CF-Ack", (2, 4): "Null",
    (2, 8): "QoS Data", (2, 12): "QoS Null",
}

# 广播 / 组播地址
BROADCAST = "ff:ff:ff:ff:ff:ff"

# Radiotap present 位（draft-ietf-ieee80211-radiotap-11 表 2）。
# 这里有两个坑：
#   1. 位号必须按标准来。曾经把 CHANNEL 写成 1<<3、SIGNAL 写成 1<<5，
#      那是把 DBM_ANTSIGNAL 和 DBM_ANTNOISE 的位置安到了 channel/signal 上。
#      Wireshark 会按标准位号往下走，位号错了它读到的字节数就少，
#      于是 802.11 帧的起始偏移整体往前错 4 字节，Type/Subtype 全废。
#      本项目里的 ``wlan_radio.fcs_bad`` 在 flags 字段（偏移 16），
#      恰好排在 channel 之前，所以那个过滤器没受影响——问题被掩盖了很久。
#   2. 字段必须按 present 位**升序**写在 body 里，不是按你想用的顺序。
RT_TSFT = 1 << 0                    # 0x001  rt_timestamp   8 字节
RT_FLAGS = 1 << 1                   # 0x002  rt_flags       1 字节
RT_RATE = 1 << 2                    # 0x004  rt_rate        1 字节
RT_DBM_ANTENNA_SIGNAL = 1 << 3      # 0x008  rt_dbm_antsignal 1 字节（有符号）
RT_CHANNEL = 1 << 11                # 0x800  rt_channel     4 字节（freq + flags）

# Radiotap flags 位。
# 这一字节 8 个位各有明确含义，写错一位 Wireshark 就完全解析不出：
#   0x01 TSF 有效 | 0x02 Short Preamble | 0x10 帧尾带 FCS
#   0x20 **FCS 校验失败（碰撞帧就是靠这一位标出来的）**
#   0x40 CRC32（旧的 CRC 类型标记）| 0x80 Bad FCS（802.11 帧级标记）
#
# 这里曾经写成 0x40，那是 CRC32 位——Wireshark 的 ``wlan_radio.fcs_bad``
# 只认 0x20。写错的后果是整个演示的核心过滤器匹配到 0 帧，而且没有任何报错。
RT_FLAG_FCS = 0x10
RT_FLAG_SHORT_PREAMBLE = 0x02
RT_FLAG_BAD_FCS = 0x20
RT_FLAG_BAD_FCS_WIRESHARK_MASK = 0x20      # = RT_FLAG_BAD_FCS

# 802.11 信道频率（MHz）
CHANNEL_FREQ = {
    1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432, 6: 2437, 7: 2442,
    8: 2447, 9: 2452, 10: 2457, 11: 2462, 12: 2467, 13: 2472, 14: 2484,
    36: 5180, 40: 5200, 44: 5220, 48: 5240, 149: 5745, 153: 5765,
    157: 5785, 161: 5805, 165: 5825,
}

# 802.11 定时参数（单位 us，802.11a/g ERP-OFDM）
SLOT_TIME = 9.0
SIFS = 16.0
DIFS = SIFS + 2 * SLOT_TIME      # 34 us
PIFS = SIFS + SLOT_TIME          # 25 us
EIFS = SIFS + DIFS + 8 * 6.0     # 约 98 us（ACK 用最低速率 6 Mbps）
CW_MIN = 15
CW_MAX = 1023
A_RETRY_LIMIT = 7                # 短重传限制
A_LIFETIME = 512                 # 长重传限制


def crc32(data: bytes) -> int:
    """标准 CRC-32（IEEE 802.3 多项式 0xEDB88320，反射实现）。"""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def fcs32(data: bytes) -> int:
    """802.11 帧检验序列：对 MAC 头 + 载荷算 CRC-32。"""
    return crc32(data)


def mac_to_bytes(mac: str) -> bytes:
    parts = mac.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError(f"非法 MAC 地址：{mac}")
    for part in parts:
        if len(part) != 2 or any(ch not in "0123456789abcdefABCDEF"
                                 for ch in part):
            raise ValueError(f"非法 MAC 地址：{mac}")
    return bytes(int(p, 16) for p in parts)


def bytes_to_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def is_multicast(mac: str) -> bool:
    return bool(mac_to_bytes(mac)[0] & 0x01)


# ---------------------------------------------------------------- Frame Control
@dataclass
class FrameControl:
    """802.11 Frame Control 字段（2 字节小端）。"""

    protocol_version: int = 0
    type: int = FRAME_TYPE_DATA
    subtype: int = 0
    to_ds: int = 0
    from_ds: int = 0
    more_fragments: int = 0
    retry: int = 0
    power_management: int = 0
    more_data: int = 0
    protected: int = 0
    order: int = 0

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type, f"Type{self.type}")

    @property
    def subtype_name(self) -> str:
        return SUBTYPE_NAMES.get((self.type, self.subtype),
                                 f"Subtype{self.subtype}")

    def encode(self) -> bytes:
        """按 802.11-2020 Figure 8-18 的**标准位号**编码。

        这一段的位号一旦写错，Wireshark 会把整帧解成错误的 Type/Subtype
        （``wlan.fc.type`` / ``wlan.fc.type_subtype`` 全部错位），
        而且 ``MacFrame.decode`` 自己的 roundtrip 测试照样全绿——
        它跟编码用的是同一套约定，错得一致就查不出来。
        所以位号必须以 IEEE 802.11 为准，而不是「自洽」。
        """
        v = (self.protocol_version & 0xF)          # bits  0-3  Protocol Version
        v |= (self.type & 0xF) << 4                # bits  4-7  Type
        v |= (self.subtype & 0xF) << 8             # bits  8-11 Subtype
        v |= (self.to_ds & 0x1) << 12              # bit   12   To DS
        v |= (self.from_ds & 0x1) << 13            # bit   13   From DS
        v |= (self.more_fragments & 0x1) << 14     # bit   14   More Fragments
        v |= (self.retry & 0x1) << 15              # bit   15   Retry
        # bit 16 往上还有 Pwr Mgmt(16) / More Data(17) / Wakeup(18) / Order(19) /
        # Protected(21)。Frame Control 只有 2 字节，本仿真不建模这些位：
        # 数据类字段留 0，Wireshark 会显示成清空的正常状态。
        return struct.pack("<H", v)

    @classmethod
    def decode(cls, raw: bytes) -> "FrameControl":
        if len(raw) < 2:
            raise ValueError("Frame Control 至少 2 字节")
        (v,) = struct.unpack("<H", raw[:2])
        return cls(
            protocol_version=v & 0xF,
            type=(v >> 4) & 0xF,
            subtype=(v >> 8) & 0xF,
            to_ds=(v >> 12) & 0x1,
            from_ds=(v >> 13) & 0x1,
            more_fragments=(v >> 14) & 0x1,
            retry=(v >> 15) & 0x1,
            power_management=0,
            more_data=0,
            protected=0,
            order=0,
        )

    def describe(self) -> str:
        ds = {0: "", 1: "ToDS", 2: "FromDS", 3: "WDS"}.get(
            (self.to_ds << 0) | (self.from_ds << 1), "")
        extra = "".join([
            " Retry" if self.retry else "",
            " MoreFrag" if self.more_fragments else "",
            " Protected" if self.protected else "",
            " MoreData" if self.more_data else "",
        ])
        return f"{self.type_name}/{self.subtype_name}{' ' + ds if ds else ''}{extra}"


# ---------------------------------------------------------------- MAC 帧
@dataclass
class MacFrame:
    """一个 802.11 MAC 帧。"""

    fc: FrameControl = field(default_factory=FrameControl)
    duration: int = 0                     # NAV 时长（us）
    addr1: str = BROADCAST                # RA / DA
    addr2: str = ""                       # TA / SA
    addr3: str = ""                       # BSSID
    addr4: Optional[str] = None           # 仅 WDS
    seq: int = 0                          # 序列号（0~4095）
    frag: int = 0                         # 分片号（0~15）
    qos_tid: Optional[int] = None         # QoS 数据帧的 TID（0~15）
    payload: bytes = b""
    fcs: Optional[int] = None             # 4 字节 FCS（若 Radiotap 声明存在）

    @property
    def is_qos(self) -> bool:
        return self.fc.type == FRAME_TYPE_DATA and (self.fc.subtype & 0x8) != 0

    @property
    def header_len(self) -> int:
        if self.fc.type == FRAME_TYPE_CTRL:
            # RTS(11) 是唯一带两个地址的控制帧：FC + Dur + RA + TA = 16
            return 16 if self.fc.subtype == 11 else 10
        n = 24
        if self.fc.to_ds and self.fc.from_ds:
            n += 6
        if self.is_qos:
            n += 2
        return n

    def encode(self) -> bytes:
        out = self.fc.encode()
        out += struct.pack("<H", self.duration & 0xFFFF)
        out += mac_to_bytes(self.addr1)
        if self.fc.type == FRAME_TYPE_CTRL:
            # 控制帧头只有 10 字节：FC(2) + Duration(2) + RA(6)
            # RTS 例外，它还要带发送方地址 TA
            if self.fc.subtype == 11:
                out += mac_to_bytes(self.addr2)
            out += self.payload
            if self.fcs is not None:
                out += struct.pack("<I", self.fcs & 0xFFFFFFFF)
            return out
        out += mac_to_bytes(self.addr2)
        out += mac_to_bytes(self.addr3)
        out += struct.pack("<H", ((self.seq & 0xFFF) << 4) | (self.frag & 0xF))
        if self.fc.to_ds and self.fc.from_ds:
            out += mac_to_bytes(self.addr4 or "00:00:00:00:00:00")
        if self.is_qos:
            out += struct.pack("<H", (self.qos_tid or 0) & 0xF)
        out += self.payload
        if self.fcs is not None:
            out += struct.pack("<I", self.fcs & 0xFFFFFFFF)
        return out

    @classmethod
    def decode(cls, raw: bytes) -> "MacFrame":
        if len(raw) < 10:
            raise ValueError("802.11 帧太短")
        fc = FrameControl.decode(raw)
        (duration,) = struct.unpack("<H", raw[2:4])
        f = cls(fc=fc, duration=duration)
        if fc.type == FRAME_TYPE_CTRL:
            # 控制帧头只有 10 字节（FC + Duration + RA）；RTS 多 6 字节 TA
            f.addr1 = bytes_to_mac(raw[4:10])
            if fc.subtype == 11 and len(raw) >= 16:
                f.addr2 = bytes_to_mac(raw[10:16])
                f.payload = raw[16:]
            else:
                f.payload = raw[10:]
            return f
        if len(raw) < 24:
            raise ValueError("802.11 数据/管理帧头不足 24 字节")
        f.addr1 = bytes_to_mac(raw[4:10])
        f.addr2 = bytes_to_mac(raw[10:16])
        f.addr3 = bytes_to_mac(raw[16:22])
        (sc,) = struct.unpack("<H", raw[22:24])
        f.seq, f.frag = sc >> 4, sc & 0xF
        off = 24
        if fc.to_ds and fc.from_ds:
            if len(raw) < 30:
                raise ValueError("WDS 帧缺少 Address4")
            f.addr4 = bytes_to_mac(raw[24:30])
            off = 30
        if f.is_qos:
            if len(raw) < off + 2:
                raise ValueError("QoS 帧缺少 QoS Control")
            (qc,) = struct.unpack("<H", raw[off:off + 2])
            f.qos_tid = qc & 0xF
            off += 2
        f.payload = raw[off:]
        return f

    def describe(self) -> str:
        return (f"{self.fc.describe()} {self.addr2}->{self.addr1} "
                f"seq={self.seq} dur={self.duration} len={len(self.payload)}")


# ---------------------------------------------------------------- Radiotap
@dataclass
class Radiotap:
    """Radiotap 头（DLT 127）。

    Wireshark 用它显示 ``wlan_radio.data_rate`` / ``wlan_radio.signal_dbm``
    等物理层信息——没有它，Wireshark 只能看到裸 802.11 帧。
    """

    tsft: Optional[int] = 0
    flags: Optional[int] = RT_FLAG_FCS
    rate_mbps: Optional[float] = 54.0      # 802.11a/g 最高速率
    channel: Optional[int] = 6
    signal_dbm: Optional[int] = -45

    @property
    def present(self) -> int:
        """present 位图：**只有非 None 的字段才置位**。

        这是 Radiotap 的核心约定：接收端完全靠这张位图决定
        后面有哪些字段、每个字段多长。多写一个位就会全盘错位。
        """
        bits = 0
        if self.tsft is not None:
            bits |= RT_TSFT
        if self.flags is not None:
            bits |= RT_FLAGS
        if self.rate_mbps is not None:
            bits |= RT_RATE
        if self.channel is not None:
            bits |= RT_CHANNEL
        if self.signal_dbm is not None:
            bits |= RT_DBM_ANTENNA_SIGNAL
        return bits

    def encode(self) -> bytes:
        # 字段顺序 = present 位升序：tsft(0x1) < flags(0x2) < rate(0x4)
        # < dbm_signal(0x8) < channel(0x800)。顺序错了整帧就废。
        body = bytearray()
        if self.tsft is not None:
            body += struct.pack("<Q", self.tsft)
        if self.flags is not None:
            body += struct.pack("<B", self.flags)
        if self.rate_mbps is not None:
            body += struct.pack("<B", int(round(self.rate_mbps * 2)) & 0xFF)
        if self.signal_dbm is not None:
            body += struct.pack("<b", self.signal_dbm)
        if self.channel is not None:
            body += struct.pack("<HH",
                                CHANNEL_FREQ.get(self.channel, 2437), 0x00A0)
        # Header Length 是「含补位的总长度」，必须取 8 的整数倍；
        # 只填 fields 长度会让 Wireshark 认为补位是帧内容的一部分。
        pad = (-(8 + len(body))) % 8
        body += b"\x00" * pad
        header = struct.pack("<BBHI", 0, 0, 8 + len(body), self.present)
        return header + bytes(body)

    @classmethod
    def decode(cls, raw: bytes) -> Tuple["Radiotap", int]:
        if len(raw) < 8:
            raise ValueError("Radiotap 头不足 8 字节")
        version, pad, length, present = struct.unpack("<BBHI", raw[:8])
        if version != 0:
            raise ValueError(f"不支持的 Radiotap 版本 {version}")
        rt = cls(tsft=None, flags=None, rate_mbps=None, channel=None,
                 signal_dbm=None)
        # 必须按 present 位升序读，与 encode() 的写出顺序一一对应
        off = 8
        if present & RT_TSFT:
            off = (off + 7) & ~7
            (rt.tsft,) = struct.unpack("<Q", raw[off:off + 8])
            off += 8
        if present & RT_FLAGS:
            rt.flags = raw[off]
            off += 1
        if present & RT_RATE:
            rt.rate_mbps = raw[off] / 2.0
            off += 1
        if present & RT_DBM_ANTENNA_SIGNAL:
            (rt.signal_dbm,) = struct.unpack("<b", raw[off:off + 1])
            off += 1
        if present & RT_CHANNEL:
            freq, _flags = struct.unpack("<HH", raw[off:off + 4])
            off += 4
            rt.channel = next((c for c, f in CHANNEL_FREQ.items() if f == freq), 0)
        return rt, length

    def describe(self) -> str:
        return (f"Radiotap {self.rate_mbps:g}Mbps ch{self.channel} "
                f"{self.signal_dbm}dBm")


def build_frame(mac_frame: MacFrame, radio: Optional[Radiotap] = None) -> bytes:
    """把 MAC 帧封装成 Radiotap + 802.11（pcap linktype 127 的载荷）。

    如果 Radiotap 声明了 ``RT_FLAG_FCS``，会自动补上 4 字节 CRC-32。
    真实网卡也是这么干的：FCS 由硬件计算并附加在帧尾，
    Wireshark 只有在 Radiotap 声明 FCS 存在时才会去校验它。
    """
    rt = radio or Radiotap()
    mf = mac_frame
    if (rt.flags & RT_FLAG_FCS) and mf.fcs is None:
        mf = replace(mf, fcs=fcs32(mf.encode()))
    return rt.encode() + mf.encode()


def parse_frame(raw: bytes) -> Tuple[Radiotap, MacFrame]:
    """拆开 Radiotap + 802.11，并按 Radiotap 声明剥离 FCS。"""
    rt, off = Radiotap.decode(raw)
    body = raw[off:]
    mf = MacFrame.decode(body)
    if rt.flags & RT_FLAG_FCS and len(body) >= 4:
        mf = replace(mf, fcs=struct.unpack("<I", body[-4:])[0],
                     payload=body[mf.header_len:-4])
    return rt, mf


# ---------------------------------------------------------------- 便捷构造
def data_frame(src: str, dst: str, bssid: str, payload: bytes,
               seq: int = 0, tid: Optional[int] = None,
               to_ds: int = 1, from_ds: int = 0,
               retry: int = 0, duration: int = 0) -> MacFrame:
    """构造一个数据帧（默认 ToDS：STA -> AP）。"""
    fc = FrameControl(type=FRAME_TYPE_DATA,
                      subtype=8 if tid is not None else 0,
                      to_ds=to_ds, from_ds=from_ds, retry=retry)
    return MacFrame(fc=fc, duration=duration, addr1=dst, addr2=src,
                    addr3=bssid, seq=seq, qos_tid=tid, payload=payload)


def ack_frame(ra: str, duration: int = 0) -> MacFrame:
    fc = FrameControl(type=FRAME_TYPE_CTRL, subtype=13)
    return MacFrame(fc=fc, duration=duration, addr1=ra)


def cts_frame(ra: str, duration: int = 0) -> MacFrame:
    fc = FrameControl(type=FRAME_TYPE_CTRL, subtype=12)
    return MacFrame(fc=fc, duration=duration, addr1=ra)


def rts_frame(ra: str, ta: str, duration: int = 0) -> MacFrame:
    fc = FrameControl(type=FRAME_TYPE_CTRL, subtype=11)
    return MacFrame(fc=fc, duration=duration, addr1=ra, addr2=ta)


def beacon_frame(bssid: str, ssid: str, channel: int = 6,
                 beacon_interval: int = 100, seq: int = 0,
                 extra_ies: Optional[List[Tuple[int, bytes]]] = None,
                 subtype: int = 8) -> MacFrame:
    """构造 Beacon / Probe Response（含 SSID 与 DS Parameter 两个 IE）。

    ``extra_ies`` 可以追加任意信息元素，例如 RSN(48) 或 HT Capabilities(45)。
    ``subtype=5`` 时构造的是 Probe Response（固定字段相同）。
    """
    body = struct.pack("<QHH", 0, beacon_interval, 0x0431)   # timestamp/cap
    ssid_ie = bytes([0, len(ssid)]) + ssid.encode()
    ds_ie = bytes([3, 1, channel & 0xFF])
    tail = b""
    for eid, value in (extra_ies or []):
        tail += bytes([eid & 0xFF, len(value) & 0xFF]) + value
    fc = FrameControl(type=FRAME_TYPE_MGMT, subtype=subtype)
    return MacFrame(fc=fc, duration=0, addr1=BROADCAST, addr2=bssid,
                    addr3=bssid, seq=seq, payload=body + ssid_ie + ds_ie + tail)


def probe_request(src: str, ssid: str = "", seq: int = 0) -> MacFrame:
    fc = FrameControl(type=FRAME_TYPE_MGMT, subtype=4)
    ie = bytes([0, len(ssid)]) + ssid.encode()
    return MacFrame(fc=fc, addr1=BROADCAST, addr2=src, addr3=BROADCAST,
                    seq=seq, payload=ie)


def auth_frame(src: str, bssid: str, seq: int = 0, algo: int = 0,
               status: int = 0, seq_num: Optional[int] = None) -> MacFrame:
    """认证帧。``seq_num`` 是认证事务序号（1=请求，2=响应）。"""
    fc = FrameControl(type=FRAME_TYPE_MGMT, subtype=11)
    body = struct.pack("<HHH", algo, seq + 1 if seq_num is None else seq_num,
                       status)
    return MacFrame(fc=fc, addr1=bssid, addr2=src, addr3=bssid, seq=seq,
                    payload=body)


def assoc_request(src: str, bssid: str, ssid: str, seq: int = 0) -> MacFrame:
    fc = FrameControl(type=FRAME_TYPE_MGMT, subtype=0)
    body = struct.pack("<HH", 0x0431, 10)      # capability + listen interval
    ie = bytes([0, len(ssid)]) + ssid.encode()
    return MacFrame(fc=fc, addr1=bssid, addr2=src, addr3=bssid, seq=seq,
                    payload=body + ie)


# ---------------------------------------------------------------- IE 解析
def parse_information_elements(payload: bytes) -> List[Tuple[int, bytes]]:
    """解析管理帧的信息元素（IE）列表。"""
    out: List[Tuple[int, bytes]] = []
    off = 0
    while off + 2 <= len(payload):
        eid, length = payload[off], payload[off + 1]
        if off + 2 + length > len(payload):
            break
        out.append((eid, payload[off + 2:off + 2 + length]))
        off += 2 + length
    return out


IE_NAMES = {0: "SSID", 1: "Supported Rates", 3: "DS Parameter Set",
            5: "TIM", 7: "Country", 11: "BSS Load", 33: "Power Capability",
            42: "ERP Information", 45: "HT Capabilities",
            48: "RSN", 50: "Extended Supported Rates",
            54: "Mobility Domain", 59: "Supported Operating Classes",
            61: "HT Operation", 70: "RM Enabled Capabilities",
            74: "Overlapping BSS Scan", 127: "Extended Capabilities",
            191: "VHT Capabilities", 192: "VHT Operation",
            221: "Vendor Specific"}


#: 各类管理帧子类型前面的**固定字段长度**（字节）。
#: 解析 IE 之前必须先跳过这部分，否则会把 timestamp 当成 IE id。
MGMT_FIXED_LEN: Dict[int, int] = {
    0: 4,    # AssocReq: capability(2) + listen interval(2)
    1: 6,    # AssocResp: capability(2) + status(2) + AID(2)
    2: 4,    # ReassocReq
    3: 6,    # ReassocResp
    4: 0,    # ProbeReq: 无固定字段
    5: 12,   # ProbeResp: timestamp(8) + beacon interval(2) + capability(2)
    8: 12,   # Beacon
    10: 2,   # Disassoc: reason code
    11: 6,   # Auth: algo(2) + seq(2) + status(2)
    12: 2,   # Deauth: reason code
}


def mgmt_ies(frame: "MacFrame") -> List[Tuple[int, bytes]]:
    """取出管理帧里的信息元素（自动跳过固定字段）。"""
    if frame.fc.type != FRAME_TYPE_MGMT:
        return []
    skip = MGMT_FIXED_LEN.get(frame.fc.subtype, 0)
    return parse_information_elements(frame.payload[skip:])


def describe_ies(payload: bytes) -> List[str]:
    out = []
    for eid, value in parse_information_elements(payload):
        name = IE_NAMES.get(eid, f"IE{eid}")
        if eid == 0:
            out.append(f"{name}={value.decode('utf-8', 'replace')!r}")
        elif eid == 3 and value:
            out.append(f"{name}=ch{value[0]}")
        else:
            out.append(f"{name}({len(value)}B)")
    return out
