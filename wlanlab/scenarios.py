"""7 个可复现实验：802.11 CSMA/CA 无线实验室。

每个实验都产出 **pcap / json / png** 三种证据，答辩时可以直接打开文件
回答「你怎么证明」。所有实验纯 Python、零外部依赖、可重复运行。

==============  ==========================================================
``frames``      帧编解码：MAC 头 / Radiotap / IE / FCS 逐字节往返
``management``  关联流程：Beacon -> Probe -> Auth -> Assoc 全握手
``dcf``         DCF 基本接入：站点数扫描（吞吐 / 碰撞 / 短时公平性）
``hidden``      隐藏终端 vs RTS/CTS（核心实验，含增益热力图）
``edca``        EDCA 四类 QoS + 三机制消融实验
``airtime``     空口时间分析：速率 / 帧长 / 聚合 / 效率
``pcap``        导出 Radiotap+802.11 pcap（linktype 127），Wireshark 直读
==============  ==========================================================
"""

from __future__ import annotations

import json
import os
from collections import OrderedDict
from typing import Dict, List, Optional, Sequence, Tuple

from netcore import viz
from netcore.pcap import PcapWriter, read_pcap, tshark_available, tshark_summary

from . import dcf as D
from . import edca as E
from . import frame as F
from . import phy

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.abspath(os.path.join(HERE, ".."))
OUT = os.path.join(PROJ, "out")
os.makedirs(OUT, exist_ok=True)

DLT_IEEE802_11_RADIO = 127

AP_MAC = "02:00:00:00:00:ff"
STA_MACS = [f"02:00:00:00:00:{i + 1:02x}" for i in range(16)]


def _json(name: str, obj) -> str:
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
    return path


def _pcap(name: str, frames: Sequence[Tuple[float, bytes]]) -> str:
    path = os.path.join(OUT, name)
    with PcapWriter(path, linktype=DLT_IEEE802_11_RADIO) as w:
        for t, raw in frames:
            w.write(raw, t)
    return path


def _pcap_stats(path: str) -> Dict[str, object]:
    linktype, packets = read_pcap(path)
    kinds: Dict[str, int] = {}
    retries = 0
    bad_fcs = 0
    for p in packets:
        try:
            radio, mf = F.parse_frame(p.data)
        except Exception:
            kinds["parse_error"] = kinds.get("parse_error", 0) + 1
            continue
        key = f"{mf.fc.type_name}/{mf.fc.subtype_name}"
        kinds[key] = kinds.get(key, 0) + 1
        if mf.fc.retry:
            retries += 1
        if radio.flags & F.RT_FLAG_BAD_FCS:
            bad_fcs += 1
    return {
        "path": os.path.basename(path),
        "linktype": linktype,
        "packets": len(packets),
        "kinds": kinds,
        "retry_frames": retries,
        "bad_fcs_frames": bad_fcs,
        "bytes": os.path.getsize(path),
    }


# ================================================================== 1. frames
def exp_frames() -> Dict[str, object]:
    """实验 1 · 帧编解码：MAC 头 / Radiotap / IE / FCS 逐字节往返。"""
    report: Dict[str, object] = {"experiment": "frames"}

    # ---- 1) 各种帧类型的往返
    cases = [
        ("Data", F.data_frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                              "02:00:00:00:00:ff", b"hello-80211", seq=7)),
        ("QoS Data", F.data_frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                                  "02:00:00:00:00:ff", b"qos", seq=8, tid=6)),
        ("ACK", F.ack_frame("02:00:00:00:00:01")),
        ("CTS", F.cts_frame("02:00:00:00:00:01")),
        ("RTS", F.rts_frame("02:00:00:00:00:02", "02:00:00:00:00:01")),
        ("Beacon", F.beacon_frame("02:00:00:00:00:ff", "NetLab-5G",
                                  channel=36, seq=1)),
        ("Probe Request", F.probe_request("02:00:00:00:00:01", "NetLab-5G")),
        ("Auth", F.auth_frame("02:00:00:00:00:01", "02:00:00:00:00:ff")),
        ("Assoc Request", F.assoc_request("02:00:00:00:00:01",
                                          "02:00:00:00:00:ff", "NetLab-5G")),
    ]
    rows = []
    for label, mf in cases:
        raw = mf.encode()
        back = F.MacFrame.decode(raw)
        rows.append({
            "frame": label,
            "type": mf.fc.type_name,
            "subtype": mf.fc.subtype_name,
            "header_bytes": mf.header_len,
            "total_bytes": len(raw),
            "roundtrip_ok": back.encode() == raw,
            "describe": mf.describe(),
        })
    report["frame_matrix"] = rows
    report["all_roundtrip_ok"] = all(r["roundtrip_ok"] for r in rows)

    # ---- 2) Radiotap 对齐
    rt = F.Radiotap(tsft=123456, flags=F.RT_FLAG_FCS, rate_mbps=54.0,
                    channel=6, signal_dbm=-42)
    raw_rt = rt.encode()
    back_rt, off = F.Radiotap.decode(raw_rt)
    report["radiotap"] = {
        "present_bitmap": hex(rt.present),
        "header_bytes": len(raw_rt),
        "aligned_to_8": len(raw_rt) % 8 == 0,
        "offset": off,
        "roundtrip_ok": back_rt.encode() == raw_rt,
        "describe": rt.describe(),
    }

    # ---- 3) 信息元素解析（Beacon）
    beacon = F.beacon_frame(AP_MAC, "NetLab-5G", channel=36, seq=1,
                            extra_ies=[(48, bytes([0x20, 0x04])),
                                       (127, b"\x04\x00\x00\x00\x02\x00\x00\x00")])
    ies = F.mgmt_ies(beacon)
    report["beacon_ies"] = [
        {"id": i, "name": F.IE_NAMES.get(i, "?"), "len": len(v),
         "value_hex": v[:16].hex()}
        for i, v in ies]
    report["beacon_ssid"] = next((v.decode("utf-8", "replace")
                                  for i, v in ies if i == 0), "")
    report["beacon_channel"] = next((v[0] for i, v in ies if i == 3), None)

    # ---- 4) FCS 校验
    body = F.data_frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                        AP_MAC, b"fcs-test").encode()
    report["fcs"] = {
        "crc32_hex": hex(F.fcs32(body)),
        "crc32_known_vector": hex(F.crc32(b"123456789")),   # 应为 0xcbf43926
        "crc32_known_vector_ok": F.crc32(b"123456789") == 0xCBF43926,
        "flip_one_bit_changes_crc": F.fcs32(body) != F.fcs32(
            body[:-1] + bytes([body[-1] ^ 0x01])),
    }

    # ---- 5) 导出 pcap
    frames = []
    t = 0.0
    for label, mf in cases:
        radio = F.Radiotap(tsft=int(t * 1e6), flags=F.RT_FLAG_FCS,
                           rate_mbps=54.0, channel=6, signal_dbm=-42)
        frames.append((t, F.build_frame(mf, radio)))
        t += 0.001
    path = _pcap("01_frames.pcap", frames)
    report["pcap"] = _pcap_stats(path)

    viz.bar_plot([r["frame"] for r in rows],
                 [r["total_bytes"] for r in rows],
                 os.path.join(OUT, "01_frame_sizes.png"),
                 title="802.11 各类型帧的字节长度", ylabel="字节")
    _json("01_frames.json", report)
    return report


# ============================================================ 2. management
def exp_management() -> Dict[str, object]:
    """实验 2 · 关联流程：Beacon -> Probe -> Auth -> Assoc 全握手。"""
    report: Dict[str, object] = {"experiment": "management"}
    sta = STA_MACS[0]
    t = 0.0
    frames: List[Tuple[float, bytes]] = []
    steps: List[Dict[str, object]] = []

    def emit(label: str, mf: F.MacFrame, note: str) -> None:
        nonlocal t
        radio = F.Radiotap(tsft=int(t * 1e6), flags=F.RT_FLAG_FCS,
                           rate_mbps=6.0, channel=6, signal_dbm=-40)
        frames.append((t, F.build_frame(mf, radio)))
        steps.append({
            "step": len(steps) + 1,
            "t_us": round(t * 1e6, 1),
            "frame": label,
            "type_subtype": f"{mf.fc.type_name}/{mf.fc.subtype_name}",
            "src": mf.addr2, "dst": mf.addr1,
            "bytes": len(mf.encode()),
            "note": note,
        })
        t += 0.002

    emit("Beacon", F.beacon_frame(AP_MAC, "NetLab-5G", channel=6, seq=0,
                                  extra_ies=[(48, bytes([0x2c, 0x01]))]),
         "AP 每 100ms 广播一次，携带 SSID / 速率 / DS 参数 / RSN")
    emit("Probe Request", F.probe_request(sta, "NetLab-5G", seq=1),
         "STA 主动扫描：广播探测请求，SSID 可以是通配（隐藏 SSID 探测）")
    emit("Probe Response", F.beacon_frame(AP_MAC, "NetLab-5G", channel=6,
                                          seq=1), "AP 单播探测响应")
    emit("Authentication", F.auth_frame(sta, AP_MAC, seq=2, algo=0, seq_num=1),
         "开放系统认证：请求（algo=0, seq=1）")
    emit("Authentication", F.auth_frame(AP_MAC, sta, seq=2, algo=0, seq_num=2),
         "开放系统认证：响应（seq=2 表示成功）")
    emit("Association Request", F.assoc_request(sta, AP_MAC, "NetLab-5G",
                                                seq=3),
         "关联请求：STA 声明自己支持的速率与能力")
    emit("Association Response", F.beacon_frame(AP_MAC, "NetLab-5G",
                                                channel=6, seq=3),
         "关联响应：AP 分配 AID")
    emit("Data", F.data_frame(sta, AP_MAC, AP_MAC, b"DHCP DISCOVER",
                              seq=4, tid=0),
         "关联成功后才能发数据帧；QoS Data 的 TID 决定 EDCA 接入类别")
    emit("ACK", F.ack_frame(sta), "每个单播数据帧都要 ACK（SIFS 之后）")

    path = _pcap("02_management.pcap", frames)
    report["handshake"] = steps
    report["total_frames"] = len(steps)
    report["total_bytes"] = sum(s["bytes"] for s in steps)
    report["pcap"] = _pcap_stats(path)
    report["mgmt_frame_types"] = sorted({s["type_subtype"] for s in steps})

    # 管理帧固定字段长度表（用于说明为什么不能无脑从 payload[0] 开始解 IE）
    report["mgmt_fixed_len"] = dict(sorted(F.MGMT_FIXED_LEN.items()))
    report["ie_names"] = {str(k): v for k, v in sorted(F.IE_NAMES.items())}

    _json("02_management.json", report)
    return report


# ==================================================================== 3. dcf
def exp_dcf(counts: Optional[Sequence[int]] = None) -> Dict[str, object]:
    """实验 3 · DCF 基本接入：站点数扫描（吞吐 / 碰撞 / 短时公平性）。"""
    counts = list(counts or (1, 2, 4, 8, 12, 16))
    report: Dict[str, object] = {"experiment": "dcf", "sweep": []}
    n_frames = 200
    for n in counts:
        sim, ap, stas = D.build_bss(n_stations=n, spacing_m=20.0, seed=42)
        for s in stas:
            for _ in range(n_frames):
                sim.enqueue(s, ap.mac, 1500)
        r = sim.run()
        report["sweep"].append({
            "stations": n,
            "throughput_mbps": r["throughput_mbps"],
            "collision_rate": r["collision_rate"],
            "channel_utilization": r["channel_utilization"],
            "wasted_ratio": r["wasted_ratio"],
            "jain_long": r["jain_fairness"],
            "jain_short": r["jain_fairness_short_term"],
            "dropped": r["dropped_frames"],
            "elapsed_us": r["elapsed_us"],
            "avg_backoff_slots": round(
                sum(s["avg_backoff_slots"] for s in r["per_station"]) / n, 2),
        })

    xs = [row["stations"] for row in report["sweep"]]
    viz.line_plot(
        OrderedDict([
            ("吞吐量 (Mbps)", [row["throughput_mbps"] for row in report["sweep"]]),
            ("信道利用率", [row["channel_utilization"] * 100
                            for row in report["sweep"]]),
            ("碰撞率 ×100", [row["collision_rate"] * 100
                             for row in report["sweep"]]),
        ]),
        os.path.join(OUT, "03_dcf_sweep.png"), x=xs,
        title="DCF：站点数对吞吐 / 利用率 / 碰撞率的影响",
        xlabel="站点数", ylabel="Mbps 或 %")

    viz.line_plot(
        OrderedDict([
            ("长时间尺度 Jain", [row["jain_long"] for row in report["sweep"]]),
            ("短时间尺度 Jain", [row["jain_short"] for row in report["sweep"]]),
        ]),
        os.path.join(OUT, "03_dcf_fairness.png"), x=xs,
        title="DCF 公平性：长时间尺度 vs 短时间尺度",
        xlabel="站点数", ylabel="Jain 公平指数")

    # 一个站点的退避序列（展示 BEB 的指数增长）
    sim, ap, stas = D.build_bss(n_stations=6, spacing_m=20.0, seed=7)
    for s in stas:
        for _ in range(60):
            sim.enqueue(s, ap.mac, 1500)
    sim.run()
    report["backoff_sequence"] = {
        "station": stas[0].name,
        "draws": stas[0].backoff_draws[:40],
        "cw_final": stas[0].cw,
        "retransmits": stas[0].retransmits,
    }
    viz.line_plot(
        {"退避时隙数": stas[0].backoff_draws[:60]},
        os.path.join(OUT, "03_backoff_sequence.png"),
        title=f"{stas[0].name} 的退避计数器抽取序列（二进制指数退避）",
        xlabel="第 n 次抽取", ylabel="退避时隙数")

    # 碰撞原因分布
    reasons: Dict[str, int] = {}
    for tr in sim._collision_trace:
        reasons[tr["reason"]] = reasons.get(tr["reason"], 0) + 1
    report["collision_reasons"] = reasons

    _json("03_dcf.json", report)
    return report


# ================================================================= 4. hidden
def exp_hidden() -> Dict[str, object]:
    """实验 4 · 隐藏终端 vs RTS/CTS（核心实验，含增益热力图）。"""
    report: Dict[str, object] = {"experiment": "hidden"}

    # ---- 4.1 经典三节点拓扑：A 与 C 相距 160m，都听得到 AP
    topo = {}
    for use_rts in (False, True):
        sim, ap, a, c = D.build_hidden_terminal(seed=7, use_rts=use_rts,
                                                rts_threshold=0)
        for _ in range(300):
            sim.enqueue(a, ap.mac, 1500)
            sim.enqueue(c, ap.mac, 1500)
        r = sim.run()
        reasons: Dict[str, int] = {}
        for tr in sim._collision_trace:
            reasons[tr["reason"]] = reasons.get(tr["reason"], 0) + 1
        topo["rts" if use_rts else "no_rts"] = {
            "throughput_mbps": r["throughput_mbps"],
            "collision_rate": r["collision_rate"],
            "wasted_ratio": r["wasted_ratio"],
            "collisions": r["collisions"],
            "attempts": r["attempts"],
            "dropped": r["dropped_frames"],
            "jain_short": r["jain_fairness_short_term"],
            "collision_reasons": reasons,
            "nav_frozen_us": [s["nav_frozen_us"] for s in r["per_station"]],
        }
    report["three_node"] = topo

    # ---- 4.2 隐藏终端农场：n 个站点围成一圈，互相听不到
    ring = []
    for n in (2, 4, 6, 8):
        row = {"stations": n}
        for use_rts in (False, True):
            sim, ap, stas = D.build_hidden_ring(n_stations=n, seed=11,
                                                use_rts=use_rts,
                                                rts_threshold=0)
            for s in stas:
                for _ in range(150):
                    sim.enqueue(s, ap.mac, 1500)
            r = sim.run()
            row["no_rts" if not use_rts else "rts"] = {
                "throughput_mbps": r["throughput_mbps"],
                "collision_rate": r["collision_rate"],
                "wasted_ratio": r["wasted_ratio"],
                "dropped": r["dropped_frames"],
                "jain_short": r["jain_fairness_short_term"],
            }
        row["gain"] = round(row["rts"]["throughput_mbps"]
                            / row["no_rts"]["throughput_mbps"], 4)
        ring.append(row)
    report["ring"] = ring

    # ---- 4.3 增益矩阵：速率 × 帧长（RTS/CTS 到底什么时候划算？）
    rates = [6.0, 12.0, 24.0, 54.0]
    sizes = [200, 500, 1000, 1500, 2304]
    matrix: List[List[float]] = []
    detail: List[Dict[str, object]] = []
    for rate in rates:
        row = []
        for size in sizes:
            vals = {}
            for use_rts in (False, True):
                sim, ap, stas = D.build_hidden_ring(
                    n_stations=8, seed=13, use_rts=use_rts, rts_threshold=0,
                    rate_mbps=rate)
                for s in stas:
                    for _ in range(80):
                        sim.enqueue(s, ap.mac, size)
                vals[use_rts] = sim.run()["throughput_mbps"]
            gain = vals[True] / vals[False] if vals[False] else 0.0
            row.append(round(gain, 4))
            detail.append({"rate_mbps": rate, "frame_bytes": size,
                           "no_rts_mbps": round(vals[False], 4),
                           "rts_mbps": round(vals[True], 4),
                           "gain": round(gain, 4)})
        matrix.append(row)
    report["gain_matrix"] = {"rates": rates, "sizes": sizes,
                             "gain": matrix, "detail": detail}

    viz.heatmap(matrix, os.path.join(OUT, "04_rts_gain_heatmap.png"),
                xticks=[str(s) for s in sizes],
                yticks=[f"{r:g} Mbps" for r in rates],
                title="RTS/CTS 吞吐增益（8 个隐藏终端，>1 表示划算）",
                xlabel="帧长（字节）", ylabel="物理层速率", cmap="RdYlGn")

    viz.line_plot(
        OrderedDict([
            ("无 RTS/CTS", [row["no_rts"]["throughput_mbps"] for row in ring]),
            ("启用 RTS/CTS", [row["rts"]["throughput_mbps"] for row in ring]),
        ]),
        os.path.join(OUT, "04_hidden_ring.png"),
        x=[row["stations"] for row in ring],
        title="隐藏终端农场：RTS/CTS 对吞吐的影响（1500B @54Mbps）",
        xlabel="隐藏站点数", ylabel="吞吐量 (Mbps)")

    viz.bar_plot(
        ["无 RTS/CTS", "启用 RTS/CTS"],
        [topo["no_rts"]["wasted_ratio"] * 100, topo["rts"]["wasted_ratio"] * 100],
        os.path.join(OUT, "04_wasted_airtime.png"),
        title="三节点隐藏终端：被碰撞浪费的空口时间占比", ylabel="%")

    # ---- 4.4 导出 pcap（碰撞帧置 Bad FCS）
    sim, ap, a, c = D.build_hidden_terminal(seed=7, use_rts=False,
                                            rts_threshold=0)
    for _ in range(60):
        sim.enqueue(a, ap.mac, 1500)
        sim.enqueue(c, ap.mac, 1500)
    sim.run()
    path = _pcap("04_hidden_terminal.pcap", sim.pcap_frames())
    report["pcap"] = _pcap_stats(path)
    _json("04_hidden.json", report)
    return report


# =================================================================== 5. edca
def exp_edca() -> Dict[str, object]:
    """实验 5 · EDCA 四类 QoS + 三机制消融实验。"""
    report: Dict[str, object] = {"experiment": "edca"}

    def run_mix(**kwargs) -> Dict[str, object]:
        sim, ap, stas = E.build_edca_bss(n_stations=3, seed=5, **kwargs)
        for name in stas:
            for ac, tid in ((E.AC_VO, 6), (E.AC_VI, 5), (E.AC_BE, 0),
                            (E.AC_BK, 2)):
                for _ in range(30):
                    sim.enqueue(name, ac, AP_MAC, 1000, tid=tid)
        return sim.run()

    full = run_mix()
    report["full"] = {
        "elapsed_us": full["elapsed_us"],
        "throughput_mbps": full["throughput_mbps"],
        "channel_utilization": full["channel_utilization"],
        "dropped": full["dropped_frames"],
        "per_ac": full["per_ac"],
    }
    order = [a.name for a in E.ALL_ACS]
    report["delay_ordering"] = [full["per_ac"][k]["avg_delay_us"]
                                for k in order]
    report["vo_bk_ratio"] = round(
        full["per_ac"]["AC_BK"]["avg_delay_us"]
        / max(full["per_ac"]["AC_VO"]["avg_delay_us"], 1e-9), 3)

    # ---- 消融实验
    ablations = OrderedDict([
        ("完整 EDCA", {}),
        ("关掉 AIFS 差异", {"enable_aifs": False}),
        ("关掉 CW 差异", {"enable_cw": False}),
        ("关掉 TXOP 突发", {"enable_txop": False}),
        ("全部关掉（=4 个 DCF 队列）", {"homogeneous": True}),
    ])
    table = []
    for label, kwargs in ablations.items():
        r = run_mix(**kwargs)
        table.append({
            "config": label,
            "vo_delay_us": r["per_ac"]["AC_VO"]["avg_delay_us"],
            "vi_delay_us": r["per_ac"]["AC_VI"]["avg_delay_us"],
            "be_delay_us": r["per_ac"]["AC_BE"]["avg_delay_us"],
            "bk_delay_us": r["per_ac"]["AC_BK"]["avg_delay_us"],
            "vo_p95_us": r["per_ac"]["AC_VO"]["p95_delay_us"],
            "dropped": r["dropped_frames"],
            "throughput_mbps": r["throughput_mbps"],
        })
    report["ablation"] = table

    viz.bar_plot(order, [full["per_ac"][k]["avg_delay_us"] for k in order],
                 os.path.join(OUT, "05_edca_delay.png"),
                 title="EDCA 四个接入类别的平均接入时延（3 站点满载）",
                 ylabel="平均时延 (us)")

    viz.line_plot(
        OrderedDict([
            (row["config"], [row["vo_delay_us"], row["vi_delay_us"],
                             row["be_delay_us"], row["bk_delay_us"]])
            for row in table]),
        os.path.join(OUT, "05_edca_ablation.png"), x=order,
        title="EDCA 消融实验：三种机制各自的贡献",
        xlabel="接入类别", ylabel="平均时延 (us)")

    # ---- 导出 pcap（用 TID 区分 AC）
    sim, ap, stas = E.build_edca_bss(n_stations=2, seed=3)
    E.traffic_mix(sim, stas, AP_MAC, n_vo=20, n_vi=12, n_be=8, n_bk=6)
    sim.run()
    path = _pcap("05_edca.pcap", sim.pcap_frames())
    report["pcap"] = _pcap_stats(path)
    report["tid_map"] = {a.name: [t for t, x in E.AC_BY_TID.items()
                                  if x.name == a.name]
                         for a in E.ALL_ACS}
    _json("05_edca.json", report)
    return report


# ================================================================ 6. airtime
def exp_airtime() -> Dict[str, object]:
    """实验 6 · 空口时间分析：速率 / 帧长 / 聚合 / 效率。"""
    report: Dict[str, object] = {"experiment": "airtime"}

    rate_rows = [{"rate_mbps": r, "airtime_us": round(t, 1),
                  "goodput_mbps": round(g, 4)}
                 for r, t, g in phy.rate_scan(1500)]
    report["rate_scan"] = rate_rows
    size_rows = [{"bytes": s, "airtime_us": round(t, 1),
                  "goodput_mbps": round(g, 4)}
                 for s, t, g in phy.size_scan()]
    report["size_scan"] = size_rows

    report["aggregation"] = [
        {"frames": n, "gain": round(phy.aggregation_gain(n, 1500), 4)}
        for n in (1, 2, 4, 8, 16, 32, 64)]

    report["example_timing"] = dict(
        phy.timing_breakdown(1500, 54.0).__dict__)

    # 关键结论：小帧的效率灾难
    report["efficiency_44B"] = round(phy.efficiency(44, 54.0), 4)
    report["efficiency_1500B"] = round(phy.efficiency(1500, 54.0), 4)

    # ---- 单帧传输的完整时序条（用于答辩画图）
    sim, ap, stas = D.build_bss(n_stations=1, spacing_m=10.0, seed=1)
    for _ in range(6):
        sim.enqueue(stas[0], ap.mac, 1500)
    sim.run()
    report["single_station_timeline"] = sim.timeline()[:12]

    viz.line_plot(
        OrderedDict([
            ("有效吞吐 (Mbps)", [r["goodput_mbps"] for r in rate_rows]),
            ("标称速率 (Mbps)", [r["rate_mbps"] for r in rate_rows]),
        ]),
        os.path.join(OUT, "06_rate_scan.png"),
        x=[r["rate_mbps"] for r in rate_rows],
        title="物理层速率 vs 实际有效吞吐（1500 字节帧）",
        xlabel="标称速率 (Mbps)", ylabel="Mbps")

    viz.line_plot(
        OrderedDict([
            ("空口时间 (us)", [r["airtime_us"] for r in size_rows]),
            ("有效吞吐 (Mbps)", [r["goodput_mbps"] for r in size_rows]),
        ]),
        os.path.join(OUT, "06_size_scan.png"),
        x=[r["bytes"] for r in size_rows],
        title="帧长对空口时间与有效吞吐的影响（54 Mbps）",
        xlabel="帧长（字节）", ylabel="us 或 Mbps")

    viz.line_plot(
        {"聚合增益": [d["gain"] for d in report["aggregation"]]},
        os.path.join(OUT, "06_aggregation.png"),
        x=[d["frames"] for d in report["aggregation"]],
        title="A-MPDU 聚合：n 帧聚合相对单帧的增益",
        xlabel="聚合帧数", ylabel="增益倍数")

    _json("06_airtime.json", report)
    return report


# ==================================================================== 7. pcap
def exp_pcap() -> Dict[str, object]:
    """实验 7 · 导出 Radiotap+802.11 pcap（linktype 127），Wireshark 直读。"""
    report: Dict[str, object] = {"experiment": "pcap"}

    # ---- 7.1 混合场景：4 个站点 + 隐藏终端 + 重传
    sim, ap, stas = D.build_hidden_ring(n_stations=4, seed=23,
                                        rts_threshold=0)
    for s in stas:
        for _ in range(40):
            sim.enqueue(s, ap.mac, 1200)
    r = sim.run()
    path = _pcap("07_wlan_full.pcap", sim.pcap_frames())
    report["mixed"] = _pcap_stats(path)
    report["mixed"]["throughput_mbps"] = r["throughput_mbps"]
    report["mixed"]["collision_rate"] = r["collision_rate"]

    # ---- 7.2 管理帧 + 数据帧混合
    sta = STA_MACS[0]
    frames: List[Tuple[float, bytes]] = []
    t = 0.0
    for mf in (F.beacon_frame(AP_MAC, "NetLab-5G", channel=6, seq=0),
               F.probe_request(sta, "NetLab-5G"),
               F.auth_frame(sta, AP_MAC, seq=1),
               F.assoc_request(sta, AP_MAC, "NetLab-5G", seq=2),
               F.data_frame(sta, AP_MAC, AP_MAC, b"GET / HTTP/1.1",
                            seq=3, tid=0),
               F.ack_frame(sta),
               F.rts_frame(AP_MAC, sta),
               F.cts_frame(AP_MAC)):
        radio = F.Radiotap(tsft=int(t * 1e6), flags=F.RT_FLAG_FCS,
                           rate_mbps=24.0, channel=6, signal_dbm=-42)
        frames.append((t, F.build_frame(mf, radio)))
        t += 0.001
    path2 = _pcap("07_wlan_frames.pcap", frames)
    report["frame_zoo"] = _pcap_stats(path2)

    # ---- 7.3 内置解析器回读（不依赖 Wireshark）
    linktype, packets = read_pcap(path)
    decoded = []
    step = max(1, len(packets) // 12)
    for p in packets[::step][:12]:
        radio, mf = F.parse_frame(p.data)
        decoded.append({
            "t": round(p.ts, 6),
            "radio": radio.describe(),
            "mac": mf.describe(),
            "bad_fcs": bool(radio.flags & F.RT_FLAG_BAD_FCS),
        })
    report["decoded_sample"] = decoded
    report["decode_ok"] = len(decoded) > 0

    # ---- 7.4 显示过滤器清单（答辩时照着敲）
    #
    # ``wlan.fc.type_subtype`` 是 ``(subtype << 4) | type`` 拼出来的，
    # **不是** subtype 本身。写裸 subtype 数字一个帧都匹配不到：
    #   Beacon  (type 0, subtype 8)  → 128
    #   QoS Data(type 2, subtype 8)  → 130
    #   ACK     (type 1, subtype 13) → 209
    #   RTS     (type 1, subtype 11) → 177
    #   CTS     (type 1, subtype 12) → 193
    report["display_filters"] = [
        "wlan", "wlan_radio",
        "wlan.fc.type == 1",            # 控制帧（RTS/CTS/ACK）
        "wlan.fc.type_subtype == 128",  # Beacon
        "wlan.fc.type_subtype == 130",  # QoS Data
        "wlan.fc.type_subtype == 209",  # ACK
        "wlan.fc.type_subtype == 177",  # RTS
        "wlan.fc.type_subtype == 193",  # CTS
        "wlan.fc.retry == 1",
        "wlan_radio.fcs_bad == 1",
        "wlan_radio.data_rate == 54",
        "wlan.qos.tid == 6",
    ]
    report["tshark_available"] = tshark_available()
    if tshark_available():
        report["tshark"] = tshark_summary(path, "wlan", limit=8)

    _json("07_pcap.json", report)
    return report


# ------------------------------------------------------------------ 注册表
SCENARIOS = OrderedDict([
    ("frames", exp_frames),
    ("management", exp_management),
    ("dcf", exp_dcf),
    ("hidden", exp_hidden),
    ("edca", exp_edca),
    ("airtime", exp_airtime),
    ("pcap", exp_pcap),
])


def run_all() -> Dict[str, object]:
    out = OrderedDict()
    for name, fn in SCENARIOS.items():
        out[name] = fn()
    return out
