#!/usr/bin/env python3
"""项目 10 命令行入口：802.11 CSMA/CA 无线实验室。

用法示例::

    python3 demo.py list          # 列出全部实验
    python3 demo.py frames        # 实验 1：帧编解码 + Radiotap + FCS
    python3 demo.py management    # 实验 2：Beacon/Probe/Auth/Assoc 关联流程
    python3 demo.py dcf           # 实验 3：DCF 站点数扫描
    python3 demo.py hidden        # 实验 4：隐藏终端 vs RTS/CTS（核心）
    python3 demo.py edca          # 实验 5：EDCA 四类 QoS + 消融
    python3 demo.py airtime       # 实验 6：空口时间分析
    python3 demo.py pcap          # 实验 7：导出 Radiotap+802.11 pcap
    python3 demo.py all           # 全部跑一遍
    python3 demo.py gui           # 图形界面（空口舞台动画 + 统计图表）
    python3 demo.py selftest      # 界面自检：所有选项卡/讲解步骤/导出跑一遍
    python3 demo.py shot          # 自动截 11 张界面截图到 shot/（报告配图用）

    python3 demo.py timeline out/07_wlan_full.pcap   # 打印空口时间线
    python3 demo.py dump out/07_wlan_full.pcap       # 用内置解析器逐帧打印
    python3 demo.py tshark out/07_wlan_full.pcap     # 调用 tshark（需装 Wireshark）
    python3 demo.py test          # 运行全部单元测试（333 个）
"""
from __future__ import annotations

import argparse
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))

from netcore.pcap import read_pcap, tshark_available, tshark_summary  # noqa: E402

from wlanlab import dcf as D  # noqa: E402
from wlanlab import edca as E  # noqa: E402
from wlanlab import frame as F  # noqa: E402
from wlanlab import phy  # noqa: E402
from wlanlab import scenarios as S  # noqa: E402

OUT = os.path.join(HERE, "out")


def cmd_list() -> None:
    print("可用实验（每个实验都会在 out/ 下产出 pcap / json / png）：")
    for name, fn in S.SCENARIOS.items():
        doc = (fn.__doc__ or "").strip().splitlines()[0]
        print(f"  {name:<12} {doc}")
    print("\n辅助命令：")
    print("  timeline <pcap>  按时间顺序打印空口事件")
    print("  dump <pcap>      用内置解析器逐帧打印 Radiotap + 802.11")
    print("  tshark <pcap>    调用 tshark（需安装 Wireshark）")
    print("  test             运行全部单元测试")
    print("  gui              启动图形界面（空口舞台动画 + 统计图表）")
    print("  selftest         界面自检：选项卡 / 讲解步骤 / 导出全跑一遍")
    print("  shot [目录]      自动截界面截图（报告配图用，默认 shot/）")


def _run(name: str) -> dict:
    print(f"\n===== 实验 {name} =====")
    result = S.SCENARIOS[name]()
    for key, value in result.items():
        if key in ("experiment", "frame_matrix", "handshake", "sweep",
                   "ring", "ablation", "per_ac", "per_queue", "detail",
                   "decoded_sample", "rate_scan", "size_scan",
                   "aggregation", "single_station_timeline",
                   "backoff_sequence", "collision_reasons", "collision_trace",
                   "display_filters", "mgmt_fixed_len", "ie_names",
                   "tid_map", "three_node", "gain_matrix", "full"):
            continue
        print(f"  {key}: {value}")
    print(f"  → 产物已写入 {OUT}/")
    return result


def cmd_frames() -> None:
    r = _run("frames")
    print("\n帧类型矩阵：")
    print(f"  {'帧类型':<18}{'子类型':<14}{'头':>4}{'总长':>6}  往返")
    for row in r["frame_matrix"]:
        print(f"  {row['frame']:<18}{row['subtype']:<14}"
              f"{row['header_bytes']:>4}{row['total_bytes']:>6}  "
              f"{'✓' if row['roundtrip_ok'] else '✗'}")
    print(f"\nBeacon IE：{r['beacon_ies']}")
    print(f"Radiotap：{r['radiotap']['describe']}"
          f"（{r['radiotap']['header_bytes']} 字节，8 字节对齐）")
    print(f"CRC-32 已知向量 123456789 → {r['fcs']['crc32_known_vector']}")


def cmd_management() -> None:
    r = _run("management")
    print("\n关联流程：")
    for s in r["handshake"]:
        print(f"  {s['step']}. t={s['t_us']:>8.1f}us  {s['frame']:<20}"
              f"{s['type_subtype']:<22}{s['bytes']:>4}B")
        print(f"     {s['note']}")


def cmd_dcf() -> None:
    r = _run("dcf")
    print(f"\n{'站点数':>6}{'吞吐Mbps':>10}{'碰撞率':>9}{'利用率':>9}"
          f"{'浪费率':>9}{'短时Jain':>10}{'丢弃':>6}")
    for row in r["sweep"]:
        print(f"{row['stations']:>6}{row['throughput_mbps']:>10.2f}"
              f"{row['collision_rate']:>9.3f}{row['channel_utilization']:>9.3f}"
              f"{row['wasted_ratio']:>9.3f}{row['jain_short']:>10.3f}"
              f"{row['dropped']:>6}")
    print(f"\n碰撞原因分布：{r['collision_reasons']}")


def cmd_hidden() -> None:
    r = _run("hidden")
    print("\n【三节点隐藏终端】A 与 C 相距 160m 互相听不到，都听得到 AP")
    print(f"  {'配置':<12}{'吞吐Mbps':>10}{'碰撞率':>9}{'浪费率':>9}{'丢弃':>6}")
    for key, label in (("no_rts", "无 RTS/CTS"), ("rts", "启用 RTS/CTS")):
        row = r["three_node"][key]
        print(f"  {label:<12}{row['throughput_mbps']:>10.2f}"
              f"{row['collision_rate']:>9.3f}{row['wasted_ratio']:>9.3f}"
              f"{row['dropped']:>6}")
    print(f"  碰撞原因：无 RTS={r['three_node']['no_rts']['collision_reasons']}"
          f"，有 RTS={r['three_node']['rts']['collision_reasons']}")

    gm = r["gain_matrix"]
    print("\n【RTS/CTS 增益矩阵】行=物理层速率，列=帧长（字节），>1 表示划算")
    header = "  " + " " * 10 + "".join(f"{s:>9}" for s in gm["sizes"])
    print(header)
    for rate, row in zip(gm["rates"], gm["gain"]):
        cells = "".join(f"{v:>9.3f}" for v in row)
        print(f"  {rate:>6.0f}Mbps{cells}")
    best = max(gm["detail"], key=lambda d: d["gain"])
    worst = min(gm["detail"], key=lambda d: d["gain"])
    print(f"\n  最划算：{best['rate_mbps']:g}Mbps / {best['frame_bytes']}B "
          f"→ 增益 {best['gain']:.3f}×")
    print(f"  最亏本：{worst['rate_mbps']:g}Mbps / {worst['frame_bytes']}B "
          f"→ 增益 {worst['gain']:.3f}×")


def cmd_edca() -> None:
    r = _run("edca")
    order = ["AC_VO", "AC_VI", "AC_BE", "AC_BK"]
    print(f"\n{'AC':<8}{'AIFS':>6}{'CWmin':>7}{'TXOP':>8}{'成功':>6}"
          f"{'碰撞率':>9}{'平均时延us':>12}{'P95':>10}{'抖动':>9}")
    for ac in order:
        v = r["full"]["per_ac"][ac]
        print(f"{ac:<8}{v['aifs_us']:>6.0f}{v['cw_min']:>7}{v['txop_us']:>8.0f}"
              f"{v['successes']:>6}{v['collision_rate']:>9.3f}"
              f"{v['avg_delay_us']:>12.1f}{v['p95_delay_us']:>10.1f}"
              f"{v['avg_jitter_us']:>9.1f}")
    print(f"\n  VO/BK 时延比 = {r['vo_bk_ratio']:.2f}×")
    print("\n【消融实验】")
    print(f"  {'配置':<26}{'VO':>10}{'VI':>10}{'BE':>10}{'BK':>10}{'丢弃':>6}")
    for row in r["ablation"]:
        print(f"  {row['config']:<26}{row['vo_delay_us']:>10.0f}"
              f"{row['vi_delay_us']:>10.0f}{row['be_delay_us']:>10.0f}"
              f"{row['bk_delay_us']:>10.0f}{row['dropped']:>6}")


def cmd_airtime() -> None:
    r = _run("airtime")
    print(f"\n{'速率Mbps':>9}{'空口时间us':>12}{'有效吞吐Mbps':>14}{'效率':>8}")
    for row in r["rate_scan"]:
        eff = row["goodput_mbps"] / row["rate_mbps"]
        print(f"{row['rate_mbps']:>9.0f}{row['airtime_us']:>12.0f}"
              f"{row['goodput_mbps']:>14.2f}{eff:>8.3f}")
    print(f"\n{'帧长B':>7}{'空口时间us':>12}{'有效吞吐Mbps':>14}")
    for row in r["size_scan"]:
        print(f"{row['bytes']:>7}{row['airtime_us']:>12.0f}"
              f"{row['goodput_mbps']:>14.2f}")
    print("\n聚合增益：")
    print("  " + "  ".join(f"{d['frames']}帧={d['gain']:.3f}×"
                           for d in r["aggregation"]))
    print(f"\n单帧时序：{r['example_timing']}")


def cmd_pcap() -> None:
    r = _run("pcap")
    for key in ("mixed", "frame_zoo"):
        row = r[key]
        print(f"\n{row['path']}：{row['packets']} 帧 / {row['bytes']} 字节"
              f"（linktype={row['linktype']}）")
        for k, v in sorted(row["kinds"].items()):
            print(f"    {k:<24}{v:>5}")
        print(f"    重传帧 {row['retry_frames']}，"
              f"Bad FCS {row['bad_fcs_frames']}")
    print("\nWireshark 显示过滤器：")
    for f in r["display_filters"]:
        print(f"    {f}")


def _load(path: str):
    if not os.path.isabs(path):
        cand = os.path.join(OUT, path)
        if os.path.exists(cand):
            path = cand
    if not os.path.exists(path):
        print(f"文件不存在：{path}")
        sys.exit(1)
    return read_pcap(path)


def cmd_timeline(path: str) -> None:
    linktype, packets = _load(path)
    print(f"{os.path.basename(path)}：{len(packets)} 帧，linktype={linktype}")
    print(f"  {'时间us':>10}  {'类型':<10}{'源':<20}{'目的':<20}{'长度':>6}")
    for pkt in packets:
        try:
            rt, mf = F.parse_frame(pkt.data)
        except Exception as exc:                       # pragma: no cover
            print(f"  {pkt.ts * 1e6:>10.1f}  <解析失败 {exc}>")
            continue
        flag = " [BadFCS]" if rt.flags & F.RT_FLAG_BAD_FCS else ""
        retry = " [Retry]" if mf.fc.retry else ""
        print(f"  {pkt.ts * 1e6:>10.1f}  {mf.fc.subtype_name:<10}"
              f"{mf.addr2:<20}{mf.addr1:<20}{len(mf.payload):>6}"
              f"{flag}{retry}")


def cmd_dump(path: str) -> None:
    linktype, packets = _load(path)
    print(f"{os.path.basename(path)}：{len(packets)} 帧，linktype={linktype}")
    for i, pkt in enumerate(packets[:40], 1):
        rt, mf = F.parse_frame(pkt.data)
        print(f"\n--- 帧 {i} @ t={pkt.ts:.6f}s ({len(pkt.data)} 字节) ---")
        print(f"    Radiotap : {rt.describe()}")
        print(f"    802.11   : {mf.describe()}")
        if mf.fc.type == F.FRAME_TYPE_MGMT:
            ies = F.mgmt_ies(mf)
            if ies:
                print(f"    IE       : "
                      f"{[(i, F.IE_NAMES.get(i, '?'), len(v)) for i, v in ies]}")
        if mf.fcs is not None:
            print(f"    FCS      : 0x{mf.fcs:08x}")


def cmd_tshark(path: str) -> None:
    if not tshark_available():
        print("未找到 tshark。请安装 Wireshark 后重试：")
        print("  macOS : brew install --cask wireshark")
        print("  Ubuntu: sudo apt install tshark")
        print("\n本项目不依赖 Wireshark 也能跑：demo.py dump 用的是内置解析器。")
        return
    _load(path)
    print(f"tshark 摘要（{path}）：")
    for line in tshark_summary(path, "wlan", limit=20):
        print("  " + line)
    print("\ntshark 空口速率统计：")
    for line in tshark_summary(path, "wlan_radio.data_rate", limit=10):
        print("  " + line)


def cmd_test() -> None:
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(HERE, "tests"), top_level_dir=HERE)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


def cmd_gui() -> None:
    """启动图形界面（Tkinter 原生窗口 + 空口舞台动画 + 统计图表）。"""
    from gui.app import main as gui_main

    gui_main()


def cmd_selftest() -> None:
    """界面自检：把选项卡 / 讲解步骤 / 导出全跑一遍并报告结果。"""
    from gui import selftest

    sys.exit(selftest.main())


def cmd_shot(outdir: str = "") -> None:
    """自动截取界面截图（报告配图用）。"""
    from gui import shot

    if outdir:
        sys.argv = [sys.argv[0], outdir]
    sys.exit(shot.main())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="802.11 CSMA/CA 无线实验室",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", nargs="?", default="list",
                        help="实验名或辅助命令")
    parser.add_argument("arg", nargs="?", help="辅助命令的参数（如 pcap 路径）")
    args = parser.parse_args()

    cmd = args.command
    if cmd == "list":
        cmd_list()
    elif cmd in S.SCENARIOS:
        globals()[f"cmd_{cmd}"]()
    elif cmd == "all":
        for name in S.SCENARIOS:
            globals()[f"cmd_{name}"]()
        print("\n全部 7 个实验完成。")
    elif cmd == "timeline":
        cmd_timeline(args.arg or "07_wlan_full.pcap")
    elif cmd == "dump":
        cmd_dump(args.arg or "07_wlan_full.pcap")
    elif cmd == "tshark":
        cmd_tshark(args.arg or "07_wlan_full.pcap")
    elif cmd == "test":
        cmd_test()
    elif cmd == "gui":
        cmd_gui()
    elif cmd == "selftest":
        cmd_selftest()
    elif cmd == "shot":
        cmd_shot(args.arg or "")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
