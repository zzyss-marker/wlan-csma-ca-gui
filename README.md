# 基于 Python 的 IEEE 802.11 CSMA/CA 协议仿真与可视化分析平台

纯 Python 实现的 802.11 DCF / EDCA 仿真 + tkinter 可视化：
把「隐藏终端 → 碰撞 → 退避 → 重传」整段过程画成可以任意倍速回放的空口动画。

## 下载 Windows 可执行文件

看 **Releases** 里的 `WlanLab-CSMA-CA.exe`：单文件、免安装，Win10 / Win11 64 位直接双击。
导出的 CSV / pcap 落在 exe 同级目录的 `out/` 里。

首次启动需要 3～8 秒（单文件 exe 要先解压到临时目录），属正常现象。

## 从源码运行

只需要 Python 3.9+ 和 matplotlib，仿真核心零第三方依赖：

```bash
pip install matplotlib
python run_gui.py        # 等价于 python demo.py gui
```

## 命令行跑实验

```bash
python demo.py list        # 列出全部实验
python demo.py hidden      # 隐藏终端 vs RTS/CTS（核心实验）
python demo.py dcf         # DCF 站点数扫描
python demo.py edca        # EDCA 四类 QoS 分层
python demo.py airtime     # 空口时间分析
python demo.py pcap        # 导出 Radiotap + 802.11 抓包文件
python demo.py all         # 全部跑一遍
python demo.py test        # 单元测试
```

## 界面结构

| 选项卡 | 内容 |
| --- | --- |
| 空口舞台 | 动画回放 + 参数调节 + 实时指标，底部是空口时间轴 |
| 讲解模式 | 九步走脚本，每步「说一句 + 真的动一下界面」 |
| 实验图表 | 四张图现场计算（站点数扫描 / RTS 增益热力图 / EDCA 时延 / 空口时间） |
| 数据明细 | 每站点统计表，可导出 CSV |
| 术语与说明 | 术语表、图例、Wireshark 过滤器、已知局限 |

导出的 pcap 把仿真里判定的碰撞写进 Radiotap 的 Bad FCS 位，
所以在 Wireshark 里用 `wlan_radio.fcs_bad == 1` 就能直接过滤出碰撞帧，与仿真结果交叉验证。

## 打包成 exe

```bash
pip install -r requirements-build.txt
pyinstaller wlanlab_gui.spec      # 产物 dist/WlanLab-CSMA-CA.exe
```

GitHub Actions 里用 `windows-latest` 自动构建（macOS / Linux 无法交叉打包 Windows exe）。

## 已知局限

- 距离模型是硬阈值（范围内即可听到），没有衰落、阴影、多径。
- 没有捕获效应：两帧重叠即判碰撞。
- 没有信道误码，碰撞是唯一丢包来源。
- 没有速率自适应、MIMO、OFDMA。
- 未在真实网卡上验证（需要 Linux + `mac80211_hwsim`）。
