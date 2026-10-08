"""802.11 CSMA/CA 无线实验室：帧编解码 / DCF / EDCA / 空口时间。

模块划分：

* :mod:`wlanlab.frame`     —— IEEE 802.11 MAC 帧 + Radiotap + FCS + IE
* :mod:`wlanlab.phy`       —— OFDM 空口时间 / 速率扫描 / 聚合增益
* :mod:`wlanlab.dcf`       —— DCF 离散事件仿真 + 隐藏终端 + RTS/CTS + NAV
* :mod:`wlanlab.edca`      —— 802.11e EDCA 四类 QoS + 三机制消融
* :mod:`wlanlab.scenarios` —— 7 个可复现实验
"""

__all__ = ["frame", "phy", "dcf", "edca", "scenarios"]
