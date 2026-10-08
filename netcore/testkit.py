"""测试与实验脚手架。

三个作用：

1. :func:`bootstrap` —— 让任意项目目录下的脚本都能 ``import netcore``，
   无需 pip 安装；
2. :func:`outdir` —— 统一的产物目录（pcap / 图 / 报告）；
3. :func:`tcp_analysis` 等断言辅助 —— 把"协议是否正确"写成可执行断言。
"""

from __future__ import annotations

import os
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def bootstrap() -> str:
    """把仓库根目录加入 ``sys.path``，返回根目录路径。"""
    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)
    return REPO_ROOT


def project_root(name: str) -> str:
    return os.path.join(REPO_ROOT, "projects", name)


def outdir(name: str) -> str:
    """返回 ``projects/<name>/out`` 并确保存在。"""
    path = os.path.join(project_root(name), "out")
    os.makedirs(path, exist_ok=True)
    return path


def artifact(name: str, filename: str) -> str:
    return os.path.join(outdir(name), filename)


def run_tests(test: unittest.TestCase | type) -> unittest.TestResult:
    """运行单个测试用例并返回结果（供 demo 脚本自检）。"""
    suite = unittest.TestLoader().loadTestsFromTestCase(
        test if isinstance(test, type) else type(test)
    )
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


def assert_pcap_parsable(tc: unittest.TestCase, path: str, min_packets: int = 1) -> list:
    """断言 pcap 可被内置解析器完整解析，返回解析结果列表。"""
    from . import dissect
    tc.assertTrue(os.path.exists(path), f"pcap 不存在：{path}")
    items = dissect.load_pcap(path)
    tc.assertGreaterEqual(len(items), min_packets, "pcap 报文数不足")
    for d in items:
        tc.assertNotEqual(d.proto, "NON-IP", f"第 {d.index} 帧不是 IPv4 报文")
    return items


def assert_tcp_handshake(tc: unittest.TestCase, items: list) -> None:
    from . import dissect
    tc.assertTrue(dissect.tcp_stream_stats(items)["handshake_ok"], "未观察到完整三次握手")


def assert_tcp_teardown(tc: unittest.TestCase, items: list) -> None:
    from . import dissect
    tc.assertTrue(dissect.tcp_stream_stats(items)["teardown_ok"], "未观察到完整四次挥手")
