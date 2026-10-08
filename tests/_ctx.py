"""测试公共上下文：把项目根目录与仓库根目录加进 sys.path。"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.abspath(os.path.join(HERE, ".."))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
for _p in (PROJ, ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

OUT = os.path.join(PROJ, "out")
os.makedirs(OUT, exist_ok=True)
