"""pytest 全局配置：给每个测试装上「真实出网熔断」。

放在 conftest.py 里用 autouse，是为了**无法绕过**：新写的测试哪怕忘了 mock，
也会立刻被熔断拦住，而不是悄悄连出去。

子进程不受影响 —— 熔断只 patch 当前测试进程的 socket；
`live_server` / `rate_limited_server` 这类集成测试起的是子进程，
它们连 127.0.0.1 照常工作（回环被显式放行）。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# 让 tests/ 自身可被 import（testkit 就在里面）
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

import testkit  # noqa: E402


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """任何非本机的出网连接 → 测试失败。

    这是拆包期间的保险丝：模块搬家会让 `monkeypatch.setattr(app, ...)` 静默失效，
    失效的表现是「测试真的去联网」，而不是报错。装了这道闸之后，
    漏 mock 会立刻炸在发生的地方。
    """
    testkit.fail_on_real_network(monkeypatch)
    yield
