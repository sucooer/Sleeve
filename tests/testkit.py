"""模块化拆分的测试基础设施：跨模块「接缝」补丁 + 真实出网熔断。

**背景：150 处 mock 为什么在拆包后会失去意义**

`tests/test_app.py` 有 150 处 `patch_seam(monkeypatch, "fetch_json", fake)`
这类写法（原本是 `monkeypatch.setattr(app, ...)`）。模块搬家之后，`app.py`
不再是 `fetch_json` 的**唯一**绑定点：

    src/app.py            → re-export（门面）
    src/net.py            → 定义 fetch_json
    src/report/album_builder.py → 调 fetch_json

只补门面 `app.fetch_json`，而 `album_builder` 调的是**它自己模块里**那个名字 ——
于是一次真实的网络请求被放出去，测试变慢、偶发失败、CI 随机红灯。**这类失效
不报错**，是最难排查的一种。

拆包要配三件事，缺一不可：

1. **`patch_seam()`**（本模块）：把名字在**所有绑定它的模块**上一起打补丁。
   调用点从 `monkeypatch.setattr(app, ...)` 改成 `patch_seam(monkeypatch, ...)`，
   拆包后仍然生效 —— 测试代码不用跟着实现搬家而反复改。
2. **`fail_on_real_network()`**（本模块）：任何**真实**的出网连接直接熔断报错。
   万一漏了一处，测试是**响亮地失败**，而不是安静地出网。
3. **统一取名 + 禁止两种写法**（配合一条守卫测试）：
   patch_seam 按**名字**打补丁，所以下面两种情况它够不到 ——

     from .net import fetch_json as http_get    # ① 别名：换了名字
     def f(cb=fetch_json): ...                  # ② 导入期捕获：绑进了默认参数/字典

   实测确认（`tests/test_testkit.py` 有对照用例）：

     写法                                  只补门面    patch_seam
     def f(): return fetch_json(u)          ✓          ✓
     def f(): return net.fetch_json(u)      ✓          ✓
     from .net import fetch_json as other   ✗          ✗   ← 名字不同，够不到
     def f(cb=fetch_json)                   ✗          ✗   ← 导入期就绑死了

   **好消息**：当前代码库里这两种写法**一处都没有**（已用 grep 核实）。
   所以只要守住这条约定，patch_seam 就足够；守卫测试会拦住将来有人破坏它。

注意 `patch_seam` 解决的是「补丁打不到」；第 3 条解决的是「写法本身就不该出现」。
"""

from __future__ import annotations

import ipaddress
import os
import socket
import sys
from pathlib import Path
from typing import Any

# app.py 不在包里（src/ 没有 __init__.py），所以直接把 src 加进 sys.path
_REPO = Path(__file__).resolve().parents[1]
_SRC = _REPO / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import app  # noqa: E402

# 允许直连的主机（本机回环）。测试只允许连这里，其它一律熔断。
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "", None})

# patch_seam 调用非常频繁（单测里上百次），每次重扫 sys.modules 会明显拖慢测试 ——
# 而且 **不能** 用「比较 sys.modules 的键集合」来判断是否变化：那本身就是 O(n)
# 的集合构造，n 会随测试进程不断增长（实测这一步就能把整个套件拖到卡住）。
#
# 改用**便宜的版本号**：只在 sys.modules 的字典大小变化时重扫。
# 大小变化是「有新模块被导入」的充分近似 —— 本项目的模块是导入后就不再增删的，
# 所以足够；真需要强制重扫时调 refresh_modules()。
_MODULE_CACHE: tuple[int, list[Any]] | None = None


def _sleeve_modules() -> list[Any]:
    """所有 sleeve 模块（门面 app + 它的全部兄弟模块）。

    判定方式：**源码文件位于 src/ 目录下**（`app.py` 自己也在此目录）。

    为什么不用「名字以 app. 开头」这种前缀判断：那只能匹配 `app.<...>` 包结构，
    而本项目的拆分目标是**平级兄弟模块**（src/net.py、src/parsers/ototoy.py …），
    它们既不是 app 的子模块、也不以 app 开头。用前缀判断会让这些模块被静默漏掉 ——
    补丁打不到真正的调用点，测试就会真的去联网。

    用「文件路径」判断还有一个好处：stdlib / site-packages 里的模块天然被排除，
    不会误伤。
    """
    global _MODULE_CACHE
    version = len(sys.modules)
    if _MODULE_CACHE is not None and _MODULE_CACHE[0] == version:
        return _MODULE_CACHE[1]

    src_root = _SRC.resolve()
    app_file = str(src_root / "app.py")
    prefix = str(src_root) + os.sep
    modules: list[Any] = []
    for module in sys.modules.values():
        module_path = getattr(module, "__file__", None)
        if not module_path:
            continue
        # 用纯字符串比较，不做 Path.resolve() —— 后者对每个模块都是一次
        # 文件系统调用，2000+ 个模块下单次重扫要 100ms 以上（实测）。
        # 规范化一下就够了：sys.modules 里第三方 / stdlib 的路径天然不匹配。
        normalized = os.path.normpath(module_path)
        if normalized == app_file or normalized.startswith(prefix):
            modules.append(module)
    # app 排最前，报错信息里优先指向它（名字写错时更好定位）
    modules.sort(key=lambda m: 0 if m is app else 1)
    _MODULE_CACHE = (version, modules)
    return modules


def refresh_modules() -> None:
    """丢掉模块清单缓存；需要强制重扫时调用。"""
    global _MODULE_CACHE
    _MODULE_CACHE = None


def patch_seam(
    monkeypatch: Any,
    name: str,
    value: Any,
    raising: bool = True,
) -> Any:
    """把 `name` 在**所有绑定它的 sleeve 模块**上一起打补丁。

    用途：`monkeypatch.setattr(app, "fetch_json", fake)` 的拆包安全版本。

    现在的行为与直接对 app 打补丁一致（拆包前只有一个模块）；拆包后
    `fetch_json` 同时存在于门面与各子模块时，**每一处都会被打上** ——
    于是「函数搬了家」不会让 mock 静默失效。

    `raising` 语义与 `monkeypatch.setattr` 相同：目标上不存在这个属性时是否报错。
    `raising=True`（默认）是我们要的 —— 名字写错时**响亮地失败**。

    **够不到的情况**（见模块文档，代码库里已核实为零处）：
      - 别名导入（`from .net import fetch_json as other`）
      - 导入期捕获（默认参数、模块级字典里存了函数对象）
    """
    targets = [module for module in _sleeve_modules() if hasattr(module, name)]
    if not targets:
        # 谁都没有这个属性：交给 monkeypatch 去抛 AttributeError（raising=True 时），
        # 报错信息里会带上 app，便于定位名字写错的情况。
        targets = [app]
    for module in targets:
        monkeypatch.setattr(module, name, value, raising=raising)
    return value


# ------------------------------------------------------------------ 出网熔断


class RealNetworkAccessError(AssertionError):
    """测试里出现了真实出网连接。

    故意继承 AssertionError：这是测试断言失败，不是被测代码的业务异常。
    """


def _is_local(host: Any) -> bool:
    if host in _LOCAL_HOSTS:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", errors="replace")
    return isinstance(host, str) and host.startswith("127.")


def _is_literal_ip(host: Any) -> bool:
    """host 是否已经是字面量 IP（不需要 DNS）。

    区分这个很关键：`getaddrinfo("169.254.169.254", 80)` 是**纯本地**调用，
    不发任何包 —— `check_outbound` 正是靠它来判定「这个地址能不能去」，
    然后在真的连出去之前拒绝。把这类调用也当成「出网」会误伤一批合法的
    SSRF 校验测试。真正要拦的是**需要 DNS 的域名解析**。
    """
    if not isinstance(host, str) or not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _block(kind: str, host: Any) -> RealNetworkAccessError:
    return RealNetworkAccessError(
        f"测试里出现了真实出网连接（{kind}: {host!r}）。\n"
        "单元测试必须全部离线：请把对应的网络函数 mock 掉"
        "（用 tests/testkit.py 的 patch_seam(monkeypatch, ...)）。\n"
        "如果你确实需要连本机服务，只允许 127.0.0.1 / localhost / ::1。"
    )


def fail_on_real_network(monkeypatch: Any) -> None:
    """让任何非本机的出网连接**直接报错**，而不是悄悄连出去。

    这是拆包期间的保险丝：只要有一处 mock 因模块搬家而失效，这里就会立刻
    把「安静地真的联网」变成「响亮地测试失败」。没有它，这类失效只会表现为
    CI 偶发变慢或间歇性红灯，极难归因。

    覆盖三个入口（urllib 三条路径都会经过其中之一）：
      - `socket.getaddrinfo`      —— DNS 解析（**字面量 IP 放行**，那不发包）
      - `socket.socket.connect`   —— 实际连接
      - `socket.create_connection`—— http.client 走的便捷入口

    只放行本机回环：live_server 类的集成测试要连 127.0.0.1，子进程不受影响
    （它在另一个进程里，本补丁只作用于当前测试进程）。
    """
    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect
    real_create_connection = socket.create_connection

    def guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
        # 字面量 IP 不需要 DNS，放行；随后 connect 那层仍会拦住非回环目标
        if not _is_local(host) and not _is_literal_ip(host):
            raise _block("DNS 解析", host)
        return real_getaddrinfo(host, *args, **kwargs)

    def guarded_connect(self: Any, address: Any):  # type: ignore[no-untyped-def]
        host = address[0] if isinstance(address, (tuple, list)) and address else address
        if not _is_local(host):
            raise _block("socket.connect", host)
        return real_connect(self, address)

    def guarded_create_connection(address: Any, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
        host = address[0] if isinstance(address, (tuple, list)) and address else address
        if not _is_local(host):
            raise _block("create_connection", host)
        return real_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "create_connection", guarded_create_connection)
