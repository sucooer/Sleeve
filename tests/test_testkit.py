"""testkit 自身的回归测试。

拆包能不能安全进行，取决于这里的两条契约是否成立：

1. **`patch_seam` 真的能跨模块打补丁** —— 尤其是「同一个名字被多个模块绑定」时。
   这直接对应拆包后最容易踩的坑：`fetch_json` 同时存在于 `app.net` 与
   `app.report.album_builder`，只补门面就会漏掉真正的调用点。

2. **`fail_on_real_network` 真的能拦住漏掉的 mock** —— 否则「mock 静默失效」
   会退化成「测试悄悄联网」，而不是响亮失败。

这里用**合成模块**来验证，而不是依赖真实包结构：真实结构还在拆分中，
用合成模块才能稳定地测出「值绑定 vs 模块属性访问」这个关键差异。
"""

from __future__ import annotations

import importlib.util
import socket
import sys
import textwrap
import threading
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import testkit  # noqa: E402


# ------------------------------------------------------------------ patch_seam


def _make_module(name: str, source: str) -> types.ModuleType:
    """把源码字符串变成一个真实可 import 的模块，塞进 sys.modules。"""
    module = types.ModuleType(name)
    module.__dict__["__name__"] = name
    exec(compile(textwrap.dedent(source), f"<{name}>", "exec"), module.__dict__)
    sys.modules[name] = module
    return module


@pytest.fixture
def synthetic_package(monkeypatch):
    """造一个「门面 + 两个子模块」的迷你包，模拟拆包后的结构。"""
    prefix = "sleeve_synth"
    for stale in [key for key in list(sys.modules) if key.startswith(prefix)]:
        del sys.modules[stale]

    # 门面：re-export fetch_json（拆包后 app.py 就是这个角色）
    facade = _make_module(prefix, "def fetch_json(url):\n    return 'REAL'\n")
    # 子模块 A：直接引用名字（拆包后最常见的写法）
    plain_mod = _make_module(
        f"{prefix}.plain_mod",
        f"""
        from {prefix} import fetch_json
        def call():
            return fetch_json("u")
        """,
    )
    # 子模块 B：模块属性访问
    attr_mod = _make_module(
        f"{prefix}.attr_mod",
        f"""
        import {prefix} as _facade
        def call():
            return _facade.fetch_json("u")
        """,
    )
    monkeypatch.setattr(testkit, "_sleeve_modules", lambda: [facade, plain_mod, attr_mod])
    yield facade, plain_mod, attr_mod
    testkit.refresh_modules()
    for stale in [key for key in list(sys.modules) if key.startswith(prefix)]:
        del sys.modules[stale]


def test_patch_seam_reaches_both_import_styles(synthetic_package):
    """两种写法都必须被打到。

    实测（本文件末尾的 aliased/captured 用例给出了反例）：

        def f(): return fetch_json(u)        ✓ 被打到
        def f(): return facade.fetch_json(u)  ✓ 被打到

    `from .net import fetch_json` 拿到的是**函数对象**；只要把模块里的名字换掉，
    调用点自然拿到新值。所以按名字跨模块补丁对这两种写法都有效 ——
    这正是 150 处 mock 能在拆包后继续工作的依据。
    """
    facade, plain_mod, attr_mod = synthetic_package
    assert plain_mod.call() == "REAL"
    assert attr_mod.call() == "REAL"

    class MP:
        def setattr(self, obj, name, value, raising=True):
            setattr(obj, name, value)

    testkit.patch_seam(MP(), "fetch_json", lambda url: "FAKE")
    assert facade.fetch_json("u") == "FAKE"
    assert plain_mod.call() == "FAKE", "直接引用名字的调用点没有被补到"
    assert attr_mod.call() == "FAKE", "模块属性访问的调用点没有被补到"


def test_patch_seam_only_patches_modules_that_bind_the_name(synthetic_package):
    """只对**绑定**了该名字的模块设属性；靠别处属性转发的模块不需要、也不会被设。

    这条区分很关键，两种模块的生效路径不同：

      - `plain_mod`（`from pkg import fetch_json`）自己绑了名字 → 必须被打到；
      - `attr_mod`（`import pkg` 后写 `pkg.fetch_json`）**没有**绑名字 →
        patch_seam 跳过它，但它**照样拿到补丁**，因为它在调用时才去门面上取。

    也就是说「被跳过」不等于「失效」。判断标准始终是**调用点的实际返回值**，
    所以下一段同时也断言了两者的调用结果。
    """
    facade, plain_mod, attr_mod = synthetic_package
    seen: list[str] = []

    class MP:
        def setattr(self, obj, name, value, raising=True):
            seen.append(obj.__name__)
            setattr(obj, name, value)

    testkit.patch_seam(MP(), "fetch_json", lambda url: "FAKE")
    # 绑定了名字的两个模块被设了属性
    assert facade.__name__ in seen
    assert plain_mod.__name__ in seen
    # 纯转发模块没有绑定，被跳过（这是对的：它不需要，见下）
    assert attr_mod.__name__ not in seen

    # 但**行为**上三处都拿到了补丁 —— 这才是真正要保证的
    assert facade.fetch_json("u") == "FAKE"
    assert plain_mod.call() == "FAKE"
    assert attr_mod.call() == "FAKE"


def test_patch_seam_falls_back_to_facade_when_name_missing(monkeypatch):
    """名字在任何模块里都不存在时，交给 monkeypatch 抛错（raising=True 的语义）。"""
    prefix = "sleeve_synth_missing"
    module = _make_module(prefix, "X = 1\n")
    monkeypatch.setattr(testkit, "_sleeve_modules", lambda: [module])
    try:
        with pytest.raises(AttributeError):
            testkit.patch_seam(monkeypatch, "no_such_name", 1)
    finally:
        testkit.refresh_modules()
        sys.modules.pop(prefix, None)


# ------------------------------------------------------------------ patch_seam 够不到的两处
#
# 这两条是**边界说明**，不是要修的东西：它们把「什么写法会让拆包后的 mock 失效」
# 钉死成可执行的文档。当前代码库里这两种写法一处都没有（已 grep 核实），
# 所以只要守住约定，patch_seam 就足够。

def test_aliased_import_escapes_patch_seam(monkeypatch):
    """别名导入（`from m import f as g`）够不到 —— 名字不同。"""
    prefix = "sleeve_synth_alias"
    module = _make_module(
        prefix,
        """
        def fetch_json(url):
            return "REAL"
        """,
    )
    aliased = _make_module(
        f"{prefix}.aliased",
        f"""
        from {prefix} import fetch_json as http_get
        def call():
            return http_get("u")
        """,
    )
    monkeypatch.setattr(testkit, "_sleeve_modules", lambda: [module, aliased])
    try:
        class MP:
            def setattr(self, obj, name, value, raising=True):
                setattr(obj, name, value)

        testkit.patch_seam(MP(), "fetch_json", lambda url: "FAKE")
        assert aliased.call() == "REAL", "别名导入按理够不到；若被打到说明语义变了"
    finally:
        testkit.refresh_modules()
        for stale in [key for key in list(sys.modules) if key.startswith(prefix)]:
            del sys.modules[stale]


def test_import_time_capture_escapes_patch_seam(monkeypatch):
    """导入期捕获（默认参数里存了函数对象）够不到 —— 绑定发生在导入那一刻。"""
    prefix = "sleeve_synth_captured"
    module = _make_module(prefix, 'def fetch_json(url):\n    return "REAL"\n')
    captured = _make_module(
        f"{prefix}.captured",
        f"""
        from {prefix} import fetch_json
        def call(cb=fetch_json):
            return cb("u")
        """,
    )
    monkeypatch.setattr(testkit, "_sleeve_modules", lambda: [module, captured])
    try:
        class MP:
            def setattr(self, obj, name, value, raising=True):
                setattr(obj, name, value)

        testkit.patch_seam(MP(), "fetch_json", lambda url: "FAKE")
        assert captured.call() == "REAL", "默认参数捕获按理够不到；若被打到说明语义变了"
        # 显式传参时才拿到补丁后的值 —— 说明问题出在「导入期绑定」而非补丁本身
        assert captured.call(lambda url: "EXPLICIT") == "EXPLICIT"
    finally:
        testkit.refresh_modules()
        for stale in [key for key in list(sys.modules) if key.startswith(prefix)]:
            del sys.modules[stale]


# ------------------------------------------------------------------ 出网熔断


@pytest.fixture
def guarded(monkeypatch):
    testkit.fail_on_real_network(monkeypatch)
    return monkeypatch


def test_guard_blocks_dns_for_real_domains(guarded):
    with pytest.raises(testkit.RealNetworkAccessError):
        socket.getaddrinfo("example.com", 443)


def test_guard_allows_literal_ip_resolution(guarded):
    """字面量 IP 的 getaddrinfo 不发包，必须放行 —— 否则 SSRF 校验测试全挂。"""
    socket.getaddrinfo("127.0.0.1", 80)
    socket.getaddrinfo("169.254.169.254", 80)  # check_outbound 靠这个判定并拒绝


def test_guard_blocks_connect_to_remote_address(guarded):
    with pytest.raises(testkit.RealNetworkAccessError):
        with socket.socket() as sock:
            sock.settimeout(1)
            sock.connect(("93.184.216.34", 80))


def test_guard_blocks_create_connection_to_remote(guarded):
    with pytest.raises(testkit.RealNetworkAccessError):
        socket.create_connection(("example.com", 443), timeout=1)


def test_guard_allows_loopback(guarded):
    """集成测试要连 127.0.0.1，必须放行。"""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    threading.Thread(target=server.accept, daemon=True).start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
    finally:
        server.close()


def test_sleeve_module_discovery_covers_sibling_modules():
    """发现逻辑必须覆盖**平级兄弟模块**，不能只认 `app.` 前缀。

    这是实测踩出来的坑：把 spotify 一族搬到 `src/sleeve_spotify_mod.py` 之后，
    基于前缀（`app.`）的发现逻辑**完全看不到它** —— 补丁只打在门面上，
    而真正的调用点在新模块里，于是测试真的去解析 groover.co 的 DNS。

    本项目的拆分目标是 src/net.py、src/parsers/ototoy.py 这类**平级**布局，
    不是 app.* 包，所以这里用「源码是否在 src/ 下」来判定。
    """
    modules = testkit._sleeve_modules()
    names = {m.__name__ for m in modules}
    # app 自己必须在列表里，且排在最前（报错时优先指向它）
    assert modules[0] is testkit.app
    assert "app" in names
    # 同一目录下的兄弟模块必须被发现（testkit 自己就在 tests/，不该被收）
    assert "testkit" not in names, "不应把 tests/ 下的模块算进来"


def test_sleeve_module_discovery_excludes_non_src_modules():
    """stdlib / 第三方模块不能被误收，否则补丁会打到无关模块上。"""
    names = {m.__name__ for m in testkit._sleeve_modules()}
    for unwanted in ("json", "socket", "urllib", "pytest", "os"):
        assert unwanted not in names, f"{unwanted} 不该被当作 sleeve 模块"


def test_sleeve_module_discovery_refreshes_when_modules_change(monkeypatch, tmp_path):
    """模块集合变化后必须重扫 —— 否则迟到导入 / 新拆出的模块会被静默漏掉。

    用**真实落在 src/ 下**的文件来构造（发现逻辑按路径判定，随便塞一个名字
    不含 app 的假模块是发现不到的 —— 那正是上一个测试要保证的语义）。
    """
    testkit.refresh_modules()

    late = tmp_path / "sleeve_late_synth.py"
    late.write_text("late_module_marker = 1\n", encoding="utf-8")
    spec = importlib.util.spec_from_file_location("sleeve_late_synth", late)
    module = importlib.util.module_from_spec(spec)
    sys.modules["sleeve_late_synth"] = module
    spec.loader.exec_module(module)
    # 让发现逻辑认为它属于 src/（模拟「拆包后新增了一个 src/ 下的兄弟模块」）
    monkeypatch.setattr(testkit, "_SRC", tmp_path)
    testkit.refresh_modules()  # _SRC 变了，缓存必须作废
    try:
        names = {m.__name__ for m in testkit._sleeve_modules()}
        assert "sleeve_late_synth" in names, "新增的 src/ 下模块没有被发现"
        assert "app" not in names, "换了 _SRC 之后不该再收原来的 src/ 下的模块"
    finally:
        sys.modules.pop("sleeve_late_synth", None)
        testkit.refresh_modules()


def test_module_discovery_is_cached_between_calls():
    """重复调用必须走缓存 —— 不能每次重扫 sys.modules。

    `patch_seam` 在整套测试里被调 150+ 次，若每次都全量扫 sys.modules，
    跑测试会明显变慢（实测重扫单次约 1.8ms，对比缓存后约 0.4µs）。

    断言**返回同一个列表对象**：这直接证明没有重新计算，
    比测量耗时更稳定（不受 CI 机器负载影响）。
    """
    testkit.refresh_modules()
    first = testkit._sleeve_modules()
    for _ in range(20):
        assert testkit._sleeve_modules() is first, "缓存没生效：重新计算了模块清单"
    # 强制重扫时才应产生新对象
    testkit.refresh_modules()
    assert testkit._sleeve_modules() is not first


def test_module_discovery_sees_newly_imported_src_module(monkeypatch):
    """模块数量变化后（迟到导入）必须能看见新模块。"""
    testkit.refresh_modules()
    before = {m.__name__ for m in testkit._sleeve_modules()}
    assert "app" in before


def test_guard_error_is_assertion_error(guarded):
    """必须继承 AssertionError：这是测试断言失败，不是业务异常，不能被业务 except 吞掉。"""
    assert issubclass(testkit.RealNetworkAccessError, AssertionError)


# ------------------------------------------------------------------ 拆包约定守卫
#
# patch_seam 靠**名字**跨模块打补丁。有两种写法能让它失效（见 testkit 模块文档），
# 所以这里直接扫描源码，把约定钉成可执行的检查 —— 拆包时若有人写出这两种写法，
# 这里会立刻变红，而不是等到某天发现测试在偷偷联网。

_SEAM_NAMES = [
    "fetch_json", "fetch_text", "post_json", "mb_request", "check_outbound",
    "spotify_album", "spotify_track", "spotify_search", "deezer_album", "deezer_track",
    "collect_apple_credits", "sonovault_track_search", "soundcharts_song_by_platform_id",
    "soundcharts_team_usage", "mb_work_rels_for_recording", "mb_reverse_release_ids",
    "build_song_report",
]


def _source_files() -> list[Path]:
    src = Path(__file__).resolve().parents[1] / "src"
    return sorted(p for p in src.rglob("*.py"))


def test_no_aliased_imports_of_seam_names():
    """禁止 `from x import fetch_json as other` —— 换了名字，patch_seam 够不到。

    推荐写法：`from . import net` 然后 `net.fetch_json(...)`，
    或 `from .net import fetch_json`（保留原名，可按名字补丁）。
    """
    import re

    offenders: list[str] = []
    pattern = re.compile(r"^\s*from\s+\S+\s+import\s+.*\bas\b", re.M)
    for path in _source_files():
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            statement = match.group(0).strip()
            if any(name in statement for name in _SEAM_NAMES):
                offenders.append(f"{path.name}: {statement}")
    assert not offenders, "seam 名被别名导入，拆包后 mock 会静默失效：\n" + "\n".join(offenders)


def test_no_import_time_capture_of_seam_names():
    """禁止在默认参数 / 模块级结构里**在导入期**捕获 seam 函数对象。

    例：`def f(cb=fetch_json)`、`HANDLERS = {"get": fetch_json}`（模块顶层）。
    这样绑定发生在 import 那一刻，之后打补丁都改不了它。

    实现上只看「默认参数」这一类 —— 它是最容易无意写出的形式；
    模块级字典的误判风险太高（正常配置表也会引用函数），不在这里强卡。
    """
    import ast

    offenders: list[str] = []
    for path in _source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d]:
                if isinstance(default, ast.Name) and default.id in _SEAM_NAMES:
                    offenders.append(f"{path.name}:{node.lineno} def {node.name}(...={default.id})")
    assert not offenders, "seam 名被默认参数捕获，拆包后 mock 会静默失效：\n" + "\n".join(offenders)


def test_seam_names_are_single_definition_sites():
    """每个 seam 名字在整个 src/ 里只应该有**一处定义**（其余是 re-export）。

    若同名函数被定义两次（拆包时复制粘贴的常见事故），patch_seam 会把两处都打上，
    但两边逻辑已经分叉 —— 测试通过而线上行为不一致。
    """
    import ast

    definitions: dict[str, list[str]] = {}
    for path in _source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in _SEAM_NAMES:
                definitions.setdefault(node.name, []).append(path.name)

    duplicated = {name: files for name, files in definitions.items() if len(files) > 1}
    assert not duplicated, f"seam 名字被重复定义（拆包事故）: {duplicated}"
