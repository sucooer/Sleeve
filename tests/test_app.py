"""Sleeve 纯函数 / 本地集成回归测试。

覆盖 2026-09-27 代码审查报告点名的部分：出网三道闸（含重定向逐跳复检、
白名单锚定）、危险协议过滤、条码与标题匹配、语言 / 文字判定、MB 查询串转义、
缓存清理与并发写、启动守卫，以及 POST 请求体的边界处理。

**全部不出网**：只解析字面量 IP、只连 127.0.0.1。

    python -m pytest -q
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
# app.py 不在包里（src/ 没有 __init__.py），所以直接把它所在目录加到 sys.path
sys.path.insert(0, str(SRC))

import app  # noqa: E402


# ------------------------------------------------------------------ 出网三道闸

def test_address_is_public_accepts_only_public_unicast():
    assert app.address_is_public(ipaddress.ip_address("8.8.8.8"))
    for value in (
        "127.0.0.1",      # 回环
        "10.0.0.1",       # 私有
        "172.16.0.1",     # 私有
        "192.168.1.1",    # 私有
        "169.254.169.254",  # 链路本地（云元数据）
        "100.64.0.1",     # CGNAT：is_private 是 False，必须靠 is_global 拦住
        "224.0.0.1",      # 组播：is_global 居然是 True，必须单独补一刀
        "0.0.0.0",
        "::1",
    ):
        assert not app.address_is_public(ipaddress.ip_address(value)), value


def test_check_outbound_rejects_dangerous_schemes_and_internal_addresses():
    for url in ("file:///etc/passwd", "javascript:alert(1)", "ftp://example.com/x", "//example.com/x"):
        with pytest.raises(app.FetchError):
            app.check_outbound(url)
    # 字面量 IP 不需要 DNS，测试离线也能跑
    for url in (
        "http://127.0.0.1:8819/secret",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/",
        "http://224.0.0.1/",
        "http://[::1]/",
    ):
        with pytest.raises(app.FetchError):
            app.check_outbound(url)


def test_check_outbound_enforces_platform_allowlist_for_user_urls(monkeypatch):
    monkeypatch.setattr(app, "ALLOW_ANY_USER_HOST", False)
    for url in ("https://notspotify.com/album/1", "https://deezer.com.evil.io/album/1", "https://music.jp.attacker.dev/x"):
        with pytest.raises(app.FetchError):
            app.check_outbound(url, user_supplied=True)


def test_site_info_anchors_rules_to_host_labels():
    known = [
        ("https://open.spotify.com/album/x", "Spotify"),
        ("https://spotify.com/album/x", "Spotify"),
        ("https://www.deezer.com:443/album/1", "Deezer"),  # 带端口也要认得
        ("https://music.apple.com/cn/album/x", "Apple Music"),
        ("https://music.amazon.com/x", "Amazon"),
        ("https://music.amazon.co.jp/albums/x", "Amazon"),
        ("https://music.yandex.ru/album/1", "Yandex Music"),
        ("https://www.qobuz.com/us-en/album/x", "Qobuz"),
        ("https://ototoy.jp/_/default/p/1", "OTOTOY"),
        ("https://music.jp/x", "music.jp"),
    ]
    for url, expected in known:
        assert app.site_info(url)[0] == expected, url
    # 子串匹配时代的漏网之鱼，全部必须是「不认识」
    impostors = [
        "https://notspotify.com/album/x",
        "https://spotify.com.evil.io/album/x",
        "https://deezer.com.evil.io/album/1",
        "https://music.jp.attacker.dev/x",
        "https://music.amazon.com.evil.io/x",
        "https://music.amazon.co.evil/x",
        "https://yandex.evil.com/album/1",
        "https://qobuz.com.attacker.dev/x",
        "https://shop.discogs.com.evil.io/x",
    ]
    for url in impostors:
        assert app.site_info(url) == ("", ""), url


def test_guarded_redirect_handler_blocks_internal_hop():
    """重定向目标也要过闸 —— 只校验入口时，白名单域名 302 到内网就穿了。"""
    handler = app.GuardedRedirectHandler()
    request = Request("https://open.spotify.com/album/x")
    request.user_supplied = True
    for target in (
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8819/secret",
        "//10.0.0.5/x",              # 协议相对写法，按当前 URL 解析
        "file:///C:/Windows/win.ini",
    ):
        with pytest.raises(app.FetchError):
            handler.redirect_request(request, None, 302, "Found", {}, target)


def test_guarded_redirect_handler_keeps_user_supplied_flag(monkeypatch):
    seen: list[tuple[str, bool]] = []
    monkeypatch.setattr(app, "check_outbound", lambda url, user_supplied=False: seen.append((url, user_supplied)))
    handler = app.GuardedRedirectHandler()
    request = Request("https://open.spotify.com/album/x")
    request.user_supplied = True
    redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://www.deezer.com/album/1")
    assert seen == [("https://www.deezer.com/album/1", True)]
    # 标记必须带到下一跳，否则从第二跳起白名单那道闸会悄悄失效
    assert redirected is not None and redirected.user_supplied is True


# ------------------------------------------------------------------ 输入链接切分

def test_split_source_urls_drops_dangerous_schemes():
    warnings: list[dict[str, str]] = []
    text = "\n".join([
        "javascript:alert(document.cookie)",
        "https://open.spotify.com/album/abc",
        "file:///etc/passwd",
        "//music.apple.com/cn/album/x",
        "FTP://example.com/x",
    ])
    assert app.split_source_urls(text, warnings) == [
        "https://open.spotify.com/album/abc",
        "https://music.apple.com/cn/album/x",
    ]
    assert len(warnings) == 3
    assert all(item["source"] == "输入链接" for item in warnings)
    assert any("javascript" in item["warning"] for item in warnings)
    # 列表形态（前端传 urls: [...]）走同一条路：非字符串直接忽略
    assert app.split_source_urls(["javascript:alert(1)", "https://mora.jp/package/1", 123]) == ["https://mora.jp/package/1"]


def test_split_source_urls_keeps_commas_inside_urls():
    assert app.split_source_urls("https://www.deezer.com/album/1?ids=1,2") == ["https://www.deezer.com/album/1?ids=1,2"]
    assert app.split_source_urls("https://a.example/x, https://b.example/y") == ["https://a.example/x", "https://b.example/y"]
    assert app.split_source_urls("https://a.example/x;https://b.example/y") == ["https://a.example/x", "https://b.example/y"]
    # 不是 URL 的输入（把专辑名填进了链接框）静默忽略，不该冒出一条「忽略了非 http 链接」
    warnings: list[dict[str, str]] = []
    assert app.split_source_urls("Heroes", warnings) == []
    assert warnings == []


def test_mb_query_escape_escapes_quotes_and_backslashes():
    assert app.mb_query_escape('"Heroes"') == r'\"Heroes\"'
    assert app.mb_query_escape("C:\\path") == "C:\\\\path"
    # 反斜杠先转义、再转义引号：顺序反了 'a\"b' 会多吃掉一个字符
    assert app.mb_query_escape('a\\"b') == r'a\\\"b'
    assert app.mb_query_escape(None) == ""


# ------------------------------------------------------------------ 数据正确性

def test_is_valid_ean_known_vectors():
    for code in ("5099750442227", "96385074", "036000291452"):  # EAN-13 / EAN-8 / UPC-A
        assert app.is_valid_ean(code), code
    for code in ("5099750442228", "96385075", "036000291453", "509975044222", "0360002914520", "50997504422a", ""):
        assert not app.is_valid_ean(code), code


def test_barcode_is_plausible_rejects_placeholder_values():
    # 全 0 / 全 9 是「没有条码」的占位写法，反查会命中无关专辑（见函数注释）
    assert not app.barcode_is_plausible("0000000000000")
    assert not app.barcode_is_plausible("9999999999999")
    assert not app.barcode_is_plausible("12345678901")
    assert not app.barcode_is_plausible("")
    assert app.barcode_is_plausible("5099750442227")
    assert app.barcode_is_plausible("509-975-044-2227")  # 非数字字符先剥掉


def test_title_match_key_normalizes_width_case_and_suffixes():
    assert app.title_match_key("ＡＢＣ") == app.title_match_key("abc")  # NFKC 全角
    assert app.title_match_key("Lemon - Single") == app.title_match_key("Lemon")
    assert app.title_match_key("Lemon – EP") == app.title_match_key("Lemon")  # 长破折号 + EP
    assert app.title_match_key("Heroes!") == app.title_match_key("heroes")  # 标点会被去掉
    # 注意：带重音的字母（é）是「字母」而不是标点，不会被抹掉 —— 这是有意的，别当成 bug 改掉
    assert app.title_match_key("Héroes") != app.title_match_key("Heroes")
    assert app.title_is_related("Lemon - Single", "Lemon")
    assert app.title_is_related("米津玄師 - Lemon", "Lemon")
    assert not app.title_is_related("", "Lemon")
    assert not app.title_is_related("Orange", "Lemon")


def test_fill_missing_isrc_only_fills_slots_that_line_up():
    tracks = [
        {"disc": "1", "number": "1", "isrc": ""},
        {"disc": "1", "number": "2", "isrc": "KEEP"},
    ]
    donors = [[{"disc": "1", "number": "1", "isrc": "FILL"}, {"disc": "1", "number": "3", "isrc": "EXTRA"}]]
    filled = app.fill_missing_isrc(tracks, donors)
    assert filled[0]["isrc"] == "FILL"   # 同碟同轨才补
    assert filled[1]["isrc"] == "KEEP"   # 只填空、不覆盖已有值
    # 轨号对不上时留空：这是有意的「宁缺勿错」，不是漏补
    assert app.fill_missing_isrc([{"disc": "1", "number": "2", "isrc": ""}], donors)[0]["isrc"] == ""


def test_language_script_separates_cjk():
    # 汉字是中日韩共用字符集：只有假名 / 谚文这类专属字符才能定语种
    assert app.language_script("Lemon", [{"title": "レモン"}]) == ("Japanese", "Japanese")
    assert app.language_script("孤勇者", []) == ("Chinese", "Han")
    assert app.language_script("孤勇者", [], "jp") == ("Japanese", "Japanese")
    assert app.language_script("孤勇者", [], "kr") == ("Korean", "Hangul")
    assert app.language_script("사랑", []) == ("Korean", "Hangul")
    assert app.language_script("Dynamite", [{"title": "Dynamite"}]) == ("English", "Latin")


# ------------------------------------------------------------------ 启动守卫

def test_bind_is_loopback_flags_exposed_binds():
    for value in ("127.0.0.1", "127.0.0.5", "localhost", "::1", "[::1]"):
        assert app.bind_is_loopback(value), value
    for value in ("0.0.0.0", "", "192.168.1.10", "example.com", "::"):
        assert not app.bind_is_loopback(value), value


def _app_env(**overrides: str) -> dict[str, str]:
    env = {
        **os.environ,
        "SLEEVE_AUTH": "",
        "SLEEVE_AUTH_ALLOW_OPEN": "",
        "SLEEVE_PUBLISH_BIND": "",
        "SLEEVE_ALLOW_ANY_USER_HOST": "",
    }
    env.update(overrides)
    return env


def _spawn_app(env: dict[str, str]) -> tuple[subprocess.Popen[str], list[str]]:
    """起一个真的 app.py 进程，并按行收集合并后的输出。

    Windows 上没法对管道做带超时的 select，所以用后台线程逐行读。
    """
    process = subprocess.Popen(
        [sys.executable, str(SRC / "app.py")],
        cwd=str(REPO), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    lines: list[str] = []
    threading.Thread(target=lambda: [lines.append(line) for line in process.stdout or []], daemon=True).start()
    return process, lines


def _output_until(process: subprocess.Popen[str], lines: list[str], predicate, timeout: float = 20.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate("\n".join(lines)) or process.poll() is not None:
            break
        time.sleep(0.1)
    return "\n".join(lines)


def _stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - 极端情况兜底
        pass


@pytest.mark.parametrize(
    "overrides",
    [
        {"SLEEVE_HOST": "0.0.0.0"},
        {"SLEEVE_HOST": "0.0.0.0", "SLEEVE_PUBLISH_BIND": "0.0.0.0"},
        {"SLEEVE_PUBLISH_BIND": "192.168.1.10"},
    ],
)
def test_startup_guard_refuses_exposed_bind_without_auth(overrides):
    process, lines = _spawn_app(_app_env(SLEEVE_PORT="0", **overrides))
    try:
        output = _output_until(process, lines, lambda text: "拒绝启动" in text)
    finally:
        _stop(process)
    assert "拒绝启动" in output, output


@pytest.mark.parametrize(
    "overrides",
    [
        {"SLEEVE_HOST": "127.0.0.1"},                                          # 本机默认
        {"SLEEVE_HOST": "0.0.0.0", "SLEEVE_PUBLISH_BIND": "127.0.0.1"},   # compose 默认形态
        {"SLEEVE_HOST": "0.0.0.0", "SLEEVE_AUTH_ALLOW_OPEN": "1"},        # 显式逃生阀
    ],
)
def test_startup_guard_allows_loopback_or_explicit_override(overrides):
    # 能打印出启动横幅就说明守卫放行了；用 PORT=0 绑临时端口，随后立刻结束进程
    process, lines = _spawn_app(_app_env(SLEEVE_PORT="0", **overrides))
    try:
        output = _output_until(process, lines, lambda text: "running at" in text)
    finally:
        _stop(process)
    assert "running at" in output, output


# ------------------------------------------------------------------ 缓存

def test_cache_sweep_expired_removes_only_stale_files(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "CACHE_DIR", tmp_path)
    stale = tmp_path / "stale.json"
    stale.write_text('{"payload": 1}', encoding="utf-8")
    old = time.time() - app.CACHE_TTL - 60
    os.utime(stale, (old, old))
    fresh = tmp_path / "fresh.json"
    fresh.write_text('{"payload": 2}', encoding="utf-8")
    leftover = tmp_path / "abandoned.tmp"
    leftover.write_text("{}", encoding="utf-8")
    os.utime(leftover, (old, old))

    app.cache_sweep_expired()

    assert not stale.exists()
    assert not leftover.exists()
    assert fresh.exists()
    assert app.cache_load("fresh") == 2


def test_cache_store_keeps_concurrent_writers_of_same_key_apart(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(app, "CACHE_ENABLED", True)

    def store(value: int) -> None:
        app.cache_store("shared-key", {"n": value})

    threads = [threading.Thread(target=store, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # 临时文件名带线程号与随机段，谁都不踩谁：最终一定是一个完整可读的 JSON
    assert app.cache_load("shared-key") in [{"n": index} for index in range(8)]
    # Windows 上 os.replace 在并发替换同一个目标时可能瞬时失败（目标被占用），
    # 于是临时文件会留下来 —— 这没关系：它不影响 cache_load，且会被
    # cache_sweep_expired 的 *.tmp 分支在超过 TTL 之后收走（这里手工把 mtime 拨老来验证）
    for leftover in tmp_path.glob("*.tmp"):
        os.utime(leftover, (0, 0))
    app.cache_sweep_expired()
    assert not list(tmp_path.glob("*.tmp"))


# ------------------------------------------------------------------ 本地集成：POST 体边界
#
# 只连 127.0.0.1，且只打 /api/health 与「注定被拒」的请求，不会发出任何出网请求。

@pytest.fixture(scope="module")
def live_server():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = _app_env(
        SLEEVE_HOST="0.0.0.0",              # 容器里的形态
        SLEEVE_PUBLISH_BIND="127.0.0.1",    # 但只发布到回环 → 守卫放行
        SLEEVE_PORT=str(port),
        SLEEVE_CACHE_DIR=tempfile.mkdtemp(prefix="sleeve-test-cache-"),
        SLEEVE_VERSION="1.2.3",             # 版本注入：health 与页面徽标都应看到它
    )
    process, lines = _spawn_app(env)
    try:
        deadline = time.time() + 20
        ready = False
        while time.time() < deadline and not ready:
            try:
                with urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1) as response:
                    ready = response.status == 200
            except (OSError, URLError):
                time.sleep(0.2)
        assert ready, "\n".join(lines)
        yield port
    finally:
        _stop(process)


def _raw_request(port: int, request_text: str) -> str:
    """发一个原始 HTTP 请求并读完整响应（服务端是 HTTP/1.0，回完就关连接）。"""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request_text.encode("utf-8"))
        chunks: list[bytes] = []
        while True:
            try:
                data = sock.recv(65536)
            except (TimeoutError, OSError):
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace")


@pytest.mark.parametrize(
    ("header", "expected_status"),
    [
        ("Content-Length: abc", 400),        # 原来会 ValueError 裸抛，连接直接挂断
        ("Content-Length: -1", 400),         # 原来 read(-1) = 读到连接关闭为止
        ("Content-Length: 2000000", 413),    # 超过 1 MiB 上限
    ],
)
def test_post_body_bounds(live_server, header, expected_status):
    response = _raw_request(live_server, f"POST /api/lookup HTTP/1.0\r\nHost: 127.0.0.1\r\n{header}\r\n\r\n")
    assert f" {expected_status} " in response.splitlines()[0], response


@pytest.mark.parametrize(("body", "expected_status"), [("[1, 2]", 400), ("{oops", 400)])
def test_post_body_rejects_non_object_and_bad_json(live_server, body, expected_status):
    response = _raw_request(
        live_server,
        "POST /api/lookup HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body.encode('utf-8'))}\r\n\r\n{body}",
    )
    assert f" {expected_status} " in response.splitlines()[0], response


def test_post_lookup_drops_dangerous_scheme_without_outbound_calls(live_server):
    """?urls=javascript:... 这条分享链接的入口：危险协议在入库前就被丢掉，
    于是「没有可用链接」→ 干净的 400，而不是拿它出网、或渲染成 href。"""
    body = json.dumps({"urls": ["javascript:alert(document.cookie)"]})
    response = _raw_request(
        live_server,
        "POST /api/lookup HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body.encode('utf-8'))}\r\n\r\n{body}",
    )
    assert " 400 " in response.splitlines()[0], response


# ------------------------------------------------------------------ 版本注入

def test_resolve_version_defaults_to_dev(monkeypatch):
    monkeypatch.delenv("SLEEVE_VERSION", raising=False)
    assert app.resolve_version() == "dev"
    assert app.resolve_version("   ") == "dev"
    assert app.resolve_version("1.2.3") == "1.2.3"


def test_user_agent_carries_current_version():
    assert app.VERSION and app.VERSION.strip() == app.VERSION
    assert app.USER_AGENT.startswith(f"Sleeve/{app.VERSION} ")


# ------------------------------------------------------------------ 版本注入（集成）

def test_health_reports_injected_version(live_server):
    with urlopen(f"http://127.0.0.1:{live_server}/api/health", timeout=2) as response:
        payload = json.load(response)
    assert payload["ok"] is True
    assert payload["version"] == "1.2.3"


def test_api_usage_endpoint(live_server):
    # 测试进程未配数据源凭据 → 两个源都报未配置，且不触发任何出网请求
    with urlopen(f"http://127.0.0.1:{live_server}/api/usage", timeout=2) as response:
        payload = json.load(response)
    assert response.status == 200
    assert payload["generated_at"]
    assert "sonovault" in payload["sources"] and "soundcharts" in payload["sources"]
    assert payload["sources"]["sonovault"]["configured"] is False
    assert payload["sources"]["soundcharts"]["configured"] is False


def test_index_badge_uses_injected_version(live_server):
    """index.html 徽标里的 __VERSION__ 占位符要被替换成注入的版本；
    还显示写死的 v0.4、或原样保留占位符，都算注入没生效。"""
    with urlopen(f"http://127.0.0.1:{live_server}/", timeout=2) as response:
        html = response.read().decode("utf-8")
    assert "v1.2.3" in html
    assert "__VERSION__" not in html
    assert ">v0.4<" not in html


# ------------------------------------------------------------------ 版本注入（Dockerfile 契约）

def test_dockerfile_version_contract():
    """Dockerfile 与应用的版本契约：ARG/ENV 两行必须字面存在。

    这是版本链路里唯一没有其他测试守护的环节 —— 改名 SLEEVE_VERSION、
    改默认值或删掉任一行，都会让 CI 注入静默断链（镜像里变 dev）。
    应用侧默认值 dev 由 test_resolve_version_defaults_to_dev 守护。"""
    dockerfile = (REPO / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG VERSION=dev" in dockerfile
    assert "ENV SLEEVE_VERSION=${VERSION}" in dockerfile



# ------------------------------------------------------------------ Apple/iTunes 区域整单切换

def _mk_itunes_collection(country: str, has_tracks: bool = True) -> dict:
    """构造 iTunes lookup 响应：专辑壳 + 可选一首曲目。country 用三位区码（CHN/JPN/USA）。"""
    out = {"results": [{
        "wrapperType": "collection",
        "collectionName": "TEST ALBUM",
        "artistName": "Art",
        "releaseDate": "2026-01-01",
        "copyright": f"Lbl {country}",
        "primaryGenreName": "J-Pop",
        "country": country,
        "collectionId": "1",
        "collectionViewUrl": f"https://music.apple.com/{country.lower()}/album/x/1",
    }]}
    if has_tracks:
        out["results"].append({
            "wrapperType": "track",
            "trackName": f"T1-{country}",
            "artistName": "Art",
            "trackTimeMillis": 1000,
            "trackNumber": 1,
            "discNumber": 1,
        })
    return out


def test_apple_storefront_chain_link_country_first():
    """尝试顺序：链接自带的区优先，JP/us/默认区兜底（是否切 JP 由艺人名匹配决定，不在这里）。"""
    assert app.apple_storefront_chain("cn") == ["cn", "jp", "us", ""]
    assert app.apple_storefront_chain("jp") == ["jp", "us", ""]
    assert app.apple_storefront_chain("us") == ["us", "jp", ""]
    assert app.apple_storefront_chain("") == ["", "jp", "us"]


def test_apple_jp_first_when_cn_shell_missing_tracks(monkeypatch):
    """CN 链接 + CN 区只有壳没有曲目：整单改用 JP 区（字段、曲目都按 JP），不再只借曲目表。"""
    def fake_fetch(url):
        if "country=cn" in url:
            return _mk_itunes_collection("CHN", has_tracks=False)
        return _mk_itunes_collection("JPN")
    monkeypatch.setattr(app, "fetch_json", fake_fetch)
    picked = app.itunes_album_by_id("1", "cn", "Art")
    assert picked["country"] == "jp"
    assert picked["data"]["country"] == "JPN"
    assert [t["title"] for t in picked["data"]["tracks"]] == ["T1-JPN"]
    assert "已按日本区数据整单查询" in picked["note"]
    assert "JP 区" in picked["note"]


def test_apple_jp_missing_falls_back_to_complete_storefront(monkeypatch):
    """JP 区没有该专辑：回落有完整数据的区（这里是 US），整单切换并注明缺数据的区。"""
    def fake_fetch(url):
        if "country=jp" in url:
            return {"results": []}
        if "country=cn" in url:
            return _mk_itunes_collection("CHN", has_tracks=False)
        return _mk_itunes_collection("USA")
    monkeypatch.setattr(app, "fetch_json", fake_fetch)
    picked = app.itunes_album_by_id("1", "cn", "Art")
    assert picked["country"] == "us"
    assert picked["data"]["country"] == "USA"
    assert [t["title"] for t in picked["data"]["tracks"]] == ["T1-USA"]
    assert "CN 区数据不全" in picked["note"]
    assert "US 区" in picked["note"]


def test_apple_jp_link_keeps_clean_jp_data(monkeypatch):
    """JP 链接：直接用 JP 区，不产生混搭提醒。"""
    monkeypatch.setattr(app, "fetch_json", lambda url: _mk_itunes_collection("JPN"))
    picked = app.itunes_album_by_id("1", "jp", "Art")
    assert picked["country"] == "jp"
    assert picked["data"]["country"] == "JPN"
    assert picked["note"] == ""


def test_apple_nowhere_returns_empty(monkeypatch):
    """任何区都查不到：返回空 data 且 note 为空。"""
    monkeypatch.setattr(app, "fetch_json", lambda url: {"results": []})
    picked = app.itunes_album_by_id("1", "cn", "Art")
    assert picked["data"] == {}
    assert picked["note"] == ""


def test_apple_west_artist_cn_link_avoids_jp_kana_name(monkeypatch):
    """欧美歌手 CN 链接：JP 区艺人名日文化（テイラー・スウィフト）与输入不符 → 整单改用
    艺人名匹配且有完整数据的 US 区，而不是被 JP 日文名污染（否则会被艺人校验整份丢弃）。"""
    def fake_fetch(url):
        if "country=jp" in url:
            # JP 区有完整数据但艺人名是日文片假名
            return {"results": [
                {"wrapperType": "collection", "collectionName": "TEST ALBUM", "artistName": "テイラー・スウィフト",
                 "releaseDate": "2026-01-01", "copyright": "Lbl JPN", "primaryGenreName": "Pop",
                 "country": "JPN", "collectionId": "1",
                 "collectionViewUrl": "https://music.apple.com/jp/album/x/1"},
                {"wrapperType": "track", "trackName": "T1-JP", "artistName": "テイラー・スウィフト",
                 "trackTimeMillis": 1000, "trackNumber": 1, "discNumber": 1},
            ]}
        if "country=cn" in url:
            return _mk_itunes_collection("CHN", has_tracks=False)
        # US 区完整数据，艺人名保持英文原名（与页面输入一致）
        return {"results": [
            {"wrapperType": "collection", "collectionName": "TEST ALBUM", "artistName": "Taylor Swift",
             "releaseDate": "2026-01-01", "copyright": "Lbl USA", "primaryGenreName": "Pop",
             "country": "USA", "collectionId": "1",
             "collectionViewUrl": "https://music.apple.com/us/album/x/1"},
            {"wrapperType": "track", "trackName": "T1-US", "artistName": "Taylor Swift",
             "trackTimeMillis": 1000, "trackNumber": 1, "discNumber": 1},
        ]}
    monkeypatch.setattr(app, "fetch_json", fake_fetch)
    picked = app.itunes_album_by_id("1", "cn", "Taylor Swift")
    assert picked["country"] == "us"
    assert picked["data"]["artist"] == "Taylor Swift"  # 英文名，不被日文化
    assert [t["title"] for t in picked["data"]["tracks"]] == ["T1-US"]
    assert "CN 区数据不全" in picked["note"]
    assert "US 区" in picked["note"]


def test_apple_no_matching_full_storefront_borrows_tracks_only(monkeypatch):
    """华语歌手：JP 区没有、US 区名字罗马化（Hebe Tien）与输入不符 → 不整单切换，
    保留主来源字段，只借用曲目表（艺人名保持页面一致的写法）。"""
    def fake_fetch(url):
        if "country=jp" in url:
            return {"results": []}
        if "country=cn" in url:
            return _mk_itunes_collection("CHN", has_tracks=False)
        return _mk_itunes_collection("USA") | {
            "results": [{"wrapperType": "collection", "collectionName": "TEST ALBUM", "artistName": "Hebe Tien",
                         "releaseDate": "2026-01-01", "copyright": "Lbl USA", "primaryGenreName": "Pop",
                         "country": "USA", "collectionId": "1",
                         "collectionViewUrl": "https://music.apple.com/us/album/x/1"},
                        {"wrapperType": "track", "trackName": "T1-US", "artistName": "Hebe Tien",
                         "trackTimeMillis": 1000, "trackNumber": 1, "discNumber": 1}]}
    monkeypatch.setattr(app, "fetch_json", fake_fetch)
    picked = app.itunes_album_by_id("1", "cn", "田馥甄")
    assert picked["country"] == "cn"
    assert picked["data"]["country"] == "CHN"
    assert picked["data"]["artist"] == "Art"  # 主来源字段保留
    assert [t["title"] for t in picked["data"]["tracks"]] == ["T1-US"]  # 只借曲目表
    assert "曲目表借用" in picked["note"]
    assert "US 区" in picked["note"]


# ------------------------------------------------------------------ Work relationships（只查询，建库人工完成）

def _mb_recording_response(works=(), artist_rels=()):
    """构造 recording 查询响应：work 关系 + recording 直接 artist 关系。"""
    relations = []
    for work in works:
        relations.append({
            "direction": "forward", "type": "performance", "target-type": "work",
            "work": work,
        })
    for rel in artist_rels:
        relations.append({"direction": "forward", "type": rel[0], "target-type": "artist", "artist": {"name": rel[1], "id": rel[2]}})
    return {"relations": relations}


def test_mb_work_relation_artist_flattens_attributes():
    rel = {
        "type": "composer",
        "target-type": "artist",
        "artist": {"name": "Taylor Swift", "id": "mbid-1"},
        "attributes": [{"name": "partial"}, {"name": "additional"}],
    }
    flat = app.mb_work_relation_artist(rel)
    assert flat["type"] == "composer"
    assert flat["artist"] == "Taylor Swift"
    assert flat["artist_mbid"] == "mbid-1"
    assert flat["attributes"] == ["partial", "additional"]


def test_mb_work_rels_for_recording_parses_work_and_artist_rels(monkeypatch):
    def fake_mb(path, params):
        if path.startswith("recording/"):
            return _mb_recording_response(
                works=[{"id": "w-1", "title": "The Fate of Ophelia", "type": "Song", "iswc": "T-000.000.000-0"}],
                artist_rels=[("conductor", "Some Conductor", "a-2")],
            )
        if path.startswith("work/w-1"):
            return {"relations": [
                {"direction": "forward", "type": "composer", "target-type": "artist",
                 "artist": {"name": "Taylor Swift", "id": "a-1"}, "attributes": [{"name": "partial"}]},
                {"direction": "backward", "type": "writer", "target-type": "work", "work": {"id": "w-x"}},
            ]}
        raise AssertionError(f"unexpected path {path}")
    monkeypatch.setattr(app, "mb_request", fake_mb)

    result = app.mb_work_rels_for_recording("r-1")
    assert len(result["works"]) == 1
    work = result["works"][0]
    assert work["title"] == "The Fate of Ophelia"
    assert work["type"] == "Song"
    assert work["iswc"] == "T-000.000.000-0"
    assert work["url"].endswith("/work/w-1")
    # work 上只保留 forward artist 关系（backward work 自引用被过滤）
    assert work["relations"] == [{
        "type": "composer", "artist": "Taylor Swift", "artist_mbid": "a-1", "attributes": ["partial"],
    }]
    assert result["recording_relations"] == [{
        "type": "conductor", "artist": "Some Conductor", "artist_mbid": "a-2", "attributes": [],
    }]


def test_mb_work_rels_for_recording_dedupes_work(monkeypatch):
    def fake_mb(path, params):
        if path.startswith("recording/"):
            return _mb_recording_response(works=[
                {"id": "w-1", "title": "Same"},
                {"id": "w-1", "title": "Same"},
            ])
        return {"relations": []}
    monkeypatch.setattr(app, "mb_request", fake_mb)

    result = app.mb_work_rels_for_recording("r-1")
    assert len(result["works"]) == 1


def test_mb_work_rels_for_recording_skips_work_fetch_on_error(monkeypatch):
    calls = []

    def fake_mb(path, params):
        if path.startswith("recording/"):
            calls.append(path)
            return _mb_recording_response(works=[{"id": "w-1", "title": "Broken work"}])
        raise app.FetchError("work fetch failed")
    monkeypatch.setattr(app, "mb_request", fake_mb)

    result = app.mb_work_rels_for_recording("r-1")
    assert result["works"][0]["relations"] == []  # work 查询失败不阻塞，关系留空


def test_build_work_relations_skips_when_no_recording_mbid():
    tracks = [{"title": "A", "recording_mbid": ""}, {"title": "B", "recording_mbid": None}]
    result = app.build_work_relations(tracks)
    assert result["status"] == "skipped"
    assert result["query_count"] == 0
    assert result["markdown"] == ""


def test_build_work_relations_queries_with_budget_limit(monkeypatch):
    tracks = [{"title": f"T{i}", "recording_mbid": f"r-{i}"} for i in range(5)]

    def fake_recording(mbid):
        return {"works": [{"title": f"W-{mbid}", "mbid": f"w-{mbid}", "type": "Song",
                           "iswc": "", "url": f"https://musicbrainz.org/work/w-{mbid}",
                           "relations": [{"type": "composer", "artist": "A", "artist_mbid": "a-1", "attributes": []}]}],
                "recording_relations": []}
    monkeypatch.setattr(app, "mb_work_rels_for_recording", fake_recording)
    monkeypatch.setattr(app, "MAX_WORK_RELS_TRACKS", 2)

    result = app.build_work_relations(tracks)
    assert result["status"] == "partial"
    assert result["query_count"] == 2
    assert result["limited"] == 3
    assert len(result["items"]) == 2
    assert result["work_count"] == 2
    assert result["relation_count"] == 2
    assert "超出查询预算" in result["notice"]


def test_build_work_relations_records_failures(monkeypatch):
    tracks = [{"title": "T1", "recording_mbid": "r-1"}, {"title": "T2", "recording_mbid": "r-2"}]

    def fake_recording(mbid):
        if mbid == "r-1":
            raise app.FetchError("rate limited 503")
        return {"works": [], "recording_relations": []}
    monkeypatch.setattr(app, "mb_work_rels_for_recording", fake_recording)

    result = app.build_work_relations(tracks)
    assert result["status"] == "partial"
    assert result["failed"] == 1
    assert result["items"][0]["error"] == "rate limited 503"
    assert result["items"][1]["error"] == ""


def test_work_relations_markdown_shape():
    items = [{
        "track": "The Fate of Ophelia", "recording_mbid": "r-1", "recording_url": "https://musicbrainz.org/recording/r-1",
        "works": [{
            "title": "The Fate of Ophelia", "mbid": "w-1", "type": "Song", "iswc": "T-123",
            "url": "https://musicbrainz.org/work/w-1",
            "relations": [{"type": "composer", "artist": "Taylor Swift", "artist_mbid": "a-1", "attributes": []}],
        }],
        "recording_relations": [{"type": "producer", "artist": "Jack Antonoff", "artist_mbid": "a-2", "attributes": ["additional"]}],
        "error": "",
    }]
    md = app.work_relations_markdown(items)
    assert "### The Fate of Ophelia" in md
    assert "recording `r-1`" in md
    assert "- (recording) producer: Jack Antonoff (a-2)" in md
    assert "- Work: The Fate of Ophelia (Song) [T-123] `w-1`" in md
    assert "  - composer: Taylor Swift (a-1)" in md
    assert "人工核对" in md


# ------------------------------------------------------------------ 单曲链接 → 所属专辑（歌曲建库入口）

def test_extract_apple_song_id_variants():
    assert app.extract_apple_song_id("https://music.apple.com/cn/song/the-fate-of-ophelia/6814997402") == "6814997402"
    assert app.extract_apple_song_id("https://music.apple.com/us/song/x/111") == "111"
    assert app.extract_apple_song_id("https://music.apple.com/cn/album/the-life/6814997249") == ""      # 专辑链接不是 song
    assert app.extract_apple_song_id("https://open.spotify.com/album/abc") == ""                        # 非 apple 域名
    assert app.extract_apple_song_id("") == ""


def test_itunes_album_from_song_returns_collection(monkeypatch):
    fake = {
        "results": [{
            "wrapperType": "track", "trackId": 6814997402, "trackName": "The Fate of Ophelia",
            "artistName": "Taylor Swift", "collectionId": 6814997249,
            "collectionName": "The Life of a Showgirl: The Encore",
            "collectionViewUrl": "https://music.apple.com/us/album/the-life/6814997249",
        }],
    }
    monkeypatch.setattr(app, "fetch_json", lambda url: fake)
    result = app.itunes_album_from_song("6814997402")
    assert result["collection_id"] == "6814997249"
    assert result["collection_name"] == "The Life of a Showgirl: The Encore"
    assert result["artist"] == "Taylor Swift"
    assert result["url"].startswith("https://music.apple.com")


def test_itunes_album_from_song_empty_when_missing_collection(monkeypatch):
    monkeypatch.setattr(app, "fetch_json", lambda url: {"results": [{"wrapperType": "track", "collectionId": ""}]})
    assert app.itunes_album_from_song("999") == {}
    monkeypatch.setattr(app, "fetch_json", lambda url: {"results": []})
    assert app.itunes_album_from_song("999") == {}


# ------------------------------------------------------------------ Apple Credits（版权方侧，建 work 用资料）

APPLE_CREDITS_HTML = '''<html><body><script>
window.__INITIAL_DATA__ = {"data":{"sections":[
  {"id":"performer","title":"\\u51fa\\u6f14\\u827a\\u4eba","items":[{"name":"Taylor Swift","roleNames":["\\u58f0\\u4e50"]},{"name":"Shellback","roleNames":["\\u7f16\\u7a0b","\\u94a2\\u7434"]}]},
  {"id":"composer-and-lyrics","title":"\\u4f5c\\u66f2\\u548c\\u4f5c\\u8bcd","items":[{"name":"Taylor Swift","roleNames":["\\u8bcd\\u66f2\\u4f5c\\u8005"]},{"name":"Max Martin","roleNames":["\\u8bcd\\u66f2\\u4f5c\\u8005"]}]},
  {"id":"production-and-engineering","title":"\\u5236\\u4f5c\\u548c\\u5de5\\u7a0b","items":[{"name":"Serban Ghenea","roleNames":["\\u6df7\\u97f3\\u5de5\\u7a0b\\u5e08"]}]},
  {"id":"lyric-details","title":"\\u6b4c\\u8bcd","items":[]}
]}}</script></body></html>'''


def test_parse_apple_credits_extracts_groups():
    groups = app.parse_apple_credits(APPLE_CREDITS_HTML)
    by_id = {g["id"]: g for g in groups}
    assert set(by_id) == {"performer", "composer-and-lyrics", "production-and-engineering"}
    assert by_id["performer"]["title"] == "出演艺人"
    assert by_id["performer"]["items"][0] == {"name": "Taylor Swift", "roles": ["声乐"]}
    assert by_id["composer-and-lyrics"]["items"][1] == {"name": "Max Martin", "roles": ["词曲作者"]}
    assert by_id["production-and-engineering"]["items"][0]["roles"] == ["混音工程师"]


def test_collect_apple_credits_rewrites_album_expansion_to_song_page(monkeypatch):
    """专辑展开页（album/…?i=<trackId>）不渲染 Credits，应改抓对应歌曲页。"""
    seen: list[str] = []
    monkeypatch.setattr(app, "fetch_text", lambda url: seen.append(url) or APPLE_CREDITS_HTML)
    result = app.collect_apple_credits(
        "https://music.apple.com/cn/album/some-album/1234567890?i=6814997402", "The Fate of Ophelia")
    assert seen == ["https://music.apple.com/cn/song/6814997402"]
    assert len(result["groups"]) == 3


def test_parse_apple_credits_empty_on_no_sections():
    assert app.parse_apple_credits("<html></html>") == []
    assert app.parse_apple_credits("") == []


def test_collect_apple_credits_only_for_song_pages(monkeypatch):
    monkeypatch.setattr(app, "fetch_text", lambda url: APPLE_CREDITS_HTML)
    result = app.collect_apple_credits("https://music.apple.com/cn/song/the-fate-of-ophelia/6814997402", "The Fate of Ophelia")
    assert result["track"] == "The Fate of Ophelia"
    assert len(result["groups"]) == 3
    # 非歌曲页 / 非 apple 域名 / 页面抓不到都返回空
    monkeypatch.setattr(app, "fetch_text", lambda url: (_ for _ in ()).throw(app.FetchError("boom")))
    assert app.collect_apple_credits("https://music.apple.com/cn/song/x/1") == {}
    assert app.collect_apple_credits("https://music.apple.com/cn/album/x/1") == {}   # 专辑页无 ?i=
    assert app.collect_apple_credits("https://example.com/song/1") == {}


def test_build_work_relations_credits_only_when_no_mb():
    tracks = [{"title": "A", "recording_mbid": ""}]
    credits = [{"track": "A", "source_url": "https://music.apple.com/cn/song/a/1", "groups": [{"id": "composer-and-lyrics", "title": "作曲和作词", "items": [{"name": "Taylor Swift", "roles": ["词曲作者"]}]}]}]
    result = app.build_work_relations(tracks, credits)
    assert result["status"] == "credits_only"
    assert result["query_count"] == 0
    assert result["apple_credits"] == credits
    assert "可直接作为新建 Work" in result["notice"]
    md = result["markdown"]
    assert "Apple Music Credits" in md
    assert "词曲作者" in md
    assert "泰勒" not in md


def test_build_work_relations_skipped_without_any_source():
    result = app.build_work_relations([{"title": "A", "recording_mbid": ""}], [])
    assert result["status"] == "skipped"
    assert result["markdown"] == ""


def test_work_relations_markdown_includes_apple_credits():
    md = app.work_relations_markdown([], [{
        "track": "The Fate of Ophelia",
        "source_url": "https://music.apple.com/cn/song/x/1",
        "groups": [{"id": "composer-and-lyrics", "title": "作曲和作词", "items": [{"name": "Max Martin", "roles": ["词曲作者"]}]}],
    }])
    assert "### The Fate of Ophelia — Apple Music Credits" in md
    assert "- **作曲和作词**" in md
    assert "  - Max Martin（词曲作者）" in md


# ------------------------------------------------------------------ Lyrics URL relationship 候选（MB 白名单站点）

def test_looks_japanese():
    assert app.looks_japanese("君の名は")
    assert app.looks_japanese("チェリータイム")
    assert not app.looks_japanese("The Fate of Ophelia")
    assert not app.looks_japanese("")


def test_lyrics_search_candidates_international():
    links = app.lyrics_search_candidates("The Fate of Ophelia", "Taylor Swift")
    sites = [l["site"] for l in links]
    assert sites == ["Genius", "Musixmatch", "LyricsTranslate"]
    assert all(l["whitelisted"] for l in links)
    genius = links[0]["url"]
    assert "The%20Fate%20of%20Ophelia%20Taylor%20Swift" in genius
    assert genius.startswith("https://genius.com/search?q=")
    assert links[1]["url"].startswith("https://www.musixmatch.com/search/")
    assert links[2]["url"].startswith("https://lyricstranslate.com/en/search?q=")


def test_lyrics_search_candidates_japanese_appends_jp_sites():
    links = app.lyrics_search_candidates("夜に駆ける", "YOASOBI")
    sites = [l["site"] for l in links]
    assert sites[:3] == ["Genius", "Musixmatch", "LyricsTranslate"]
    assert "J-Lyric.net" in sites and "Uta-Net" in sites and "UtaMap" in sites and "UtaTen" in sites
    jp = next(l for l in links if l["site"] == "J-Lyric.net")["url"]
    assert jp.startswith("https://search.j-lyric.net/index.php?kt=")


def test_lyrics_search_candidates_empty_title():
    assert app.lyrics_search_candidates("", "") == []
    assert app.lyrics_search_candidates("", "Taylor") == []


def test_lyrics_candidates_for_tracks_budget_and_skip():
    tracks = [
        {"title": f"Song {i}", "artist": "A", "recording_mbid": f"r{i}"} for i in range(3)
    ] + [{"title": "", "artist": "B"}]
    items = app.lyrics_candidates_for_tracks(tracks)
    assert len(items) == 3
    assert all(it["track"].startswith("Song") for it in items)
    assert all(len(it["links"]) == 3 for it in items)  # 英文歌 3 个国际站

    many = app.lyrics_candidates_for_tracks([{"title": f"T{i}", "artist": "A"} for i in range(20)])
    assert len(many) <= app.MAX_LYRICS_CANDIDATE_TRACKS


# ------------------------------------------------------------------ 单曲链接：独立 song 报告（recording / work / credits / 歌词候选）

def test_mb_search_recording_basic(monkeypatch):
    fake = {"recordings": [{
        "id": "abc-123", "title": "The Fate of Ophelia", "score": 100,
        "artist-credit": [{"name": "Taylor Swift", "joinphrase": ""}],
        "isrcs": ["USUG12506436"], "length": 226000,
        "releases": [{"title": "The Life of a Showgirl: The Encore"}],
    }]}
    monkeypatch.setattr(app, "mb_request", lambda path, params: fake if path == "recording" else {})
    rows = app.mb_search_recording("The Fate of Ophelia", "Taylor Swift")
    assert rows[0]["mbid"] == "abc-123"
    assert rows[0]["isrc"] == "USUG12506436"
    assert rows[0]["length"] == "3:46"
    assert rows[0]["artist"] == "Taylor Swift"


def test_mb_search_recording_no_terms():
    assert app.mb_search_recording("", "") == []


def _fake_itunes_track():
    return {"results": [{
        "wrapperType": "track", "trackId": 6814997402, "trackName": "The Fate of Ophelia",
        "artistName": "Taylor Swift", "collectionName": "The Life of a Showgirl: The Encore",
        "collectionId": 6814997249, "trackTimeMillis": 226000, "isrc": "USUG12506436",
        "releaseDate": "2026-09-25T07:00:00Z", "primaryGenreName": "Pop",
        "trackViewUrl": "https://music.apple.com/cn/song/the-fate-of-ophelia/6814997402",
        "collectionViewUrl": "https://music.apple.com/us/album/the-life-of-a-showgirl-the-encore/6814997249",
        "artworkUrl100": "https://is1-ssl.mzstatic.com/image/thumb/x.jpg/100x100bb.jpg",
    }]}


def test_build_song_report_full(monkeypatch):
    monkeypatch.setattr(app, "fetch_json", lambda url: _fake_itunes_track())
    monkeypatch.setattr(app, "mb_request", lambda path, params: _mb_song_payload(path, params))
    monkeypatch.setattr(app, "collect_apple_credits", lambda url, track_title="": _fake_apple_credit(track_title))
    report = app.build_song_report("https://music.apple.com/cn/song/the-fate-of-ophelia/6814997402",
                                   ["https://music.apple.com/cn/song/the-fate-of-ophelia/6814997402"],
                                   "apple", "6814997402")
    assert report["report_type"] == "song"
    song = report["song"]
    assert song["title"] == "The Fate of Ophelia"
    assert song["artist"] == "Taylor Swift"
    assert song["album"] == "The Life of a Showgirl: The Encore"
    assert song["album_platform_id"] == "6814997249"
    assert song["album_source"] == "Apple Music"
    assert song["track_url"].startswith("https://music.apple.com/cn/song/")
    assert song["length"] == "3:46"
    assert song["isrc"] == "USUG12506436"
    assert "1000x1000" in song["artwork_url"]
    assert report["recording"]["mbid"] == "rec-1"
    assert report["lyrics_candidates"][0]["track"] == "The Fate of Ophelia"
    sites = [l["site"] for l in report["lyrics_candidates"][0]["links"]]
    assert sites == ["Genius", "Musixmatch", "LyricsTranslate"]
    assert any(e["site"] == "Apple Music" for e in report["external_links"])
    assert any(e["site"] == "Deezer" for e in report["external_links"])
    assert len(report["manual_review"]) >= 4
    assert report["edit_notes"]["Recording / Work 提交备忘"]
    assert "The Fate of Ophelia" in report["markdown"]


def _mb_song_payload(path, params):
    if path == "recording":
        return {"recordings": [{
            "id": "rec-1", "title": "The Fate of Ophelia", "score": 92,
            "artist-credit": [{"name": "Taylor Swift", "joinphrase": ""}],
            "isrcs": ["USUG12506436"], "length": 226000,
            "releases": [{"title": "The Life of a Showgirl: The Encore"}],
        }]}
    if path == "recording/rec-1":
        return {
            "relations": [
                {"direction": "forward", "target-type": "work", "work": {"id": "work-1", "title": "The Fate of Ophelia", "type": "Song"}},
                {"direction": "forward", "target-type": "url", "url": {"resource": "https://www.deezer.com/track/123"}},
            ],
            "works": [],
        }
    return {}


def _fake_apple_credit(track_title):
    return {"track": track_title, "source_url": "https://music.apple.com/cn/song/x/1", "groups": [
        {"id": "composer-and-lyrics", "title": "词曲作者", "items": [{"name": "Taylor Swift", "roles": ["词曲"]}]},
    ]}


def test_build_song_report_lookup_fails(monkeypatch):
    monkeypatch.setattr(app, "fetch_json", lambda url: {"results": []})
    report = app.build_song_report("https://music.apple.com/cn/song/x/999", ["https://music.apple.com/cn/song/x/999"], "apple", "999")
    assert report.get("needs_selection") is True


def test_build_song_report_mb_fails_but_credits_ok(monkeypatch):
    monkeypatch.setattr(app, "fetch_json", lambda url: _fake_itunes_track())
    def boom(path, params):
        raise app.FetchError("MB unreachable")
    monkeypatch.setattr(app, "mb_request", boom)
    monkeypatch.setattr(app, "collect_apple_credits", lambda url, track_title="": _fake_apple_credit(track_title))
    report = app.build_song_report("https://music.apple.com/cn/song/the-fate-of-ophelia/6814997402",
                                   ["https://music.apple.com/cn/song/the-fate-of-ophelia/6814997402"], "apple", "6814997402")
    assert report["recording"] == {}
    assert report["source_errors"], "MB 失败要记进诊断"
    assert report["work_relations"]["status"] == "credits_only"
    assert report["work_relations"]["apple_credits"], "credits 与 work 关系合一展示"
    assert report["lyrics_candidates"][0]["track"] == "The Fate of Ophelia"


def test_build_song_report_japanese_lyric_sites(monkeypatch):
    itunes = _fake_itunes_track()
    itunes["results"][0]["trackName"] = "夜に駆ける"
    itunes["results"][0]["artistName"] = "YOASOBI"
    monkeypatch.setattr(app, "fetch_json", lambda url: itunes)
    monkeypatch.setattr(app, "mb_request", lambda path, params: {"recordings": [], "relations": [], "works": []})
    monkeypatch.setattr(app, "collect_apple_credits", lambda url, track_title="": {})
    report = app.build_song_report("https://music.apple.com/cn/song/夜に駆ける/111", ["https://music.apple.com/cn/song/夜に駆ける/111"], "apple", "111")
    sites = [l["site"] for l in report["lyrics_candidates"][0]["links"]]
    assert "J-Lyric.net" in sites and "UtaTen" in sites


def test_build_report_routes_song_to_song_report(monkeypatch):
    monkeypatch.setattr(app, "build_song_report", lambda *a, **k: {"report_type": "song", "song": {"title": "x"}})
    report = app.build_report("", "https://music.apple.com/cn/song/the-fate-of-ophelia/6814997402")
    assert report["report_type"] == "song"


# ------------------------------------------------------------------ 多平台单曲：spotify / deezer 都走单曲报告

def test_detect_song_url_platforms():
    assert app.detect_song_url("https://music.apple.com/cn/song/the-fate-of-ophelia/6814997402?x=1") == {"source": "apple", "track_id": "6814997402"}
    assert app.detect_song_url("https://music.apple.com/cn/album/the-life/6814997249") == {}
    assert app.detect_song_url("https://open.spotify.com/track/5Xecnqa3ODQuCK9BCms2VK?si=abc") == {"source": "spotify", "track_id": "5Xecnqa3ODQuCK9BCms2VK"}
    assert app.detect_song_url("https://open.spotify.com/intl-ja/track/5Xecnqa3ODQuCK9BCms2VK") == {"source": "spotify", "track_id": "5Xecnqa3ODQuCK9BCms2VK"}
    assert app.detect_song_url("https://open.spotify.com/album/4hF2gTGuPYlykYuphDxi8J") == {}
    assert app.detect_song_url("https://www.deezer.com/track/123456789") == {"source": "deezer", "track_id": "123456789"}
    assert app.detect_song_url("https://www.deezer.com/us/track/123456789") == {"source": "deezer", "track_id": "123456789"}
    assert app.detect_song_url("https://www.deezer.com/album/123456789") == {}


def test_build_song_report_spotify(monkeypatch):
    monkeypatch.setattr(app, "spotify_track", lambda track_id: {
        "id": "5Xecnqa3ODQuCK9BCms2VK", "title": "The Fate of Ophelia", "artist": "Taylor Swift",
        "album": "The Life of a Showgirl: The Encore", "album_id": "4hF2gTGuPYlykYuphDxi8J",
        "album_url": "https://open.spotify.com/album/4hF2gTGuPYlykYuphDxi8J", "isrc": "USUG12506436",
        "date": "2026-09-25", "length": "3:46", "url": "https://open.spotify.com/track/5Xecnqa3ODQuCK9BCms2VK",
        "image": "https://i.scdn.co/image/abc", "source": "Spotify 曲目",
    })
    monkeypatch.setattr(app, "mb_request", lambda path, params: {"recordings": [], "relations": [], "works": []})
    monkeypatch.setattr(app, "fetch_json", lambda url: {"results": []})  # itunes credits 搜索找不到（降级）
    report = app.build_song_report("https://open.spotify.com/track/5Xecnqa3ODQuCK9BCms2VK",
                                   ["https://open.spotify.com/track/5Xecnqa3ODQuCK9BCms2VK"], "spotify", "5Xecnqa3ODQuCK9BCms2VK")
    assert report["report_type"] == "song"
    s = report["song"]
    assert s["title"] == "The Fate of Ophelia"
    assert s["album_source"] == "Spotify"
    assert s["album_platform_id"] == "4hF2gTGuPYlykYuphDxi8J"
    assert s["album_url"] == "https://open.spotify.com/album/4hF2gTGuPYlykYuphDxi8J"
    assert s["isrc"] == "USUG12506436"
    assert report["external_links"][0]["site"] == "Spotify"
    assert report["external_links"][0]["relationship"] == "streaming"


def test_build_song_report_deezer(monkeypatch):
    monkeypatch.setattr(app, "deezer_track", lambda track_id: {
        "id": "123456789", "title": "The Fate of Ophelia", "artist": "Taylor Swift",
        "album": "The Life of a Showgirl: The Encore", "album_id": "987654321",
        "album_url": "https://www.deezer.com/album/987654321", "isrc": "USUG12506436",
        "date": "2026-09-25", "length": "3:46", "url": "https://www.deezer.com/track/123456789",
        "image": "https://cdns-preview-x.dzcdn.net/x.jpg", "source": "Deezer 曲目",
    })
    monkeypatch.setattr(app, "mb_request", lambda path, params: {"recordings": [], "relations": [], "works": []})
    monkeypatch.setattr(app, "fetch_json", lambda url: {"results": []})
    report = app.build_song_report("https://www.deezer.com/track/123456789",
                                   ["https://www.deezer.com/track/123456789"], "deezer", "123456789")
    s = report["song"]
    assert s["album_source"] == "Deezer"
    assert s["album_platform_id"] == "987654321"
    assert report["external_links"][0]["site"] == "Deezer"
    assert report["external_links"][0]["relationship"] == "streaming"


def test_build_song_report_spotify_uses_apple_credits(monkeypatch):
    monkeypatch.setattr(app, "spotify_track", lambda track_id: {
        "id": "t1", "title": "夜に駆ける", "artist": "YOASOBI", "album": "夜に駆ける",
        "album_id": "a1", "album_url": "https://open.spotify.com/album/a1", "isrc": "",
        "date": "", "length": "4:21", "url": "https://open.spotify.com/track/t1", "image": "",
        "source": "Spotify 曲目",
    })
    monkeypatch.setattr(app, "mb_request", lambda path, params: {"recordings": [], "relations": [], "works": []})
    # iTunes 搜到 Apple 页面 → 抓到 credits → credits_only
    def fake_fetch(url):
        if url.startswith("https://itunes.apple.com/search"):
            return {"results": [{"wrapperType": "track", "trackName": "夜に駆ける", "trackViewUrl": "https://music.apple.com/jp/song/x/123?i=456&uo=4"}]}
        return {"results": []}
    monkeypatch.setattr(app, "fetch_json", fake_fetch)
    monkeypatch.setattr(app, "collect_apple_credits", lambda url, track_title="": _fake_apple_credit(track_title) if "apple.com" in url else {})
    report = app.build_song_report("https://open.spotify.com/track/t1", ["https://open.spotify.com/track/t1"], "spotify", "t1")
    assert report["work_relations"]["status"] == "credits_only"
    assert report["apple_credits"][0]["track"] == "夜に駆ける"


# ------------------------------------------------------------ Sonovault ISRC 补查

def test_sonovault_track_search_parses_and_filters(monkeypatch):
    monkeypatch.setattr(app, "SONOVAULT_API_KEY", "test-key")
    monkeypatch.setattr(app, "fetch_json", lambda url, headers=None: {"results": [
        {"id": 1, "title": "Around the World (loop)", "artists": [{"name": "Daft Punk"}], "isrc": None, "iswc": None},
        {"id": 2, "title": "Around the World", "artists": [{"name": "Masters At Work"}, {"name": "Daft Punk"}], "isrc": "GBDUW0600009", "iswc": None},
    ]})
    got = app.sonovault_track_search("Around the World", "Daft Punk")
    assert got["isrc"] == "GBDUW0600009"
    assert got["title"] == "Around the World"


def test_sonovault_track_search_skips_without_key(monkeypatch):
    monkeypatch.setattr(app, "SONOVAULT_API_KEY", "")
    monkeypatch.setattr(app, "fetch_json", lambda url, headers=None: {"results": [{"isrc": "X"}]})
    assert app.sonovault_track_search("a", "b") == {}


def test_build_song_report_spotify_sonovault_fills_isrc(monkeypatch):
    monkeypatch.setattr(app, "SONOVAULT_API_KEY", "test-key")
    monkeypatch.setattr(app, "spotify_track", lambda track_id: {
        "id": "t1", "title": "The Fate of Ophelia", "artist": "Taylor Swift",
        "album": "The Life of a Showgirl: The Encore", "album_id": "", "album_url": "",
        "isrc": "", "date": "2026-09-25", "length": "4:00",
        "url": "https://open.spotify.com/track/t1", "image": "", "source": "Spotify 曲目",
    })
    monkeypatch.setattr(app, "mb_request", lambda path, params: {"recordings": [], "relations": [], "works": []})
    def fake_fetch(url, headers=None):
        if "api.sonovault.now" in url:
            return {"results": [{"id": 9, "title": "The Fate of Ophelia", "artists": [{"name": "Taylor Swift"}], "isrc": "USUMV2503024", "iswc": "T-123.456.789-0"}]}
        if url.startswith("https://itunes.apple.com/search"):
            return {"results": []}
        return {"results": []}
    monkeypatch.setattr(app, "fetch_json", fake_fetch)
    report = app.build_song_report("https://open.spotify.com/track/t1", ["https://open.spotify.com/track/t1"], "spotify", "t1")
    assert report["song"]["isrc"] == "USUMV2503024"
    assert report["song"]["iswc"] == "T-123.456.789-0"
    assert any("Sonovault" in note for note in report["api_notes"])


def test_build_song_report_spotify_sonovault_miss_stays_silent(monkeypatch):
    monkeypatch.setattr(app, "SONOVAULT_API_KEY", "test-key")
    monkeypatch.setattr(app, "spotify_track", lambda track_id: {
        "id": "t1", "title": "夜に駆ける", "artist": "YOASOBI", "album": "夜に駆ける",
        "album_id": "", "album_url": "", "isrc": "", "date": "", "length": "4:21",
        "url": "https://open.spotify.com/track/t1", "image": "", "source": "Spotify 曲目",
    })
    monkeypatch.setattr(app, "mb_request", lambda path, params: {"recordings": [], "relations": [], "works": []})
    def fake_fetch(url, headers=None):
        if "api.sonovault.now" in url:
            return {"results": []}
        if url.startswith("https://itunes.apple.com/search"):
            return {"results": []}
        return {"results": []}
    monkeypatch.setattr(app, "fetch_json", fake_fetch)
    report = app.build_song_report("https://open.spotify.com/track/t1", ["https://open.spotify.com/track/t1"], "spotify", "t1")
    assert report["song"]["isrc"] == ""
    assert not any("Sonovault" in err.get("error", "") for err in report["source_errors"])


# ------------------------------------------------------------ Soundcharts ISRC 补查

def test_soundcharts_by_platform_id_parses_envelope(monkeypatch):
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_TOKEN_CACHE", {})
    seen: list[str] = []
    monkeypatch.setattr(app, "fetch_json", lambda url, headers=None: (
        seen.append(url) or {
            "type": "song",
            "object": {
                "uuid": "abc-123",
                "name": "The Fate of Ophelia",
                "isrc": {"value": "USUMV2503024", "countryCode": "US"},
                "iswcs": ["T-123.456.789-0"],
                "mainArtists": [{"name": "Taylor Swift", "appUrl": "https://soundcharts.com/app/artist/x"}],
                "appUrl": "https://soundcharts.com/app/song/abc-123",
                "duration": 240,
            },
        }
    ))
    got = app.soundcharts_song_by_platform_id("spotify", "t1")
    assert got["isrc"] == "USUMV2503024"
    assert got["iswc"] == "T-123.456.789-0"
    assert got["title"] == "The Fate of Ophelia"
    assert got["source_url"] == "https://soundcharts.com/app/song/abc-123"
    assert "song/by-platform/spotify/t1" in seen[0]


def test_soundcharts_platform_code_mapping(monkeypatch):
    # 歌曲级 Apple 链接的 Soundcharts 平台代码是 itunes（不是 apple-music）
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_TOKEN_CACHE", {})
    seen: list[str] = []
    monkeypatch.setattr(app, "fetch_json", lambda url, headers=None: (
        seen.append(url) or {"object": {"uuid": "u", "name": "x", "isrc": {"value": "USX"}}}
    ))
    got = app.soundcharts_song_by_platform_id("apple", "42")
    assert got["isrc"] == "USX"
    assert "by-platform/itunes/42" in seen[0]


def test_soundcharts_skips_without_credentials(monkeypatch):
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "")
    monkeypatch.setattr(app, "fetch_json", lambda url, headers=None: {"object": {"uuid": "x"}})
    assert app.soundcharts_song_by_platform_id("spotify", "t1") == {}


def test_soundcharts_unknown_source_skipped(monkeypatch):
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "")
    monkeypatch.setattr(app, "fetch_json", lambda url, headers=None: {"object": {"uuid": "x"}})
    assert app.soundcharts_song_by_platform_id("youtube", "t1") == {}


def test_soundcharts_no_match_returns_empty(monkeypatch):
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "")
    monkeypatch.setattr(app, "fetch_json", lambda url, headers=None: {"message": "No song found"})
    assert app.soundcharts_song_by_platform_id("spotify", "t1") == {}


def test_soundcharts_404_not_found_stays_silent(monkeypatch):
    # 404 = 曲库未收录，属于正常结果，静默返回 {}（不抛错、不上 warning）
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_TOKEN_CACHE", {})
    def not_found(url, headers=None):
        raise app.FetchError("HTTP Error 404: Not Found")
    monkeypatch.setattr(app, "fetch_json", not_found)
    assert app.soundcharts_song_by_platform_id("spotify", "t1") == {}


def test_soundcharts_401_raises_for_caller(monkeypatch):
    # 401 = 凭据问题，需要让调用方知道（区别于未收录）
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "wrong-key")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_TOKEN_CACHE", {})
    def unauthorized(url, headers=None):
        raise app.FetchError("HTTP Error 401: Unauthorized")
    monkeypatch.setattr(app, "fetch_json", unauthorized)
    try:
        app.soundcharts_song_by_platform_id("spotify", "t1")
        raise AssertionError("401 应该抛 FetchError")
    except app.FetchError:
        pass


def test_build_song_report_spotify_soundcharts_fills_isrc_when_sonovault_misses(monkeypatch):
    # Sonovault 未命中（日文原文标题不索引等）→ Soundcharts 按平台曲目 ID 直查补上
    monkeypatch.setattr(app, "SONOVAULT_API_KEY", "test-key")
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_TOKEN_CACHE", {})
    monkeypatch.setattr(app, "spotify_track", lambda track_id: {
        "id": "t1", "title": "夜に駆ける", "artist": "YOASOBI", "album": "夜に駆ける",
        "album_id": "", "album_url": "", "isrc": "", "date": "", "length": "4:21",
        "url": "https://open.spotify.com/track/t1", "image": "", "source": "Spotify 曲目",
    })
    monkeypatch.setattr(app, "mb_request", lambda path, params: {"recordings": [], "relations": [], "works": []})
    def fake_fetch(url, headers=None):
        if "api.sonovault.now" in url:
            return {"results": []}
        if "customer.api.soundcharts.com" in url:
            return {"object": {
                "uuid": "sc-uuid-1",
                "name": "夜に駆ける",
                "isrc": {"value": "JPP301900716"},
                "iswcs": ["T-101.234.567-8"],
                "mainArtists": [{"name": "YOASOBI"}],
                "appUrl": "https://soundcharts.com/app/song/sc-uuid-1",
            }}
        if url.startswith("https://itunes.apple.com/search"):
            return {"results": []}
        return {"results": []}
    monkeypatch.setattr(app, "fetch_json", fake_fetch)
    report = app.build_song_report("https://open.spotify.com/track/t1", ["https://open.spotify.com/track/t1"], "spotify", "t1")
    assert report["song"]["isrc"] == "JPP301900716"
    assert report["song"]["iswc"] == "T-101.234.567-8"
    assert any("Soundcharts" in note for note in report["api_notes"])


def test_build_song_report_sonovault_hit_does_not_call_soundcharts(monkeypatch):
    # Sonovault 命中时不触发 Soundcharts（Soundcharts 计费，省调用）
    monkeypatch.setattr(app, "SONOVAULT_API_KEY", "test-key")
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "soundcharts")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_TOKEN_CACHE", {})
    calls: list[str] = []
    monkeypatch.setattr(app, "spotify_track", lambda track_id: {
        "id": "t1", "title": "The Fate of Ophelia", "artist": "Taylor Swift", "album": "a",
        "album_id": "", "album_url": "", "isrc": "", "date": "", "length": "4:00",
        "url": "https://open.spotify.com/track/t1", "image": "", "source": "Spotify 曲目",
    })
    monkeypatch.setattr(app, "mb_request", lambda path, params: {"recordings": [], "relations": [], "works": []})
    def fake_fetch(url, headers=None):
        calls.append(url)
        if "api.sonovault.now" in url:
            return {"results": [{"id": 9, "title": "The Fate of Ophelia", "artists": [{"name": "Taylor Swift"}], "isrc": "USUMV2503024", "iswc": "T-9"}]}
        if url.startswith("https://itunes.apple.com/search"):
            return {"results": []}
        return {"results": []}
    monkeypatch.setattr(app, "fetch_json", fake_fetch)
    report = app.build_song_report("https://open.spotify.com/track/t1", ["https://open.spotify.com/track/t1"], "spotify", "t1")
    assert report["song"]["isrc"] == "USUMV2503024"
    assert not any("customer.api.soundcharts.com" in u for u in calls)


# ------------------------------------------------------------ /api/usage 用量查询

def test_collect_usage_status_not_configured(monkeypatch):
    monkeypatch.setattr(app, "SONOVAULT_API_KEY", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "")
    status = app.collect_usage_status()
    assert status["sources"]["sonovault"]["configured"] is False
    assert status["sources"]["soundcharts"]["configured"] is False
    assert "usage" not in status["sources"]["soundcharts"]
    assert status["sources"]["sonovault"]["usage_api"] is False


def test_collect_usage_status_soundcharts_fetches_usage(monkeypatch):
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "cid")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "csecret")
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_TOKEN_CACHE", {})
    monkeypatch.setattr(app, "soundcharts_team_usage", lambda: {
        "quota": {"limit": 1000, "used": 1, "remaining": 999, "period": "", "end_period_date": None},
        "rate_limit": {"limit_per_minute": 10000, "used": 0, "remaining": 10000, "reset_in_seconds": 37},
    })
    status = app.collect_usage_status()
    assert status["sources"]["soundcharts"]["auth"] == "oauth"
    assert status["sources"]["soundcharts"]["usage"]["quota"]["remaining"] == 999
    assert status["sources"]["sonovault"]["configured"] is False


def test_soundcharts_team_usage_parses_envelope(monkeypatch):
    class FakeResp:
        def read(self):
            return json.dumps({
                "type": "usage",
                "object": {
                    "quota": {"limit": 1000, "used": 1, "remaining": 999, "period": "", "endPeriodDate": None},
                    "rateLimit": {"limitPerMinute": 10000, "used": 0, "remaining": 10000, "resetInSeconds": 37},
                },
                "errors": [],
            }).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class FakeOpener:
        def open(self, req, timeout=20):
            return FakeResp()

    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_ID", "cid")
    monkeypatch.setattr(app, "SOUNDCHARTS_CLIENT_SECRET", "csecret")
    monkeypatch.setattr(app, "SOUNDCHARTS_APP_ID", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_API_KEY", "")
    monkeypatch.setattr(app, "SOUNDCHARTS_TOKEN_CACHE", {"token": "tok", "expires_at": app.time.time() + 3600})
    monkeypatch.setattr(app, "GUARDED_OPENER", FakeOpener())
    got = app.soundcharts_team_usage()
    assert got["quota"]["remaining"] == 999
    assert got["rate_limit"]["limit_per_minute"] == 10000
    assert got["rate_limit"]["reset_in_seconds"] == 37
