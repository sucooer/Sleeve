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
