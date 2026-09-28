from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unicodedata
from collections import Counter
from html import escape, unescape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import count
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import HTTPError, URLError
from uuid import uuid4

SRC_DIR = Path(__file__).resolve().parent
ROOT = SRC_DIR.parent / "public"
HOST = os.environ.get("SLEEVE_HOST", "127.0.0.1")
PORT = int(os.environ.get("SLEEVE_PORT", "8765"))
def resolve_version(raw: str | None = None) -> str:
    """应用版本号。镜像里由 CI 传 --build-arg VERSION → ENV SLEEVE_VERSION 注入；
    本地直接跑没有这个环境变量时降级为 dev —— 代码里永远不硬编码第二份版本号。"""
    value = (raw if raw is not None else os.environ.get("SLEEVE_VERSION", "")).strip()
    return value or "dev"

VERSION = resolve_version()
USER_AGENT = f"Sleeve/{VERSION} (local metadata preparation tool)"
MB_BASE = "https://musicbrainz.org/ws/2"
MB_LAST_REQUEST = 0.0
# 限速时间戳必须与「打请求」这个动作原子地绑在一起，否则并发下形同虚设（见 mb_request）
MB_LOCK = threading.Lock()

# 静态资源的 Content-Type。
# 默认给 application/octet-stream 而不是 text/plain：站点图标一旦被标成 text/plain，
# 浏览器会拒绝把它当图片用，图标就静默失效 —— 页面里看不出任何报错，
# 只有「标签页上是空白」这一个现象，很难往 MIME 上想。
STATIC_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".webmanifest": "application/manifest+json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
}

# 前端脚本与样式跟后端放在同一个目录（代码归 src/，public/ 只留纯静态资源），
# 所以这两条 URL 必须显式映射过去。
#
# 这样做顺带更安全：映射表是**写死的常量**，不拼接任何用户输入，
# 因此这两条路径上不存在目录穿越的可能。src/ 里其余文件（比如 app.py 自己）
# 一律不对外，`/app.py` 只会拿到 404。
FRONTEND_ASSETS: dict[str, tuple[str, str]] = {
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}

# ------------------------------------------------------------------ 网络：优先 IPv4
#
# 本机（以及不少国内网络）的 IPv6 是「能解析、但连不通」的状态。实测：
#     api.deezer.com     IPv4 0.01s 通 / IPv6 5s 超时
#     musicbrainz.org    IPv4 0.02s 通 / IPv6 5s 超时
# 而这些站点都走 CDN 轮询 DNS，返回的地址顺序每次都可能不同 ——
# 一旦 IPv6 排在前面，urllib 会把整个超时都耗在一条死路上；
# 再叠上「失败重试」，单次调用就能拖到 80 秒以上（这正是查询慢的一大来源）。
#
# 这里把 IPv4 排到候选列表前面，IPv6 仍然保留：IPv4 真的连不上时照样会回落到它。
# 想恢复系统默认顺序：设环境变量 SLEEVE_IPV4_FIRST=0
if os.environ.get("SLEEVE_IPV4_FIRST", "1") != "0":
    _default_getaddrinfo = socket.getaddrinfo

    def _ipv4_first_getaddrinfo(host, *args, **kwargs):  # type: ignore[no-untyped-def]
        infos = _default_getaddrinfo(host, *args, **kwargs)
        return sorted(infos, key=lambda info: 0 if info[0] == socket.AF_INET else 1)

    socket.getaddrinfo = _ipv4_first_getaddrinfo


class FetchError(Exception):
    pass


# 4xx 是确定性失败：链接不存在、没有权限、参数不对 —— 重试只会白白拖长等待。
# 408（请求超时）、425（过早）、429（限流）是例外，它们确实值得再试一次。
RETRYABLE_HTTP_STATUS = {408, 425, 429}


def is_permanent_failure(exc: BaseException) -> bool:
    if isinstance(exc, HTTPError):
        code = getattr(exc, "code", 0) or 0
        return 400 <= code < 500 and code not in RETRYABLE_HTTP_STATUS
    return False


def is_timeout_failure(exc: BaseException) -> bool:
    """超时（含 TLS 握手超时）。urllib 会把原始异常包进 URLError.reason，所以两边都要看。"""
    if isinstance(exc, TimeoutError):
        return True
    reason = getattr(exc, "reason", None)
    if isinstance(reason, TimeoutError):
        return True
    return "timed out" in str(exc).lower() or "timed out" in str(reason).lower()


def ascii_url(url: str) -> str:
    """把 URL 里的非 ASCII 字符（中文路径等）做百分号编码。

    浏览器地址栏复制出来的链接经常是解码形态，例如
    `https://music.apple.com/cn/album/要去什么地方/6812635395`。
    urllib 只接受 ASCII URL，不处理会直接抛 UnicodeEncodeError，
    整次查询 500 挂掉 —— 表现是「粘贴链接后什么都没发生」。
    safe 里保留 `%`，否则已经编码好的 %E9 会被二次编码成 %25E9。
    """
    return quote(url, safe=":/?#[]@!$&'()*+,;=%~")


# ------------------------------------------------------------------ 网络：响应缓存
#
# 免费路线（iTunes Search API + Deezer 公开 API）都没有 SLA，而一次查询会打出 30~50 个
# 出网请求，其中 iTunes 约 8 个。iTunes Search API 的限流约 20 次/分钟/IP，且**超限时
# 静默返回 `resultCount: 0`（不是 429）** —— 限流会直接伪装成「这张专辑查不到」。
# Apple 官方文档也写着「大型站点应为 search / lookup 请求加缓存」。
#
# 「改完品番再查一遍」「换个链接再查同一张」是最常见的用法，缓存能把这类重复查询的
# 出网请求直接降到 0，既省时间也避开限流。可按需关闭：
#     SLEEVE_CACHE=0           关闭缓存
#     SLEEVE_CACHE_TTL=600     改有效期（秒，默认 3600）
#     SLEEVE_CACHE_DIR=...     改缓存目录（默认系统临时目录）
CACHE_ENABLED = os.environ.get("SLEEVE_CACHE", "1").strip().lower() not in {"0", "false", "no", "off"}
CACHE_DIR = Path(os.environ.get("SLEEVE_CACHE_DIR") or (Path(tempfile.gettempdir()) / "sleeve-cache"))
try:
    CACHE_TTL = int(os.environ.get("SLEEVE_CACHE_TTL", "3600"))
except ValueError:
    CACHE_TTL = 3600  # 环境变量填错不该让服务起不来，退回默认值
CACHE_STORE_SWEEP_EVERY = 200
CACHE_SWEEP_LOCK = threading.Lock()
CACHE_STORE_COUNT = count()


class CacheStats(threading.local):
    """缓存命中计数，每个线程各存一份。

    ThreadingHTTPServer 是「一个连接一个线程」，所以线程局部实际上就等于请求局部：
    原来的全局 dict 会被并发查询互相清零，报告里那句「本次有 N 个命中缓存」
    就成了假数据（谁最后清零、谁最后写报告，全看调度顺序）。
    """

    def __init__(self) -> None:
        self.hit = 0
        self.miss = 0


CACHE_STATS = CacheStats()

# ------------------------------------------------------------------ 访问控制
#
# 这个服务默认没有任何鉴权，因为它最初只跑在本机 127.0.0.1 上。一旦挂到公网，
# /api/lookup 是**完全裸奔**的：一次调用会扇出十几个对外的请求，任何人拿到地址
# 都能把你的上游额度用光，并让你这台机器的 IP 被 iTunes / Deezer / MusicBrainz
# 一起限流。所以公网部署必须先开这两道闸。
#
# 沿用本仓库一贯的「配了才启用、没配不改变行为」风格：
#     SLEEVE_AUTH=user:password        开启认证（前端显示自定义登录页，替代浏览器原生 Basic 弹框）
#     SLEEVE_RATE_LIMIT=30/60          每 IP 每 60 秒最多 30 次请求
# /api/health 与 /api/login 永远豁免 —— health 供探针使用（响应里带 auth 标志），
# login 是前端登录页的凭据校验入口，凭据在其内部自行比对。
#
# 2026-09-27 补上守卫：原来只校验 SLEEVE_AUTH 的**格式**，不校验它是否**生效**。
# 照着 .env.example 抄一份 .env 得到的就是「绑定 0.0.0.0 + 空口令」，一句
# `docker compose up -d` 就裸奔上线了。现在「对外监听 + 无鉴权」直接拒绝启动，
# 逃生阀是 SLEEVE_AUTH_ALLOW_OPEN=1（见下）。
AUTH_RAW = os.environ.get("SLEEVE_AUTH", "").strip()
if AUTH_RAW and ":" not in AUTH_RAW:
    # 宁可起不来，也不要静默地以「无鉴权」状态对外服务 —— 那正是最危险的失败方式
    raise SystemExit("SLEEVE_AUTH 格式应为 user:password，当前值里没有冒号，拒绝启动。")
AUTH_HEADER = "Basic " + base64.b64encode(AUTH_RAW.encode("utf-8")).decode("ascii") if AUTH_RAW else ""

# 逃生阀：确要在可信网络里无鉴权开放时才显式设 1
ALLOW_OPEN_NO_AUTH = os.environ.get("SLEEVE_AUTH_ALLOW_OPEN", "").strip().lower() in {"1", "true", "yes", "on"}


def bind_is_loopback(value: str) -> bool:
    """这个监听 / 发布地址是否只有本机能访问。空值按「全网卡」（0.0.0.0）处理。"""
    host = (value or "").strip().strip("[]").lower()
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# 「对外」看的是**能被谁访问**，不是进程绑在哪个网卡上：
#   - 直接跑 app.py：就是 HOST 本身；
#   - docker compose：容器里必须绑 0.0.0.0（否则宿主机的端口映射进不来），
#     真正决定暴露面的是宿主机上的发布地址，compose 把 ${SLEEVE_BIND}
#     通过 SLEEVE_PUBLISH_BIND 传进来。
EXPOSED_BIND = os.environ.get("SLEEVE_PUBLISH_BIND", "").strip() or HOST
# 对外监听时，500 的正文只留一句「详情见服务端日志」：异常里可能带上游原文、内网主机名与路径
DETAIL_IN_ERRORS = bind_is_loopback(EXPOSED_BIND)

if not AUTH_HEADER and not ALLOW_OPEN_NO_AUTH and not bind_is_loopback(EXPOSED_BIND):
    raise SystemExit(
        f"监听地址 {EXPOSED_BIND} 对外且未设置 SLEEVE_AUTH，拒绝启动。\n"
        "  · 要对外开放：设 SLEEVE_AUTH=user:password（并套一层 HTTPS 反向代理）；\n"
        "  · 只给本机用：把监听 / 发布地址改回 127.0.0.1（SLEEVE_HOST / SLEEVE_BIND）；\n"
        "  · 确要在可信网络里无鉴权开放：显式设 SLEEVE_AUTH_ALLOW_OPEN=1。\n"
        "无鉴权的 /api/lookup 等于一个开放代理：任何人都能借你的 IP 扇出 30~50 个出网请求，\n"
        "并把 MusicBrainz「每秒 1 次」的配额打光。"
    )


def parse_rate_limit(raw: str) -> tuple[int, int]:
    """把 "30/60" 解析成 (30, 60)；格式不对或未设置则返回 (0, 0) 表示不限流。"""
    raw = (raw or "").strip()
    if not raw:
        return (0, 0)
    try:
        count, window = raw.split("/", 1)
        limit, seconds = int(count), int(window)
    except ValueError:
        print(f"[warn] SLEEVE_RATE_LIMIT 格式应为 次数/秒数，忽略当前值：{raw}", flush=True)
        return (0, 0)
    return (limit, seconds) if limit > 0 and seconds > 0 else (0, 0)


RATE_LIMIT_MAX, RATE_LIMIT_WINDOW = parse_rate_limit(os.environ.get("SLEEVE_RATE_LIMIT", ""))
RATE_LOCK = threading.Lock()
RATE_HITS: dict[str, list[float]] = {}


def rate_limit_allow(client_ip: str) -> bool:
    """滑动窗口限流。只保证「同一个 IP 不会把上游打爆」，不是精确的配额系统。"""
    if not RATE_LIMIT_MAX:
        return True
    now = time.time()
    with RATE_LOCK:
        hits = [stamp for stamp in RATE_HITS.get(client_ip, []) if now - stamp < RATE_LIMIT_WINDOW]
        if len(hits) >= RATE_LIMIT_MAX:
            RATE_HITS[client_ip] = hits
            return False
        hits.append(now)
        RATE_HITS[client_ip] = hits
        # 顺手回收沉寂条目，否则这个 dict 会随来访 IP 数无限增长
        if len(RATE_HITS) > 4096:
            for key in [k for k, v in RATE_HITS.items() if not v or now - v[-1] > RATE_LIMIT_WINDOW]:
                RATE_HITS.pop(key, None)
    return True


def cache_key(kind: str, url: str, body: str = "") -> str:
    return hashlib.sha1(f"{kind}|{url}|{body}".encode("utf-8")).hexdigest()


def cache_load(key: str) -> Any | None:
    if not CACHE_ENABLED:
        return None
    path = CACHE_DIR / f"{key}.json"
    try:
        if time.time() - path.stat().st_mtime > CACHE_TTL:
            return None
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle).get("payload")
    except (OSError, ValueError, AttributeError):
        # 缓存文件损坏 / 被别的进程删掉：当未命中处理，不影响查询
        return None


def cache_store(key: str, payload: Any) -> None:
    if not CACHE_ENABLED:
        return
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        # 临时名带上线程号与一段随机串：两个并发查询写同一个 key 时不会互相踩写。
        # 踩写的后果被 cache_load 兜成 miss，不报错，但会白写一次。
        temp_path = CACHE_DIR / f"{key}.{os.getpid()}.{threading.get_ident()}.{uuid4().hex[:8]}.tmp"
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump({"payload": payload}, handle, ensure_ascii=False)
        temp_path.replace(CACHE_DIR / f"{key}.json")  # 原子替换，避免读到写了一半的文件
    except (OSError, TypeError, ValueError):
        # 缓存只是加速手段，磁盘不可写或序列化失败都不该让查询本身失败
        pass
    sweep_cache_once_in_a_while()


def cache_sweep_expired() -> None:
    """删掉超过 TTL 的缓存文件。

    TTL 原来只在**读**时生效：过期文件不会被返回，但也不会被删除 ——
    一次查询要写 30~50 个文件，长跑服务（compose 里挂在 /data 卷上）只增不减。
    """
    try:
        deadline = time.time() - CACHE_TTL
        # 正常写入的临时文件只存在毫秒级，看到的 .tmp 基本都是崩在写盘的残骸，一起按 TTL 清
        for pattern in ("*.json", "*.tmp"):
            for path in CACHE_DIR.glob(pattern):
                try:
                    if path.stat().st_mtime < deadline:
                        path.unlink()
                except OSError:
                    continue  # 刚好被别的线程删掉 / 文件被占用：跳过这一条就够了
    except OSError:
        pass  # 缓存目录不存在或不可读：清理失败不该影响查询


def sweep_cache_once_in_a_while() -> None:
    """每写 N 次缓存顺手清一次过期文件；已有线程在清就直接跳过。"""
    if next(CACHE_STORE_COUNT) % CACHE_STORE_SWEEP_EVERY:
        return
    if not CACHE_SWEEP_LOCK.acquire(blocking=False):
        return
    try:
        cache_sweep_expired()
    finally:
        CACHE_SWEEP_LOCK.release()


def cache_usable(payload: Any) -> bool:
    """错误响应不能进缓存。

    Deezer 用「HTTP 200 + {"error": ...}」表达失败（见下方 deezer_error），
    缓存它会把一次瞬时抖动锁成整段 TTL 内的「查不到」。
    """
    return not (isinstance(payload, dict) and payload.get("error"))


def cache_hit_note() -> str:
    if not CACHE_ENABLED or not CACHE_STATS.hit:
        return ""
    return f"本次有 {CACHE_STATS.hit} 个出网请求命中本地缓存（有效期 {CACHE_TTL} 秒），未重复访问来源站点。"


# ------------------------------------------------------------------ 出网边界（SSRF）
#
# /api/lookup 会**拿服务端身份去抓调用者贴的那个链接** —— fetch_text 全项目只有
# source_page_summary 一个调用点，参数就是用户输入。所以这个服务天然带 SSRF 面。
# 未设防时实测：
#     source_page_summary("http://127.0.0.1:8819/secret")
#       → status ok, title='SSRF-MARKER-12345', description='internal-only page, ...'
# 也就是任何人都能驱使这台机器去访问它所在的网络：云元数据 169.254.169.254、
# 回环上的其它服务、内网扫描；而 urlopen 还接受 file://，本地文件一样会被打开。
#
# 三道闸。只作用在**用户可控的 URL** 上；服务端自己的 API 调用
# （fetch_json / post_json，URL 全是写死的常量）不走第三道，
# 免得白名单写窄了反而把正常功能掐掉。
#   1) 只允许 http / https         —— 挡掉 file:// 等协议
#   2) 解析后按 IP 拒绝非公网地址   —— 挡掉回环 / 私有 / 链路本地 / 保留 / CGNAT
#   3) 主机必须在已知平台表里       —— 复用 site_info 的 URL_SITE_RULES，
#                                     不另维护第二份域名清单
# 想抓冷门站点的链接可以设 SLEEVE_ALLOW_ANY_USER_HOST=1，前两道闸仍然生效。
#
# 重定向要**逐跳**复检：urlopen 默认跟随 301/302/307/308，只在入口校验一次的话，
# 白名单域名 302 到 169.254.169.254 就能把内网响应读进报告。
# 统一走 GUARDED_OPENER（见 GuardedRedirectHandler），每一跳都重新过闸。
#
# 如实记一个残留风险：第 2 道是「先解析判断、再交给 urlopen」，两次解析之间存在
# DNS 重绑定窗口。要彻底关掉得自己解析 IP 并直连（还得处理 TLS SNI），代价不成比例。
# 配合第 3 道的域名白名单之后，攻击者得先控制一个已在表内的域名才谈得上重绑定。
ALLOW_ANY_USER_HOST = os.environ.get("SLEEVE_ALLOW_ANY_USER_HOST", "").strip().lower() in {
    "1", "true", "yes", "on",
}


def address_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """这个 IP 是否在公网。

    用 is_global 而不是 is_private —— 实测差别很关键：
    100.64.0.1（CGNAT 段）的 is_private 是 **False**，只查 is_private 会把它放过去，
    而 is_global 是 False。is_global 对 ::ffff:127.0.0.1 这类 v4-mapped 地址
    也按 v4 规则处理，不需要自己去拆。
    唯一要额外补的是组播：224.0.0.1 的 is_global 居然是 True。
    """
    return ip.is_global and not ip.is_multicast


def check_outbound(url: str, user_supplied: bool = False) -> None:
    """出网总闸。不通过就抛 FetchError —— 走既有错误传播路径，会显示在查询诊断里。"""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise FetchError(f"只允许 http/https 链接，当前协议是「{parsed.scheme or '空'}」：{url}")
    host = parsed.hostname or ""
    if not host:
        raise FetchError(f"链接里没有主机名：{url}")
    if user_supplied and not ALLOW_ANY_USER_HOST and not site_info(url)[0]:
        raise FetchError(
            f"{host} 不在已知平台列表里，已拒绝抓取；"
            "如确需访问该站点，设置 SLEEVE_ALLOW_ANY_USER_HOST=1 可放开（其余两道闸仍生效）"
        )
    try:
        infos = socket.getaddrinfo(
            host, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP
        )
    except OSError as exc:
        raise FetchError(f"域名解析失败：{host}（{exc}）") from exc
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if not address_is_public(address):
            raise FetchError(f"拒绝访问非公网地址：{host} → {address}")


class GuardedRedirectHandler(HTTPRedirectHandler):
    """每一跳重定向都重新过闸。

    三道闸原来只在 urlopen **之前**校验一次，而 urllib 默认会静默跟随
    301/302/307/308（最多 10 跳），跳转目标不再过闸：

        用户贴 link → check_outbound 通过（公网 IP + 白名单域名）
          → 该域名 302 → http://169.254.169.254/latest/meta-data/
          → urlopen 无校验跟随 → 内网响应的 <title>/og:description 进报告

    也就是说，白名单里任何一个域名只要挂了恶意跳转，第一、二道闸就一起形同虚设。
    这里在每一跳上重新跑一遍 check_outbound，并且把 Request 上的 user_supplied
    标记带到下一跳 —— 否则从第二跳起，白名单那道闸会悄悄失效。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        target = urljoin(req.full_url, newurl)
        check_outbound(target, user_supplied=bool(getattr(req, "user_supplied", False)))
        redirected = super().redirect_request(req, fp, code, msg, headers, target)
        if redirected is not None and getattr(req, "user_supplied", False):
            redirected.user_supplied = True
        return redirected


# 出网统一走这个 opener：默认的 urlopen 不带任何跳转校验（见上）
GUARDED_OPENER = build_opener(GuardedRedirectHandler)


def fetch_json(url: str, headers: dict[str, str] | None = None, timeout: int = 20, retries: int = 2) -> Any:
    if not urlparse(url or "").scheme:
        raise FetchError(f"链接不是完整 URL：{url}")
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    target = ascii_url(url)
    check_outbound(target)
    key = cache_key("GET", target)
    cached = cache_load(key)
    if cached is not None:
        CACHE_STATS.hit += 1
        return cached
    CACHE_STATS.miss += 1
    request = Request(target, headers=request_headers)
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with GUARDED_OPENER.open(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
                if cache_usable(payload):
                    cache_store(key, payload)
                return payload
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            last_error = exc
            # 超时不再重试：一次 20 秒都没握上手，再等两轮多半还是白等，
            # 却会把「某个源挂了」放大成 60 秒以上的整体等待。4xx 同理（确定性失败）。
            if is_permanent_failure(exc) or attempt >= (0 if is_timeout_failure(exc) else retries):
                break
            time.sleep(1.2 * (attempt + 1))
    raise FetchError(str(last_error))


def post_json(url: str, payload: Any, headers: dict[str, str] | None = None, timeout: int = 25, retries: int = 2) -> Any:
    if not urlparse(url or "").scheme:
        raise FetchError(f"链接不是完整 URL：{url}")
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json", "Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    body = json.dumps(payload).encode("utf-8")
    target = ascii_url(url)
    check_outbound(target)
    key = cache_key("POST", target, body.decode("utf-8"))
    cached = cache_load(key)
    if cached is not None:
        CACHE_STATS.hit += 1
        return cached
    CACHE_STATS.miss += 1
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with GUARDED_OPENER.open(Request(target, data=body, headers=request_headers), timeout=timeout) as response:
                result = json.loads(response.read().decode("utf-8", errors="replace"))
                if cache_usable(result):
                    cache_store(key, result)
                return result
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            last_error = exc
            # 超时不再重试：一次 20 秒都没握上手，再等两轮多半还是白等，
            # 却会把「某个源挂了」放大成 60 秒以上的整体等待。4xx 同理（确定性失败）。
            if is_permanent_failure(exc) or attempt >= (0 if is_timeout_failure(exc) else retries):
                break
            time.sleep(1.2 * (attempt + 1))
    raise FetchError(str(last_error))


def fetch_text(url: str, timeout: int = 20, retries: int = 2) -> str:
    if not urlparse(url or "").scheme:
        raise FetchError(f"链接不是完整 URL：{url}")
    target = ascii_url(url)
    # 全项目只有 source_page_summary 会调 fetch_text，参数就是用户贴的链接 ——
    # 所以这里是唯一需要过第三道闸（已知平台白名单）的地方。
    check_outbound(target, user_supplied=True)
    key = cache_key("TEXT", target)
    cached = cache_load(key)
    if cached is not None:
        CACHE_STATS.hit += 1
        return cached
    CACHE_STATS.miss += 1
    request = Request(target, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"})
    # 标记「这条 URL 来自用户输入」：重定向处理器据此让每一跳都过第三道闸（白名单）
    request.user_supplied = True
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with GUARDED_OPENER.open(request, timeout=timeout) as response:
                text = response.read().decode("utf-8", errors="replace")
                cache_store(key, text)
                return text
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            last_error = exc
            # 超时不再重试：一次 20 秒都没握上手，再等两轮多半还是白等，
            # 却会把「某个源挂了」放大成 60 秒以上的整体等待。4xx 同理（确定性失败）。
            if is_permanent_failure(exc) or attempt >= (0 if is_timeout_failure(exc) else retries):
                break
            time.sleep(1.2 * (attempt + 1))
    raise FetchError(str(last_error))


def first(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


MB_PLACEHOLDERS = {"[no label]", "[none]", "[no catalog number]", "[unknown]", "[no barcode]", "[no title]", "[untitled]"}


def clean_value(value: Any) -> str:
    text = first(value).strip()
    return "" if text.casefold() in MB_PLACEHOLDERS else text


def named_text(value: Any) -> str:
    if isinstance(value, dict):
        return first(value.get("name"))
    if isinstance(value, list):
        return " / ".join(named_text(item) for item in value if named_text(item))
    return first(value)


def format_duration(milliseconds: Any) -> str:
    try:
        total_seconds = max(0, round(int(milliseconds) / 1000))
    except (TypeError, ValueError):
        return ""
    return f"{total_seconds // 60}:{total_seconds % 60:02d}"


def iso_date(value: Any) -> str:
    text = first(value)
    return text[:10] if text else ""


def extract_apple_id(url: str) -> str:
    # 只在 Apple 域名下取 ID：Deezer / TIDAL 的 /album/<数字> 也会命中同一个模式
    if "apple.com" not in urlparse(url or "").netloc.lower():
        return ""
    match = re.search(r"/(?:album|playlist)/(?:[^/?]+/)?(\d+)(?:[/?]|$)", url or "", re.I)
    if match:
        return match.group(1)
    parsed = urlparse(url or "")
    return parse_qs(parsed.query).get("i", [""])[0]


def extract_spotify_id(url: str) -> str:
    match = re.search(r"open\.spotify\.com/(?:intl-[a-z-]+/)?album/([A-Za-z0-9]{22})", url or "", re.I)
    return match.group(1) if match else ""


def extract_spotify_track_id(url: str) -> str:
    match = re.search(r"open\.spotify\.com/(?:intl-[a-z-]+/)?track/([A-Za-z0-9]{22})", url or "", re.I)
    return match.group(1) if match else ""


def extract_mbids(url: str) -> tuple[str, str]:
    release_id = ""
    release_group_id = ""
    release_match = re.search(r"musicbrainz\.org/release/([0-9a-f-]{36})", url or "", re.I)
    group_match = re.search(r"musicbrainz\.org/release-group/([0-9a-f-]{36})", url or "", re.I)
    if release_match:
        release_id = release_match.group(1)
    if group_match:
        release_group_id = group_match.group(1)
    return release_id, release_group_id


def html_meta(html: str, name: str) -> str:
    patterns = [
        rf'<meta[^>]+(?:property|name)=["\']{re.escape(name)}["\'][^>]+content=["\']([^"\']+)',
        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']{re.escape(name)}["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, html, re.I)
        if match:
            return unescape(match.group(1)).strip()
    return ""


def json_ld_summary(html: str) -> dict[str, Any]:
    for raw in re.findall(r"<script[^>]+type=[\"']application/ld\+json[\"'][^>]*>(.*?)</script>", html, re.I | re.S):
        try:
            data = json.loads(unescape(raw.strip()))
        except json.JSONDecodeError:
            continue
        records = data if isinstance(data, list) else [data]
        for record in records:
            if not isinstance(record, dict):
                continue
            kind = record.get("@type")
            kinds = kind if isinstance(kind, list) else [kind]
            if not any(str(item) in {"MusicAlbum", "Album", "MusicRelease"} for item in kinds):
                continue
            artist = record.get("byArtist") or record.get("artist") or {}
            label = record.get("recordLabel") or record.get("publisher") or {}
            return {
                "title": first(record.get("name")),
                "artist": named_text(artist),
                "date": iso_date(record.get("datePublished") or record.get("releaseDate")),
                "label": first(label.get("name")) if isinstance(label, dict) else first(label),
                "track_count": record.get("numTracks") or 0,
                "image": first(record.get("image")) if isinstance(record.get("image"), str) else "",
            }
    return {}


def strip_html(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", unescape(text)).strip()


TITLE_SUFFIX_RE = re.compile(r"\s*[-–—]\s*(?:single|ep|album|mini[- ]album|maxi[- ]single|deluxe(?:\s+edition)?)\s*$", re.I)


def title_match_key(value: Any) -> str:
    """统一日文全/半角、大小写和常见标点，去掉 Apple 的 Single/EP 后缀。"""
    text = unicodedata.normalize("NFKC", first(value))
    text = TITLE_SUFFIX_RE.sub("", text).casefold()
    return re.sub(r"[\s\W_]+", "", text, flags=re.UNICODE)


def title_is_related(candidate_title: Any, query_title: str) -> bool:
    candidate = title_match_key(candidate_title)
    query = title_match_key(query_title)
    if not candidate or not query:
        return False
    if candidate == query or candidate in query or query in candidate:
        return True
    # 日文长标题经常夹带修饰语；允许共享连续两字以上的词片段，但不把完全无关结果放进来
    if len(query) >= 2 and any(query[i:i + 2] in candidate for i in range(len(query) - 1)):
        return True
    return False


def extract_date_text(value: str) -> str:
    match = re.search(r"\d{4}-\d{2}-\d{2}", value or "")
    return match.group(0) if match else ""


def parse_ototoy_html(html: str, url: str) -> dict[str, Any]:
    title_match = re.search(r'<h1[^>]+class=["\'][^"\']*album-title[^"\']*["\'][^>]*>(.*?)</h1>', html, re.I | re.S)
    artist_match = re.search(r'<p[^>]+class=["\'][^"\']*album-artist[^"\']*["\'][^>]*>(.*?)</p>', html, re.I | re.S)
    date_match = re.search(r'<p[^>]+class=["\'][^"\']*release-day[^"\']*["\'][^>]*>(.*?)</p>', html, re.I | re.S)
    label_match = re.search(r'<p[^>]+class=["\'][^"\']*label-name[^"\']*["\'][^>]*>(.*?)</p>', html, re.I | re.S)
    catalog_match = re.search(r'<p[^>]+class=["\'][^"\']*catalog-id[^"\']*["\'][^>]*>(.*?)</p>', html, re.I | re.S)
    runtime_match = re.search(r'<p[^>]+class=["\'][^"\']*total-duration[^"\']*["\'][^>]*>(.*?)</p>', html, re.I | re.S)
    image_matches = re.findall(r'<img[^>]+(?:src|data-src)=["\']([^"\']+)["\']', html, re.I)
    album_artist = strip_html(artist_match.group(1)) if artist_match else ""
    tracks: list[dict[str, Any]] = []
    table_match = re.search(r'<table[^>]+class=["\'][^"\']*tracklist[^"\']*["\'][^>]*>(.*?)</table>', html, re.I | re.S)
    if table_match:
        for row in re.findall(r'<tr[^>]*>(.*?)</tr>', table_match.group(1), re.I | re.S):
            number_match = re.search(r'<td[^>]+class=["\'][^"\']*\bnum\b[^"\']*["\'][^>]*>(.*?)</td>', row, re.I | re.S)
            title_match_row = re.search(r'<span[^>]+id=["\']title-[^"\']+["\'][^>]*>(.*?)</span>', row, re.I | re.S)
            duration_match = re.search(r'<td[^>]+class=["\'][^"\']*\bitem\b[^"\']*\bcenter\b[^"\']*["\'][^>]*>(\d{1,2}:\d{2})</td>', row, re.I | re.S)
            if not title_match_row:
                continue
            artists = [strip_html(item) for item in re.findall(r'<a[^>]+class=["\'][^"\']*\bartist\b[^"\']*["\'][^>]*>(.*?)</a>', row, re.I | re.S)]
            tracks.append({
                "number": strip_html(number_match.group(1)) if number_match else str(len(tracks) + 1),
                "title": strip_html(title_match_row.group(1)),
                "artist": " / ".join(artists) or album_artist,
                "length": duration_match.group(1) if duration_match else "",
                "recording_mbid": "",
                "source": "OTOTOY",
            })
    image = next((item for item in image_matches if "jacket" in item and "4168264" in item), "")
    return {
        "url": url,
        "status": "ok",
        "title": strip_html(title_match.group(1)) if title_match else "",
        "artist": strip_html(artist_match.group(1)) if artist_match else "",
        "date": extract_date_text(strip_html(date_match.group(1)) if date_match else ""),
        "label": strip_html(label_match.group(1)).removeprefix("Label:").strip() if label_match else "",
        "catalog_number": extract_catalog(html, url, strip_html(catalog_match.group(1)).removeprefix("Catalog number:").strip() if catalog_match else ""),
        "track_count": len(tracks),
        "tracks": tracks,
        "format": "Digital Media" if "Audio format" in html or "download" in html.lower() else "",
        "image": image,
        "description": html_meta(html, "description"),
        "source": "ototoy.jp",
    }


def parse_iso_duration(value: str) -> str:
    match = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?", value or "", re.I)
    if not match:
        return ""
    hours = int(match.group(1) or 0)
    minutes = int(match.group(2) or 0) + hours * 60
    seconds = int(match.group(3) or 0)
    return f"{minutes}:{seconds:02d}"


SPOTIFY_PROXY_BASE = "https://groover.co/core"
SPOTIFY_PROXY_HEADERS = {
    "Origin": "https://groover.co",
    "Referer": "https://groover.co/",
    "X-CSRFToken": "/za/warudo/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
}


def spotify_search(query: str, limit: int = 8, kind: str = "album") -> list[dict[str, Any]]:
    params = {"q": query, "limit": str(limit), "offset": "0", "full": "true", "type": kind}
    query_string = "&".join(f"{quote(key)}={quote(value)}" for key, value in params.items())
    data = fetch_json(f"{SPOTIFY_PROXY_BASE}/distantapi/spotify/search/?{query_string}", headers=SPOTIFY_PROXY_HEADERS)
    results = data.get("results") if isinstance(data, dict) else None
    return [item for item in (results or []) if isinstance(item, dict)]


def spotify_related_rows(term: str, title_hint: str, kind: str = "album", limits: tuple[int, ...] = (15, 14, 17)) -> list[dict[str, Any]]:
    """Groover 代理按「完整 URL（含 limit）」缓存，偶发返回上一次查询的结果；
    换一个 limit 就能拿到真实响应，因此命中不到相关标题时依次换 limit 重试。"""
    for limit in limits:
        try:
            found = spotify_search(term, limit=limit, kind=kind)
        except FetchError:
            continue
        rows = [item for item in found if first(item.get("id"))]
        related = [item for item in rows if not title_hint or title_is_related(item.get("name"), title_hint)]
        if related:
            return related
        if not rows:
            return []
        time.sleep(0.8)
    return []


def spotify_track(track_id: str) -> dict[str, Any]:
    data = post_json(f"{SPOTIFY_PROXY_BASE}/distantapi/spotify/getdata/", {"url": f"https://open.spotify.com/track/{track_id}"}, headers=SPOTIFY_PROXY_HEADERS)
    if not isinstance(data, dict) or not data.get("id"):
        return {}
    return {
        "id": first(data.get("id")),
        "title": first(data.get("name")),
        "artist": first(data.get("artist_name")),
        "album": first(data.get("album_name")),
        "date": iso_date(data.get("release_date")),
        "length": format_duration(data.get("duration_ms")),
        "url": first(data.get("external_url")) or f"https://open.spotify.com/track/{track_id}",
        "image": first(data.get("thumbnail")),
        "source": "Spotify 曲目",
    }


def spotify_album(album_id: str) -> dict[str, Any]:
    data = post_json(f"{SPOTIFY_PROXY_BASE}/distantapi/spotify/getdata/", {"url": f"https://open.spotify.com/album/{album_id}"}, headers=SPOTIFY_PROXY_HEADERS)
    if not isinstance(data, dict) or not data.get("id"):
        return {}
    tracks: list[dict[str, Any]] = []
    raw_tracks = data.get("tracks")
    items = raw_tracks.get("items") if isinstance(raw_tracks, dict) else raw_tracks
    for index, item in enumerate(items or [], 1):
        if not isinstance(item, dict):
            continue
        artists = [first(artist.get("name")) for artist in item.get("artists") or [] if isinstance(artist, dict)]
        tracks.append({
            "number": str(item.get("track_number") or index),
            "disc": str(item.get("disc_number") or ""),
            "title": first(item.get("name")),
            "artist": " / ".join(item for item in artists if item),
            "length": format_duration(item.get("duration_ms")),
            "isrc": item_isrc(item),
            "recording_mbid": "",
            "source": "Spotify",
        })
    images = data.get("images") or []
    copyrights = [first(item.get("text")) for item in data.get("copyrights") or [] if isinstance(item, dict)]
    return {
        "url": first((data.get("external_urls") or {}).get("spotify")),
        "status": "ok",
        "title": first(data.get("name")),
        "artist": " / ".join(first(artist.get("name")) for artist in data.get("artists") or [] if isinstance(artist, dict) and first(artist.get("name"))),
        "date": iso_date(data.get("release_date")),
        "label": clean_value(data.get("label")),
        "barcode": first((data.get("external_ids") or {}).get("upc")),
        "upc": first((data.get("external_ids") or {}).get("upc")),
        "copyrights": copyrights,
        "track_count": data.get("total_tracks") or len(tracks),
        "tracks": tracks,
        "image": first((images[0] or {}).get("url")) if images else "",
        "source": "Spotify",
    }


DEEZER_BASE = "https://api.deezer.com"
DEEZER_TYPE_MAP = {"album": "Album", "single": "Single", "ep": "EP", "compile": "Album", "bundle": "Album"}


def item_isrc(item: dict[str, Any]) -> str:
    external = item.get("external_ids")
    return first(external.get("isrc")) if isinstance(external, dict) else ""


def deezer_error(data: Any) -> str:
    """Deezer 失败时返回的是 **HTTP 200 + {"error": {...}}**，不是 4xx / 429。

    实测（2026-09-26）：
        /album/999999999999  -> HTTP 200 {"error":{"type":"DataException","message":"no data","code":800}}
        /album/999999999999/tracks -> 同上
        连续快速请求 60 次 -> 全部 HTTP 200，没有 429

    所以**任何只靠异常判断成败的地方都会静默拿到空数据** ——
    表现就是「曲目 / ISRC 莫名缺失，却一条报错都没有」，用户无从判断是这张碟本来就没有，
    还是接口出错了。凡是解析 Deezer 响应的地方都要先过这个函数。
    """
    if not isinstance(data, dict):
        return ""
    error = data.get("error")
    if not isinstance(error, dict):
        return ""
    message = first(error.get("message")) or first(error.get("type")) or "未知错误"
    code = error.get("code")
    return f"{message}（code {code}）" if code else message


def extract_deezer_id(url: str) -> str:
    match = re.search(r"deezer\.com/(?:[a-z-]{2,5}/)?album/(upc:)?(\d+)", url or "", re.I)
    if not match:
        return ""
    return f"upc:{match.group(2)}" if match.group(1) else match.group(2)


def deezer_cover_large(url: str) -> str:
    """Deezer 的 CDN 接受 1400×1400 变换，比 API 枚举的 cover_xl（1000×1000）大一圈。"""
    return re.sub(r"/\d+x\d+-\d+-\d+-\d+-\d+\.jpg$", "/1400x1400-000000-92-0-0.jpg", first(url)) or first(url)


def deezer_track_rows(album_id: str) -> list[dict[str, Any]]:
    """专辑对象里内嵌的曲目缺 ISRC / 碟号，要单独取 /album/{id}/tracks 才有。

    出错时抛 FetchError（带上 Deezer 的真实原因），由调用方决定保留多少已有数据 ——
    不能默默返回空列表，否则「没有 ISRC」和「接口挂了」在报告里长得一模一样。
    """
    rows: list[dict[str, Any]] = []
    url = f"{DEEZER_BASE}/album/{quote(album_id, safe=':')}/tracks?limit=100"
    pages = 0
    while url and len(rows) < 600 and pages < 20:
        pages += 1
        data = fetch_json(url)
        if not isinstance(data, dict):
            break
        problem = deezer_error(data)
        if problem:
            raise FetchError(f"Deezer 曲目列表读取失败：{problem}")
        for item in data.get("data") or []:
            if not isinstance(item, dict):
                continue
            duration = item.get("duration")
            rows.append({
                "number": str(item.get("track_position") or len(rows) + 1),
                "disc": str(item.get("disk_number") or 1),
                "vendor_id": str(item.get("id") or ""),
                "title": first(item.get("title")),
                "artist": first((item.get("artist") or {}).get("name")),
                "length": format_duration(int(duration) * 1000) if isinstance(duration, (int, float)) else "",
                "isrc": first(item.get("isrc")),
                "recording_mbid": "",
                "source": "Deezer",
            })
        next_url = first(data.get("next"))
        # 翻页指针没前进就停：避免「有 next 但 data 为空」时死循环
        url = next_url if next_url and next_url != url else ""
    return rows


def deezer_album(album_id: str) -> dict[str, Any]:
    """Deezer 公开 API 免鉴权，一次拿齐条码（UPC）、imprint（label）、发行类型、高清封面和逐轨 ISRC。"""
    data = fetch_json(f"{DEEZER_BASE}/album/{quote(album_id, safe=':')}")
    if not isinstance(data, dict) or deezer_error(data) or not data.get("id"):
        return {}
    # 曲目拉失败也要保住专辑级字段（条码 / 厂牌 / 发行类型仍然有用），只把原因带出去
    tracks: list[dict[str, Any]] = []
    tracks_error = ""
    try:
        tracks = deezer_track_rows(str(data.get("id")))
    except FetchError as exc:
        tracks_error = str(exc)
    record_type = first(data.get("record_type")).casefold()
    upc = clean_value(data.get("upc"))
    return {
        "url": first(data.get("link")) or f"https://www.deezer.com/album/{first(data.get('id'))}",
        "status": "ok",
        "title": first(data.get("title")),
        "artist": first((data.get("artist") or {}).get("name")),
        "contributors": [
            {"name": first(item.get("name")), "role": first(item.get("role"))}
            for item in data.get("contributors") or []
            if isinstance(item, dict)
        ],
        "date": iso_date(data.get("release_date")),
        "label": clean_value(data.get("label")),
        "record_type": record_type,
        "primary_type": DEEZER_TYPE_MAP.get(record_type, ""),
        "secondary_types": ["Compilation"] if record_type == "compile" else [],
        "genres": [first(item.get("name")) for item in ((data.get("genres") or {}).get("data") or []) if isinstance(item, dict)],
        "barcode": upc,
        "upc": upc,
        "track_count": data.get("nb_tracks") or len(tracks),
        "tracks": tracks,
        "tracks_error": tracks_error,
        "image": deezer_cover_large(first(data.get("cover_xl")) or first(data.get("cover_big"))),
        "source": "Deezer",
    }


def barcode_is_plausible(upc: str) -> bool:
    """排除「查得到、但一定是错的」条码。

    实测（2026-09-26）：`/album/upc:000000000000` 会返回一张真实却完全无关的专辑
    （Moral Groove）。而全 0、全 9 这类值正是 MusicBrainz / 发行页面标记「没有条码」
    时最常用的占位写法 —— 一旦反查命中，就会把**无关专辑的条码、厂牌、逐轨 ISRC**
    灌进报告。这比查不到更糟：报告看着完整，数据却是错的。
    """
    code = re.sub(r"\D", "", first(upc))
    if len(code) < 12:
        return False
    return len(set(code)) > 1


def deezer_album_matches(album: dict[str, Any], album_name: str, artist_name: str) -> bool:
    """反查到的 Deezer 专辑是否就是我们要的那张。

    标题对不上直接否掉；艺人名对不上时，只接受标题**完全一致**的结果 —— 跨区罗马字
    差异很常见（`田馥甄` / `Hebe Tien`），不该仅凭艺人名就误杀，但也不能靠模糊匹配放行。
    """
    got_title = first(album.get("title"))
    got_artist = first(album.get("artist"))
    if album_name and not title_is_related(got_title, album_name):
        return False
    if artist_name and got_artist:
        wanted = artist_name.casefold().replace(" ", "")
        got = got_artist.casefold().replace(" ", "")
        if wanted not in got and got not in wanted:
            return title_match_key(got_title) == title_match_key(album_name)
    return True


def deezer_album_by_upc(upc: str, album_name: str = "", artist_name: str = "") -> dict[str, Any]:
    """/album/upc:{UPC} 是 Deezer 的条码反查入口：只有 Apple / Spotify 链接时用它补齐 ISRC、imprint 和发行类型。

    这个入口对不合理的条码也会返回结果，所以入参和出参都要校验（见 barcode_is_plausible
    与 deezer_album_matches）—— 反查错了会把无关专辑的资料混进报告。
    """
    code = re.sub(r"\D", "", first(upc))
    if not barcode_is_plausible(code):
        return {}
    album = deezer_album(f"upc:{code}")
    if album and not deezer_album_matches(album, album_name, artist_name):
        return {}
    return album


def discover_platform_links(
    artist: str,
    title: str,
    upc: str = "",
    skip_sites: set[str] | None = None,
    warnings: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    """MusicBrainz 和输入页面都没给链接时，用免鉴权的公开检索 API 直接定位专辑页（Apple 按条码、Deezer 按标题）。

    MusicBrainz 里的发行录了 External links 就轮不到这里；这些链接是「候选」，来源标注里会写清楚需人工核对。
    """
    found: list[dict[str, str]] = []
    skip = {site.casefold() for site in (skip_sites or set())}
    if upc and "apple music" not in skip:
        try:
            data = fetch_json(f"https://itunes.apple.com/lookup?upc={quote(upc)}&entity=album")
        except FetchError as exc:
            data = {}
            if warnings is not None:
                warnings.append({"source": "External links", "warning": f"按条码 {upc} 自动检索 Apple Music 链接失败：{exc}"})
        for item in data.get("results") or []:
            if isinstance(item, dict) and item.get("wrapperType") == "collection" and first(item.get("collectionViewUrl")):
                found.append({"url": normalize_mb_url(urljoin("https://music.apple.com", first(item.get("collectionViewUrl")))), "source": f"自动发现：iTunes 按条码 {upc}（需核对）"})
                break
    # Deezer 的 album: 结构化查询不可用，用文本检索再按标题 + 艺人筛，避免拿到同名错项
    term = search_query_text(" ".join(item for item in [artist, title] if item))
    if term and artist.strip() and title.strip() and "deezer" not in skip:
        try:
            data = fetch_json(f"{DEEZER_BASE}/search/album?q={quote(term)}&limit=5")
        except FetchError as exc:
            data = {}
            if warnings is not None:
                warnings.append({"source": "External links", "warning": f"Deezer 标题检索失败，未能自动发现 Deezer 链接：{exc}"})
        # Deezer 的失败是「200 + error 体」，不检查的话会静默当成「没有匹配结果」
        problem = deezer_error(data)
        if problem and warnings is not None:
            warnings.append({"source": "External links", "warning": f"Deezer 标题检索未返回结果（{problem}），未能自动发现 Deezer 链接"})
        row = next(
            (
                item for item in data.get("data") or []
                if isinstance(item, dict)
                and first(item.get("link"))
                and title_is_related(item.get("title"), title)
                and artist.casefold().replace(" ", "") in first((item.get("artist") or {}).get("name")).casefold().replace(" ", "")
            ),
            {},
        )
        if row:
            found.append({"url": first(row.get("link")), "source": "自动发现：Deezer 标题检索（需核对）"})
    return found


URL_SITE_RULES: list[tuple[str, str, str]] = [
    (r"(?:open|play)\.spotify\.com|spotify\.com", "Spotify", "streaming"),
    (r"music\.apple\.com|itunes\.apple\.com|geo\.music\.apple\.com", "Apple Music", "purchase for download"),
    (r"deezer\.com", "Deezer", "free streaming"),
    (r"tidal\.com", "TIDAL", "streaming"),
    (r"qobuz\.com", "Qobuz", "purchase for download"),
    (r"ototoy\.jp", "OTOTOY", "purchase for download"),
    (r"mora\.jp", "mora", "purchase for download"),
    (r"bandcamp\.com", "Bandcamp", "purchase for download"),
    (r"music\.youtube\.com", "YouTube Music", "streaming"),
    (r"youtube\.com|youtu\.be", "YouTube", "streaming"),
    (r"soundcloud\.com", "SoundCloud", "streaming"),
    (r"music\.amazon\.|amazon\.(?:co\.jp|com|co\.uk|de|fr|it|es|ca|com\.au)", "Amazon", "purchase for download"),
    (r"anghami\.com", "Anghami", "streaming"),
    (r"line\.me", "LINE MUSIC", "streaming"),
    (r"recochoku\.jp", "recochoku", "purchase for download"),
    (r"kkbox\.com", "KKBOX", "streaming"),
    (r"joox\.com", "JOOX", "streaming"),
    (r"awa\.fm", "AWA", "streaming"),
    (r"music\.jp", "music.jp", "purchase for download"),
    (r"7digital\.com", "7digital", "purchase for download"),
    (r"napster\.com", "Napster", "streaming"),
    (r"pandora\.com", "Pandora", "streaming"),
    (r"iheart\.com", "iHeartRadio", "streaming"),
    (r"yandex\.", "Yandex Music", "streaming"),
    (r"music\.163\.com|163cn\.tv|y\.music\.163\.com", "NetEase Cloud Music", "streaming"),
    (r"y\.qq\.com|c\.y\.qq\.com|i\.y\.qq\.com", "QQ Music", "streaming"),
    (r"kuwo\.cn", "Kuwo", "streaming"),
    (r"migu\.cn", "Migu Music", "streaming"),
    (r"bilibili\.com", "bilibili", "streaming"),
    (r"discogs\.com", "Discogs", "other databases"),
    (r"vgmdb\.net", "VGMdb", "other databases"),
    (r"genius\.com", "Genius", "lyrics"),
    (r"utaten\.com", "UtaTen", "lyrics"),
    (r"uta-net\.com", "uta-net", "lyrics"),
    (r"j-lyric\.net", "J-Lyric.net", "lyrics"),
    (r"joysound\.com", "JOYSOUND", "lyrics"),
    (r"petitlyrics\.com", "プチリリ", "lyrics"),
    (r"kashinavi\.com", "歌詞ナビ", "lyrics"),
]


# 规则表里的 pattern 是**后缀式**写法，但匹配必须落在域名标签边界上。
# 原来直接 re.search(pattern, host) 是纯子串匹配，实测：
#     notspotify.com       含 spotify.com → 命中 Spotify
#     deezer.com.evil.io   含 deezer.com  → 命中 Deezer（攻击者完全控制该域名，
#                                          再配一条 302 就凑成完整的 SSRF 链）
#     music.jp.attacker.dev 含 music.jp   → 命中
# 主机这道闸被这样一蹭就没了，报告里还会把攻击者域名标成「Spotify」，
# 关系类型会被照抄进 MusicBrainz。
#
# 规则里 music\.amazon\. / yandex\. 是「前缀式」写法（本意是 music.amazon.<某 TLD>），
# 它们只吃掉域名前半段，所以剩下的部分必须真的像一段域名尾巴：
# 一级 TLD（com / de / …）或 co.jp / com.au 这类二段后缀。
# 不这么卡的话，music.amazon.co.evil、yandex.evil.com 照样能蹭进来。
PUBLIC_SUFFIX_TAIL_RE = re.compile(r"^(?:[a-z]{2,6}|(?:co|com|net|org|gov|edu)\.[a-z]{2})$", re.I)


def host_matches_site_rule(pattern: str, host: str) -> bool:
    """命中必须「起点在开头或紧跟一个点，终点在结尾」——即真正以该域名结尾。"""
    for match in re.finditer(pattern, host, re.I):
        start, end = match.span()
        if start and host[start - 1] != ".":
            continue
        if end == len(host):
            return True
        if match.group(0).endswith(".") and PUBLIC_SUFFIX_TAIL_RE.match(host[end:]):
            return True
    return False


def site_info(url: str) -> tuple[str, str]:
    # 用 hostname 而不是 netloc：带端口（www.deezer.com:443）或 userinfo 时
    # netloc 不是纯域名，后缀匹配会整个落空
    host = (urlparse(url or "").hostname or "").lower()
    for pattern, name, relationship in URL_SITE_RULES:
        if host_matches_site_rule(pattern, host):
            return name, relationship
    return "", ""


PLATFORM_SEARCH_URLS: list[tuple[str, str]] = [
    ("Apple Music", "https://music.apple.com/search?term={query}"),
    ("Spotify", "https://open.spotify.com/search/{query}"),
    # Deezer 的搜索页路径形式才是对的：/search/{q} 可用，/search?q= 会 404。
    # 注意它的 Edgecast WAF 会**间歇性**返回 Access Denied（连续访问后触发，过一阵自己恢复），
    # 所以这个链接偶尔会看到报错页 —— 不是地址写错了，刷新或稍后再试即可。
    ("Deezer", "https://www.deezer.com/search/{query}"),
    # Qobuz 的 /search?q= 已废弃（直接 404），现行入口带区域前缀 /us-en/
    ("Qobuz", "https://www.qobuz.com/us-en/search?q={query}"),
    ("TIDAL", "https://tidal.com/search?q={query}"),
    ("YouTube Music", "https://music.youtube.com/search?q={query}"),
    ("Amazon Music", "https://music.amazon.com/search/{query}"),
    ("Bandcamp", "https://bandcamp.com/search?q={query}"),
    ("OTOTOY", "https://ototoy.jp/find/?q={query}"),
    ("mora", "https://mora.jp/search/top?keyWord={query}"),
    ("recochoku", "https://recochoku.jp/search/?keyword={query}"),
    # KKBOX 整站（首页 / 排行榜 / 搜索）都挂在人机校验后面，搜索页地址本身是对的；
    # 换 URL 解决不了，只能等它放行或人工过关。
    ("KKBOX", "https://www.kkbox.com/tw/tc/search?q={query}"),
    ("NetEase Cloud Music", "https://music.163.com/#/search/m/?s={query}"),
    ("QQ Music", "https://y.qq.com/n/ryqq/search?w={query}"),
]

# 会被自家 WAF 拦（可能要求人机校验 / 间歇性 Access Denied）的站点，界面上要提醒一句，
# 免得点开看到报错页以为是链接写错了
WAF_FLAKY_SITES = {"Deezer", "KKBOX"}


def extract_apple_country(url: str) -> str:
    match = re.search(r"music\.apple\.com/([a-z]{2})(?:/|$)", url or "", re.I)
    return match.group(1).lower() if match else ""


def apple_storefront_chain(preferred: str) -> list[str]:
    """按优先级给出要尝试的商店区域：先用链接自带的区，再用常见区兜底。

    两边都不能只靠一个：
      - 链接里的 /cn/ 只代表网页语言，这张专辑未必在 CN 区上架（CN 区常常只有专辑壳、
        没有曲目数据）；
      - 省略 country 时接口一律按**美区**返回，中文专辑的艺人名会变成「Hebe Tien」这种罗马字，
        和页面抓到的「田馥甄」对不上，接着会被下面的艺人校验判定为不匹配而整份丢弃。

    JP 区是否优先不在这里决定 —— 由 itunes_album_by_id 按「JP 区艺人名与输入艺人是否一致」
    在收尾时决定整单切换，避免欧美歌手的链接被日文片假名污染。
    """
    chain: list[str] = []
    for code in [preferred, "jp", "us", ""]:
        code = (code or "").lower()
        if code not in chain:
            chain.append(code)
    return chain


def itunes_album_by_id(apple_id: str, preferred_country: str = "", artist_hint: str = "") -> dict[str, Any]:
    """按区依次查同一张专辑。

    区域选择的原则：**数据完整优先，且整单切换只给「艺人名对得上」的区** ——
      - 链接自带的区有完整曲目就用它（链接区只是个候选，不是唯一答案）；
      - 链接区缺曲目表时，若 JP 区有完整数据且艺人名与输入一致（日音/JP 规范名），
        整单改用 JP 区 —— 艺人写法、厂牌、区域、曲目表都跟 JP 区走；
      - JP 区艺人名对不上（如欧美歌手的日文片假名「テイラー・スウィフト」）时，
        整单改用其他艺人名匹配且有完整数据的区，避免被日文名污染；
      - 实在没有艺人名匹配的完整区，才退回「保留主来源字段 + 借用曲目表」的兜底。

    这样「粘贴 /cn/ 的链接」：日音专辑整单按 JP 区；欧美专辑不会因 JP 区日文名与
    页面不符而被艺人校验整份丢弃。
    返回 {data, country, tracks_from, note}；完全查不到时 data 为 {}。
    """
    wanted = artist_hint.strip().casefold().replace(" ", "")
    primary: dict[str, Any] = {}
    primary_country = ""
    primary_artist_ok = False
    jp_data: dict[str, Any] = {}
    matched_donor: dict[str, Any] = {}
    matched_donor_country = ""
    donor_data: dict[str, Any] = {}
    donor_tracks: list[dict[str, Any]] = []
    donor_country = ""
    # 链接自带区的状态：用于 note 准确说明「为什么不用链接区」（未查到 / 缺曲目 / 名字不符）
    preferred_found = False
    preferred_tracks = False
    preferred_artist_ok = False

    for code in apple_storefront_chain(preferred_country):
        suffix = f"&country={code}" if code else ""
        try:
            data = normalize_itunes(fetch_json(f"https://itunes.apple.com/lookup?id={quote(apple_id)}&entity=song{suffix}"))
        except FetchError:
            continue
        if not first(data.get("title")):
            continue
        if code == "jp" and not jp_data:
            jp_data = data
        got = first(data.get("artist")).casefold().replace(" ", "")
        artist_ok = bool(wanted) and got == wanted
        tracks = data.get("tracks") or []
        if code == preferred_country.lower():
            preferred_found = True
            if tracks:
                preferred_tracks = True
            if artist_ok:
                preferred_artist_ok = True

        # 取第一个有结果的区作主来源；若它艺人名对不上，而后面某个区对得上，则改用它。
        if not primary:
            primary, primary_country, primary_artist_ok = data, code, artist_ok
        elif not primary_artist_ok and artist_ok:
            primary, primary_country, primary_artist_ok = data, code, artist_ok

        if tracks and not donor_tracks:
            donor_data, donor_tracks, donor_country = data, tracks, code
        if tracks and artist_ok and not matched_donor:
            matched_donor, matched_donor_country = data, code

        # 主来源区艺人名对得上且自带完整曲目，就没有再试别的区的必要
        # （只借曲目表不算数：链接区缺曲目时，后面可能还有艺人名匹配的完整区，值得继续试）
        if primary_artist_ok and primary.get("tracks"):
            break

    if not primary:
        return {"data": {}, "country": "", "tracks_from": "", "note": ""}

    note = ""
    # 链接区问题描述：区分「未查到 / 缺曲目 / 名字不符」，别把所有情况都笼统说成数据不全
    preferred_label = f"链接所在 {preferred_country.upper() or '默认'} 区"
    if not preferred_found:
        preferred_issue = f"{preferred_label}未查到该专辑"
    elif not preferred_tracks:
        preferred_issue = f"{preferred_label}数据不全（缺曲目表）"
    elif not preferred_artist_ok:
        preferred_issue = f"{preferred_label}艺人名与输入不符"
    else:
        preferred_issue = preferred_label

    # 1) 主来源区自带完整曲目：直接用，不折腾（若主来源已因艺人名匹配切到别的区，说明链接区不理想）
    if primary.get("tracks"):
        if preferred_country and primary_country != preferred_country.lower():
            note = f"{preferred_issue}，已改用 {primary_country.upper()} 区完整数据"
        return {"data": primary, "country": primary_country, "tracks_from": primary_country, "note": note}

    # 2) 链接区缺曲目：JP 区有完整数据且艺人名与输入一致（日音/JP 规范名）→ 整单改用 JP 区
    if jp_data and jp_data.get("tracks"):
        jp_artist = first(jp_data.get("artist")).casefold().replace(" ", "")
        if not wanted or jp_artist == wanted:
            primary, primary_country = jp_data, "jp"
            note = (f"{preferred_issue}，"
                    f"已按日本区数据整单查询（艺人、厂牌、区域、曲目表均按 JP 区）")
            return {"data": primary, "country": primary_country, "tracks_from": "jp", "note": note}

    # 3) 艺人名匹配的其他完整区 → 整单切换（不会因名字与页面不符被外部校验丢弃）
    if matched_donor and matched_donor.get("tracks") and matched_donor_country != primary_country:
        deficient = primary_country
        primary, primary_country = matched_donor, matched_donor_country
        note = (f"{deficient.upper() or '默认'} 区数据不全（缺曲目表），"
                f"已整单改用 {matched_donor_country.upper()} 区——艺人、厂牌、区域、曲目表均按 {matched_donor_country.upper()} 区")
        return {"data": primary, "country": primary_country, "tracks_from": matched_donor_country, "note": note}

    # 4) 兜底：没有艺人名匹配的完整区，保留主来源字段，只借用有曲目的区的曲目表
    if donor_tracks and donor_country != primary_country:
        note = (f"{primary_country.upper() or '默认'} 区数据不全，没有艺人名匹配的完整区，"
                f"曲目表借用 {donor_country.upper()} 区")
    if donor_tracks:
        primary["tracks"] = donor_tracks
        primary["track_count"] = len(donor_tracks)
    return {"data": primary, "country": primary_country, "tracks_from": donor_country, "note": note}


def platform_search_links(query: str, existing: list[dict[str, str]]) -> list[dict[str, str]]:
    if not query:
        return []
    present = {first(item.get("site")).casefold() for item in existing}
    links: list[dict[str, str]] = []
    for site, template in PLATFORM_SEARCH_URLS:
        if site.casefold() in present:
            continue
        links.append({"name": site, "url": template.format(query=quote(search_query_text(query)))})
    return links


def platform_search_notes(links: list[dict[str, str]]) -> list[str]:
    """给会被 WAF 拦的站点补一句说明，避免点开看到 Access Denied 以为是链接错了。"""
    return [item["name"] for item in links if item.get("name") in WAF_FLAKY_SITES]


def build_external_links(source_urls: list[str], mb_data: dict[str, Any], spotify_data: dict[str, Any], deezer_data: dict[str, Any] | None = None, discovered: list[dict[str, str]] | None = None) -> list[dict[str, str]]:
    links: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(url: str, source: str, relationship: str = "") -> None:
        url = first(url).strip()
        if not url:
            return
        key = normalize_mb_url(url).casefold() or url.casefold()
        if key in seen:
            if relationship and source == "MusicBrainz":
                for item in links:
                    if (normalize_mb_url(item["url"]).casefold() or item["url"].casefold()) == key and not item.get("relationship"):
                        item["relationship"] = relationship
            return
        seen.add(key)
        site, guessed = site_info(url)
        links.append({
            "url": url,
            "site": site or urlparse(url).netloc,
            "relationship": relationship or guessed or "streaming",
            "source": source,
        })

    for relation in mb_data.get("external_urls") or []:
        add(relation.get("url", ""), "MusicBrainz", first(relation.get("type")))
    for url in source_urls:
        add(url, "输入链接")
    if first(spotify_data.get("url")):
        add(spotify_data["url"], "Spotify")
    if first((deezer_data or {}).get("url")):
        add(deezer_data["url"], "Deezer")
    # 自动发现的链接只在前面这些来源完全没提供该平台时才补
    present = {site_info(item["url"])[0] or urlparse(item["url"]).netloc for item in links}
    for item in discovered or []:
        site, _ = site_info(item.get("url", ""))
        if site and site in present:
            continue
        add(item.get("url", ""), item.get("source", "自动发现"))
    return links


def add_derived_external_links(links: list[dict[str, str]], apple_id: str, apple_country: str, source_urls: list[str], apple_url: str = "") -> list[dict[str, str]]:
    if not apple_id and not apple_url:
        return links
    existing = {normalize_mb_url(item.get("url", "")).casefold() for item in links}
    for url in source_urls:
        if apple_id and apple_id in url and normalize_mb_url(url).casefold() in existing:
            return links
    if apple_url and "music.apple.com" in apple_url and normalize_mb_url(apple_url).casefold() not in existing:
        links.append({"url": apple_url, "site": "Apple Music", "relationship": "purchase for download", "source": "Apple/iTunes 查询结果"})
        return links
    if not apple_id:
        return links
    country = apple_country or "us"
    derived = f"https://music.apple.com/{country}/album/{apple_id}"
    if normalize_mb_url(derived).casefold() in existing:
        return links
    links.append({"url": derived, "site": "Apple Music", "relationship": "purchase for download", "source": "按专辑 ID 生成"})
    return links


def imprint_from_copyright(text: str) -> str:
    # Apple 的 ℗ 行常写成「A Virgin Music release; ℗ 2026 UNIVERSAL MUSIC LLC」，其中前半段就是厂牌
    match = re.match(r"\s*A\s+(.+?)\s+release\b", first(text), re.I)
    if match:
        candidate = match.group(1).strip(" 　,;")
        return candidate if 1 < len(candidate) < 60 else ""
    return ""


def search_query_text(text: str) -> str:
    # 只清掉会破坏查询或被 WAF 拦的符号，保留撇号/连字符等艺人名常见字符
    cleaned = re.sub(r'[?!*#&%+=<>()\[\]{}|\\/^~`"]', " ", text or "")
    return re.sub(r"\s+", " ", cleaned).strip()


def catalog_from_url(url: str) -> str:
    parsed = urlparse(url or "")
    segments = [segment for segment in parsed.path.split("/") if segment]
    host = parsed.netloc.lower()
    # mora 的专辑地址固定是 /package/<label_id>/<品番>/，品番允许是纯数字（如 Universal 的 UPC）
    if "mora.jp" in host:
        for index, segment in enumerate(segments):
            if segment.lower() == "package" and index + 2 < len(segments):
                candidate = unescape(segments[index + 2]).strip()
                if candidate and candidate.lower() != "package":
                    return candidate
    for segment in reversed(segments):
        candidate = unescape(segment).strip()
        if re.fullmatch(r"[A-Za-z]{2,6}[-_]?\d{4,8}(?:[A-Za-z0-9]{1,4})?", candidate) and len(candidate) >= 7:
            return candidate
        if re.fullmatch(r"\d{12,14}", candidate) and re.search(r"mora\.jp|ototoy\.jp|bandcamp\.com|qobuz\.com|tidal\.com|deezer\.com", host):
            return candidate
    return ""


def extract_catalog(html: str, url: str, parsed_value: str = "") -> str:
    if parsed_value:
        return parsed_value
    from_url = catalog_from_url(url)
    if from_url:
        return from_url
    for pattern in (r'Catalog number[:：]\s*([A-Za-z0-9\-_]{6,24})', r'品番[:：]\s*([A-Za-z0-9\-_]{6,24})', r'"catalog[_ ]?number"\s*[:=]\s*["\']([A-Za-z0-9\-_]{6,24})', r'catalogNumber["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_]{6,24})'):
        match = re.search(pattern, html or "", re.I)
        if match:
            return match.group(1).strip()
    return ""


def parse_bandcamp_html(html: str, url: str) -> dict[str, Any]:
    title = html_meta(html, "og:title") or html_meta(html, "twitter:title")
    if title:
        title = re.sub(r"\s*\|\s*Bandcamp$", "", title).strip()
    image = html_meta(html, "og:image")
    description = html_meta(html, "og:description") or html_meta(html, "description")
    return {
        "url": url,
        "status": "ok",
        "title": title,
        "artist": "",
        "date": "",
        "label": "",
        "catalog_number": extract_catalog(html, url),
        "track_count": 0,
        "tracks": [],
        "image": image,
        "description": description,
        "source": urlparse(url).netloc,
    }


def parse_mora_html(html: str, url: str) -> dict[str, Any]:
    structured = json_ld_summary(html)
    title = structured.get("title") or html_meta(html, "og:title") or html_meta(html, "twitter:title")
    image = structured.get("image") or html_meta(html, "og:image")
    return {
        "url": url,
        "status": "ok",
        "title": title,
        "artist": structured.get("artist", ""),
        "date": structured.get("date", ""),
        "label": structured.get("label", ""),
        "catalog_number": extract_catalog(html, url),
        "track_count": structured.get("track_count", 0),
        "tracks": [],
        "image": image,
        "description": html_meta(html, "description"),
        "source": "mora.jp",
    }


def parse_apple_html(html: str, url: str) -> dict[str, Any]:
    structured = json_ld_summary(html)
    records: list[dict[str, Any]] = []
    for raw in re.findall(r"<script[^>]+type=[\"']application/ld\+json[\"'][^>]*>(.*?)</script>", html, re.I | re.S):
        try:
            data = json.loads(unescape(raw.strip()))
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and data.get("@type") == "MusicAlbum":
            records.append(data)
    album = records[0] if records else {}
    tracks: list[dict[str, Any]] = []
    for index, item in enumerate(album.get("tracks") or [], 1):
        if not isinstance(item, dict):
            continue
        tracks.append({
            "number": str(index),
            "title": first(item.get("name")),
            "artist": named_text(item.get("byArtist")) or first(structured.get("artist")),
            "length": parse_iso_duration(first(item.get("duration"))),
            "recording_mbid": "",
            "source": "Apple Music page",
        })
    image = first(album.get("image"))
    if image:
        image = re.sub(r"/\d+x\d+bb\.(jpg|jpeg|png)$", r"/4000x4000-999.\1", image, flags=re.I)
    return {
        "url": url,
        "status": "ok",
        "title": first(album.get("name")) or first(structured.get("title")),
        "artist": named_text(album.get("byArtist")) or first(structured.get("artist")),
        "date": iso_date(album.get("datePublished")),
        "label": "",
        "catalog_number": extract_catalog(html, url),
        "track_count": len(tracks),
        "tracks": tracks,
        "image": image,
        "description": first(album.get("description")),
        "source": "music.apple.com",
    }


def source_page_summary(url: str) -> dict[str, Any]:
    if not url or "musicbrainz.org" in url or "open.spotify.com" in url:
        return {}
    # Deezer 的专辑页是 JS 渲染的壳，数据统一走 Deezer API
    if "deezer.com" in urlparse(url).netloc.lower() and extract_deezer_id(url):
        return {}
    try:
        html = fetch_text(url)
    except FetchError as exc:
        return {"url": url, "status": "unavailable", "error": str(exc), "source": urlparse(url).netloc}
    domain = urlparse(url).netloc.lower()
    if "music.apple.com" in domain:
        return parse_apple_html(html, url)
    if "ototoy.jp" in domain and "tracklist" in html:
        return parse_ototoy_html(html, url)
    if "mora.jp" in domain:
        return parse_mora_html(html, url)
    if "bandcamp.com" in domain:
        return parse_bandcamp_html(html, url)
    structured = json_ld_summary(html)
    title = structured.get("title") or html_meta(html, "og:title") or html_meta(html, "twitter:title")
    image = structured.get("image") or html_meta(html, "og:image")
    description = html_meta(html, "og:description") or html_meta(html, "description")
    return {
        "url": url,
        "status": "ok",
        "title": title,
        "artist": structured.get("artist", ""),
        "date": structured.get("date", ""),
        "label": structured.get("label", ""),
        "catalog_number": extract_catalog(html, url),
        "track_count": structured.get("track_count", 0),
        "tracks": [],
        "image": image,
        "description": description,
        "source": urlparse(url).netloc,
    }


def mb_request(path: str, params: dict[str, str]) -> Any:
    """MusicBrainz 要求每秒最多 1 个请求（每个应用、每个 IP）。

    限速只约束**真正打到 MusicBrainz 的请求**：命中本地缓存时直接返回，既不睡、
    也不更新 MB_LAST_REQUEST。否则重复查询会被一串无谓的 sleep 拖慢十几秒 ——
    一次查询有十来个 MB 调用，纯等待就超过 10 秒。

    限速本身必须整段上锁：全局时间戳无锁时，两个并发查询会同时读到旧值、
    都判定「离上次请求已经超过 1 秒」、于是一起打过去 —— 净结果是违反 MB
    每秒 1 次的约束，然后被 503 打回来并记进 source_errors（见 api_notes）。
    """
    global MB_LAST_REQUEST
    query = "&".join(f"{quote(key)}={quote(value)}" for key, value in params.items())
    url = f"{MB_BASE}/{path}?{query}"
    key = cache_key("GET", ascii_url(url))
    cached = cache_load(key)
    if cached is not None:
        CACHE_STATS.hit += 1
        return cached
    with MB_LOCK:
        cached = cache_load(key)  # 等锁期间别的线程可能已经拿到并写好了，别再白等 1 秒
        if cached is not None:
            CACHE_STATS.hit += 1
            return cached
        elapsed = time.monotonic() - MB_LAST_REQUEST
        if elapsed < 1.05:
            time.sleep(1.05 - elapsed)
        result = fetch_json(url, headers={"Accept": "application/json"})
        MB_LAST_REQUEST = time.monotonic()
    return result


def artist_name(credit: dict[str, Any]) -> str:
    artist = credit.get("artist") or {}
    return first(credit.get("name")) or first(artist.get("name"))


def mb_artist_credit(credits: list[dict[str, Any]] | None) -> str:
    if not credits:
        return ""
    result = ""
    for credit in credits:
        result += artist_name(credit)
        result += first(credit.get("joinphrase"))
    return result


def is_valid_ean(code: str) -> bool:
    if not code.isdigit() or len(code) not in (8, 12, 13):
        return False
    digits = [int(char) for char in code]
    body, check = digits[:-1], digits[-1]
    # EAN-13 and EAN-8 start with weight 1; UPC-A starts with weight 3.
    weights = [1, 3] * 6 if len(code) == 13 else ([3, 1] * 6 if len(code) == 12 else [3, 1, 3, 1, 3, 1, 3])
    total = sum(digit * weight for digit, weight in zip(body, weights))
    return (10 - total % 10) % 10 == check


def barcode_from_artwork(url: str) -> str:
    segments = [segment for segment in urlparse(url or "").path.split("/") if segment]
    for segment in reversed(segments):
        candidate = re.sub(r"\.(jpe?g|png|gif|webp)$", "", segment, flags=re.I).split(".")[0]
        if is_valid_ean(candidate):
            return candidate
    return ""


def normalize_mb_url(url: str) -> str:
    parsed = urlparse(url or "")
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}{path}" if parsed.scheme and parsed.netloc else ""


def mb_reverse_release_ids(url: str) -> list[str]:
    candidates: list[str] = []
    for candidate in (url.strip(), normalize_mb_url(url)):
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    release_ids: list[str] = []
    for candidate in candidates:
        try:
            data = mb_request("url", {"resource": candidate, "inc": "release-rels", "fmt": "json"})
        except FetchError:
            continue
        for relation in data.get("relations") or []:
            release = relation.get("release") or {}
            release_id = first(release.get("id"))
            if release_id and release_id not in release_ids:
                release_ids.append(release_id)
    return release_ids


def mb_search_artist(item: dict[str, Any]) -> str:
    return first(item.get("artist-credit-phrase")) or mb_artist_credit(item.get("artist-credit"))


def single_credit_mbid(credits: list[dict[str, Any]] | None) -> str:
    """只有单一艺人的 credit 才敢直接给 MBID；多艺人（& / feat. / vs.）交给人工拆分。"""
    items = [credit for credit in credits or [] if first((credit.get("artist") or {}).get("id"))]
    if len(items) != 1 or first(items[0].get("joinphrase")):
        return ""
    return first((items[0].get("artist") or {}).get("id"))


MULTI_CREDIT_RE = re.compile(r"\s(?:&|and|feat\.?|featuring|with|vs\.?|×|/)\s", flags=re.I)


def multi_credit_name(name: str) -> bool:
    return bool(MULTI_CREDIT_RE.search(first(name)))


def mb_release_events(release: dict[str, Any]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for event in release.get("release-events") or []:
        area = event.get("area") or {}
        codes = area.get("iso-3166-1-codes") or []
        items.append({
            "code": first(codes[0]) if codes else "",
            "name": first(area.get("name")),
            "date": iso_date(event.get("date")),
        })
    return items


def mb_tracks(release: dict[str, Any]) -> list[dict[str, Any]]:
    tracks: list[dict[str, Any]] = []
    for media in release.get("media") or []:
        for item in media.get("tracks") or []:
            tracks.append({
                "number": first(item.get("number")),
                "disc": str(media.get("position") or ""),
                "title": first(item.get("title")),
                "artist": mb_artist_credit(item.get("artist-credit")) or mb_artist_credit(release.get("artist-credit")),
                "artist_mbid": single_credit_mbid(item.get("artist-credit")),
                "length": format_duration(item.get("length")),
                "recording_mbid": first((item.get("recording") or {}).get("id")),
                "source": "MusicBrainz",
            })
    return tracks


def mb_release_sites(release_id: str) -> list[str]:
    """这条发行已经挂了哪些平台的链接（只看站点名，用来算「还缺什么」）。"""
    try:
        data = mb_request(f"release/{release_id}", {"inc": "url-rels", "fmt": "json"})
    except FetchError:
        return []
    sites: set[str] = set()
    for relation in data.get("relations") or []:
        site, _ = site_info(first((relation.get("url") or {}).get("resource")))
        if site:
            sites.add(site)
    return sorted(sites)


def mb_duplicate_releases(barcode: str, known_release_id: str = "", max_candidates: int = 2) -> list[dict[str, Any]]:
    """按条码在 MusicBrainz 里找已存在的发行：命中就说明这张已经被建过，别重复建。"""
    code = re.sub(r"\D", "", first(barcode))
    if len(code) < 12:
        return []
    try:
        found = mb_request("release", {"query": f"barcode:{code}", "limit": str(max_candidates + 1), "fmt": "json"})
    except FetchError:
        return []
    duplicates: list[dict[str, Any]] = []
    for item in (found.get("releases") or [])[:max_candidates]:
        release_id = first(item.get("id"))
        if not release_id or release_id == known_release_id:
            continue
        duplicates.append({
            "release_mbid": release_id,
            "title": clean_value(item.get("title")),
            "artist": mb_search_artist(item),
            "date": iso_date(item.get("date")),
            "country": first(item.get("country")),
            "track_count": item.get("track-count") or 0,
            "release_group_mbid": first((item.get("release-group") or {}).get("id")),
            "linked_sites": mb_release_sites(release_id),
            "url": f"https://musicbrainz.org/release/{release_id}",
        })
    return duplicates


def mb_query_escape(value: Any) -> str:
    """把文本塞进 MusicBrainz 的 Lucene 查询串之前先转义。

    MB 搜索语法里 `"` 用来包短语、`\\` 是转义符。原来直接
    `f'release:"{album_name}"'` 拼接，专辑名自带引号（"Heroes"、
    日碟名里嵌的英文引号）会把查询截断 → MB 返回 400 →
    is_permanent_failure 判定确定性失败、不重试 → FetchError 被 catch →
    **候选列表静默变空**，用户只看到「没找到」，无从知道是查询语法坏了。
    反斜杠必须先转义，否则 'a\\"' 这类输入会多吃掉一个字符。
    """
    text = first(value)
    return text.replace("\\", "\\\\").replace('"', '\\"')


def mb_release_group_candidates(title: str, artist: str = "", limit: int = 8) -> list[dict[str, Any]]:
    """新建发行组之前先查有没有现成的，避开重复 RG。"""
    clean_title = TITLE_SUFFIX_RE.sub("", first(title)).strip() or first(title)
    if not clean_title:
        return []
    query = f'releasegroup:"{mb_query_escape(clean_title)}"'
    if artist.strip():
        query += f' AND artist:"{mb_query_escape(artist)}"'
    try:
        found = mb_request("release-group", {"query": query, "limit": str(limit), "fmt": "json"})
    except FetchError:
        return []
    rows: list[dict[str, Any]] = []
    for item in found.get("release-groups") or []:
        mbid = first(item.get("id"))
        if not mbid or not title_is_related(item.get("title"), clean_title):
            continue
        rows.append({
            "mbid": mbid,
            "title": first(item.get("title")),
            "primary_type": first(item.get("primary-type")),
            "artist": mb_search_artist(item),
            "release_count": item.get("count") or 0,
            "score": item.get("score") or 0,
            "url": f"https://musicbrainz.org/release-group/{mbid}",
        })
    return rows


def mb_artist_candidates(name: str, limit: int = 3) -> list[dict[str, Any]]:
    """把艺人名解析成 MusicBrainz 艺人，避免新建重名艺人；候选按「同名优先」排序。"""
    clean_name = first(name).strip()
    if not clean_name:
        return []
    try:
        found = mb_request("artist", {"query": f'"{mb_query_escape(clean_name)}"', "limit": str(limit), "fmt": "json"})
    except FetchError:
        return []
    rows: list[dict[str, Any]] = []
    for item in found.get("artists") or []:
        mbid = first(item.get("id"))
        if not mbid:
            continue
        try:
            score = int(item.get("score") or 0)
        except (TypeError, ValueError):
            score = 0
        rows.append({
            "mbid": mbid,
            "name": first(item.get("name")),
            "score": score,
            "disambiguation": first(item.get("disambiguation")),
            "type": first(item.get("type")),
            "url": f"https://musicbrainz.org/artist/{mbid}",
        })
    rows.sort(key=lambda row: (row["name"].casefold() != clean_name.casefold(), -row["score"]))
    return rows


def deezer_available_countries(tracks: list[dict[str, Any]], samples: int = 3) -> tuple[list[str], int]:
    """Deezer 只在单曲接口给 available_countries；抽首/中/尾各一轨取并集，标成抽样结果。"""
    ids = [first(track.get("vendor_id")) for track in tracks if first(track.get("vendor_id"))]
    if not ids:
        return [], 0
    codes: set[str] = set()
    used = 0
    picks = list(dict.fromkeys(ids[index] for index in sorted({0, len(ids) // 2, len(ids) - 1})))[:samples]
    for track_id in picks:
        try:
            data = fetch_json(f"{DEEZER_BASE}/track/{quote(track_id)}")
        except FetchError:
            continue
        # 出错时 Deezer 给的是 200 + error 体，不能当成「取到了但没地区」
        if deezer_error(data):
            continue
        used += 1
        codes.update(first(code) for code in data.get("available_countries") or [] if first(code))
        time.sleep(0.2)
    return sorted(codes), used


def normalize_itunes(data: dict[str, Any]) -> dict[str, Any]:
    tracks = []
    for item in data.get("results") or []:
        if item.get("wrapperType") != "track":
            continue
        tracks.append({
            "number": str(item.get("trackNumber") or ""),
            "disc": str(item.get("discNumber") or ""),
            "title": first(item.get("trackName")),
            "artist": first(item.get("artistName")),
            "length": format_duration(item.get("trackTimeMillis")),
            "recording_mbid": "",
            "source": "Apple/iTunes",
        })
    collection = next((item for item in data.get("results") or [] if item.get("wrapperType") == "collection"), {})
    artwork = first(collection.get("artworkUrl100"))
    if artwork:
        artwork = artwork.replace("100x100bb", "4000x4000-999")
    return {
        "title": first(collection.get("collectionName")),
        "artist": first(collection.get("artistName")),
        "date": iso_date(collection.get("releaseDate")),
        "label": first(collection.get("copyright")),
        "genre": first(collection.get("primaryGenreName")),
        "country": first(collection.get("country")),
        "track_count": len(tracks),
        "tracks": tracks,
        "artwork_url": artwork,
        "url": normalize_mb_url(urljoin("https://music.apple.com", first(collection.get("collectionViewUrl")))),
        "collection_id": str(collection.get("collectionId") or ""),
        "source": "Apple/iTunes Search API",
    }


def normalize_mb_release(release: dict[str, Any]) -> dict[str, Any]:
    group = release.get("release-group") or {}
    labels = release.get("label-info") or []
    label = ""
    catalog = ""
    for info in labels:
        label_data = info.get("label") or {}
        label = label or first(label_data.get("name"))
        catalog = catalog or first(info.get("catalog-number"))
    return {
        "title": clean_value(release.get("title")),
        "artist": mb_artist_credit(release.get("artist-credit")),
        "artist_mbid": single_credit_mbid(release.get("artist-credit")),
        "date": iso_date(release.get("date")),
        "country": first(release.get("country")),
        "release_events": mb_release_events(release),
        "label": clean_value(label),
        "catalog_number": clean_value(catalog),
        "status": first(release.get("status")),
        "barcode": clean_value(release.get("barcode")),
        "format": ", ".join(first(media.get("format")) for media in release.get("media") or [] if first(media.get("format"))),
        "release_mbid": first(release.get("id")),
        "release_group_mbid": first(group.get("id")),
        "primary_type": first(group.get("primary-type")),
        "secondary_types": group.get("secondary-types") or [],
        "track_count": sum(len(media.get("tracks") or []) for media in release.get("media") or []),
        "tracks": mb_tracks(release),
        "external_urls": [
            {"type": first(relation.get("type")), "url": first((relation.get("url") or {}).get("resource"))}
            for relation in release.get("relations") or []
            if first((relation.get("url") or {}).get("resource"))
        ],
        "source": "MusicBrainz API",
    }


def language_script(title: str, tracks: list[dict[str, Any]], region: str = "") -> tuple[str, str]:
    """推断 Language / Script。

    关键一点：汉字（U+4E00–U+9FFF）是**中文、日文、韩文共用**的字符集。
    早期版本把「含汉字」直接判定为日语，于是所有中文专辑都被写成了
    Language=Japanese / Script=Japanese —— 在 MusicBrainz 上是错的。
    真正的判据是假名与谚文这类**专属**字符：
      - 平假名 / 片假名 (U+3040–U+30FF) → 日语
      - 谚文 (U+AC00–U+D7AF)           → 韩语
      - 只有汉字                       → 中文（Han 文字）
    纯汉字时若链接明确来自 JP / KR 区，再按该区倾斜。
    """
    text = " ".join([title] + [first(track.get("title")) for track in tracks])
    has_kana = bool(re.search(r"[\u3040-\u30ff]", text))
    has_hangul = bool(re.search(r"[\uac00-\ud7af]", text))
    has_han = bool(re.search(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]", text))
    region = (region or "").lower()

    if has_kana:
        return "Japanese", "Japanese"
    if has_hangul:
        return "Korean", "Hangul"
    if has_han:
        if region == "jp":
            return "Japanese", "Japanese"
        if region == "kr":
            return "Korean", "Hangul"
        return "Chinese", "Han"
    return "English", "Latin"


def likely_compilation(title: str, source_data: list[dict[str, Any]]) -> tuple[bool, str]:
    terms = r"compilation|best|greatest|collection|selection|精选|合集|合辑|歌单|夏に聴きたい"
    if re.search(terms, title, re.I):
        return True, "标题包含合辑/精选语义，建议人工确认。"
    if any(str(item.get("secondary_types") or "").lower().find("compilation") >= 0 for item in source_data):
        return True, "MusicBrainz 来源标记为 Compilation。"
    return False, "未能从公开来源确认 Compilation，请根据发行页面和官方署名人工判断。"


def merge_tracks(itunes_tracks: list[dict[str, Any]], mb_tracks_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if mb_tracks_data:
        return mb_tracks_data
    return itunes_tracks


def track_slot(track: dict[str, Any]) -> tuple[str, str]:
    return first(track.get("disc")) or "1", first(track.get("number"))


def fill_missing_isrc(tracks: list[dict[str, Any]], donors: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """MusicBrainz 的曲目没有 ISRC 字段，用 Deezer / Spotify 的同碟同轨号补上；只填空值，不覆盖已有数据。"""
    by_slot: dict[tuple[str, str], str] = {}
    for donor in donors:
        for track in donor or []:
            isrc = first(track.get("isrc"))
            if isrc:
                by_slot.setdefault(track_slot(track), isrc)
    if not by_slot:
        return tracks
    for track in tracks:
        if not first(track.get("isrc")):
            track["isrc"] = by_slot.get(track_slot(track), "")
    return tracks


# 切分用户粘贴的一串链接：换行 / 分号，以及「逗号后面紧跟一个新链接」。
# 纯按 [\n,;]+ 切会把查询参数里带逗号的链接（?ids=1,2）截断，
# 前端 app.js 的 collectUrls 用的是同一套规则。
SOURCE_URL_SPLIT_RE = re.compile(r"[\n;]+|,\s*(?=https?://)", re.I)


def split_source_urls(value: Any, warnings: list[dict[str, str]] | None = None) -> list[str]:
    """把输入框 / 请求体里的一串链接切成列表，并丢掉抓不了的协议。

    ⚠ 危险协议必须在这里就拦掉。原来只判断「有没有 scheme」，
    `javascript:alert(1)` 有 scheme 就被原样放行入库，最后以「输入链接」
    的名义渲染成 `<a href="javascript:...">` —— escapeHtml 只处理字符、不处理协议头，
    点一下就在报告页里执行；配合 #copy-share 生成的 ?urls=... 分享链接，
    这就是一个「点开就中招」的完整入口。所以这里复用 check_outbound 的第一道闸。
    """
    raw_values = value if isinstance(value, list) else SOURCE_URL_SPLIT_RE.split(first(value))
    result: list[str] = []
    for item in raw_values:
        url = first(item).strip().strip("\u200b")
        if not url:
            continue
        if url.startswith("//"):
            url = f"https:{url}"  # 协议相对写法（//example.com/x）
        scheme = urlparse(url).scheme.lower()
        if scheme not in ("http", "https"):
            if scheme and warnings is not None:
                # 有协议头但不是 http/https：明确回一条 warning，别静默丢弃。
                # 没有协议头的（比如用户把专辑名填进了链接框）保持原样忽略。
                warnings.append({"source": "输入链接", "warning": f"已忽略非 http/https 链接：{url[:80]}"})
            continue
        if url not in result:
            result.append(url)
    return result


def choose_itunes_candidate(candidates: list[dict[str, Any]], title_hint: str, artist_hint: str) -> dict[str, Any]:
    def score(candidate: dict[str, Any]) -> tuple[int, int]:
        title_match = int(title_match_key(candidate.get("title")) == title_match_key(title_hint)) if title_hint else 0
        artist_match = int(bool(artist_hint) and first(candidate.get("artist")).casefold().replace(" ", "") == artist_hint.casefold().replace(" ", ""))
        return artist_match, title_match
    return max(candidates, key=score, default={})


def choose_mb_candidate(candidates: list[dict[str, Any]], title_hint: str, artist_hint: str) -> dict[str, Any]:
    def score(candidate: dict[str, Any]) -> tuple[int, int, int]:
        title = first(candidate.get("title")).casefold()
        phrase = mb_search_artist(candidate).casefold()
        title_match = int(bool(title_hint) and title == title_hint.casefold())
        artist_match = int(bool(artist_hint) and artist_hint.casefold().replace(" ", "") in phrase.replace(" ", ""))
        try:
            relevance = int(candidate.get("score") or 0)
        except (TypeError, ValueError):
            relevance = 0
        return title_match, artist_match, relevance
    return max(candidates, key=score, default={})


def comparable_sources(apple_data: dict[str, Any], mb_data: dict[str, Any], page_summaries: list[dict[str, Any]], extra_records: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if apple_data:
        records.append({"name": "Apple/iTunes", **apple_data})
    if mb_data:
        records.append({"name": "MusicBrainz", **mb_data})
    for page in page_summaries:
        if page.get("status") == "ok":
            records.append({"name": page.get("source") or "输入页面", **page})
    for item in extra_records or []:
        name = item.get("source") or "补充来源"
        existing = next((record for record in records if record.get("name") == name), None)
        if existing is not None:
            for key, value in item.items():
                if key not in ("source", "url") and value and not existing.get(key):
                    existing[key] = value
        else:
            record = dict(item)
            record["name"] = name
            records.append(record)
    fields = [
        ("Title", "title"), ("Artist", "artist"), ("Date", "date"), ("Label", "label"),
        ("Catalog number", "catalog_number"), ("Barcode", "barcode"), ("Track count", "track_count"),
        ("Primary type", "primary_type"),
    ]
    comparison: list[dict[str, Any]] = []
    for label, key in fields:
        values = [{"source": record.get("name", ""), "value": record.get(key, "")} for record in records if record.get(key, "") not in ("", None, 0)]
        distinct = {re.sub(r"\s+", "", str(item["value"])).casefold() for item in values}
        if not values:
            status = "missing"
            note = "公开来源未提供"
        elif len(distinct) == 1:
            status = "match"
            note = "来源一致"
        else:
            status = "conflict"
            note = "来源存在差异，需要人工核对"
        comparison.append({"field": label, "key": key, "status": status, "values": values, "note": note})
    return comparison


def itunes_artist_albums(artist_name: str, limit_artists: int = 3, max_albums: int = 200) -> list[dict[str, Any]]:
    """Apple 的专辑名搜索对重名专辑很弱，但按艺人查专辑列表很全：先找艺人 ID，再列该艺人全部专辑。"""
    if not artist_name.strip():
        return []
    try:
        found = fetch_json(f"https://itunes.apple.com/search?term={quote(artist_name)}&entity=musicArtist&limit={limit_artists}")
    except FetchError:
        return []
    artists = [item for item in found.get("results") or [] if item.get("artistId")]
    target = artist_name.strip()
    # 大小写敏感完全一致的优先，避免把 LiSA 匹配到 LISA
    artists.sort(key=lambda item: (
        0 if first(item.get("artistName")) == target else 1,
        0 if first(item.get("artistName")).casefold() == target.casefold() else 1,
    ))
    albums: list[dict[str, Any]] = []
    seen: set[str] = set()
    for artist in artists[:2]:
        try:
            listing = fetch_json(f"https://itunes.apple.com/lookup?id={artist.get('artistId')}&entity=album&limit={max_albums}")
        except FetchError:
            continue
        for item in listing.get("results") or []:
            if item.get("wrapperType") != "collection":
                continue
            data = normalize_itunes({"results": [item]})
            collection_id = data.get("collection_id", "")
            if not collection_id or collection_id in seen:
                continue
            seen.add(collection_id)
            data["track_count"] = item.get("trackCount") or 0
            albums.append(data)
    return albums


def search_candidates(album_name: str, artist_name: str = "") -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    try:
        term = " ".join(item for item in [artist_name, album_name] if item).strip()
        if term:
            rows = spotify_related_rows(term, album_name)
            for item in rows:
                candidates.append({
                    "source": "Spotify",
                    "title": first(item.get("name")),
                    "artist": " / ".join(first(artist.get("name")) for artist in item.get("artists") or [] if isinstance(artist, dict) and first(artist.get("name"))),
                    "date": iso_date(item.get("release_date")),
                    "track_count": item.get("total_tracks") or 0,
                    "url": f"https://open.spotify.com/album/{first(item.get('id'))}",
                    "id": first(item.get("id")),
                })
    except FetchError as exc:
        errors.append({"source": "Spotify", "error": str(exc)})
    try:
        term = " ".join(item for item in [artist_name, album_name] if item).strip()
        apple_raw = fetch_json(f"https://itunes.apple.com/search?term={quote(term)}&entity=album&limit=25")
        for item in apple_raw.get("results") or []:
            if item.get("wrapperType") != "collection":
                continue
            data = normalize_itunes({"results": [item]})
            data["track_count"] = item.get("trackCount") or 0
            if album_name and not title_is_related(data.get("title"), album_name):
                continue
            candidates.append({
                "source": "Apple/iTunes",
                "title": data.get("title", ""),
                "artist": data.get("artist", ""),
                "date": data.get("date", ""),
                "track_count": data.get("track_count", 0),
                "url": data.get("url", ""),
                "cover": data.get("artwork_url", ""),
                "id": data.get("collection_id", ""),
            })
    except FetchError as exc:
        errors.append({"source": "Apple/iTunes", "error": str(exc)})
    # 如果专辑名搜不到，再查「歌曲名」；很多用户输入的其实是曲名（如 ご褒美しよっ！）
    track_candidates: list[dict[str, Any]] = []
    apple_song_fallback: list[dict[str, Any]] = []
    try:
        if album_name:
            apple_songs = fetch_json(f"https://itunes.apple.com/search?term={quote(album_name)}&entity=song&limit=25")
            for item in apple_songs.get("results") or []:
                track_title = first(item.get("trackName"))
                if not track_title:
                    continue
                row = {
                    "source": "Apple Music 曲目",
                    "title": first(item.get("collectionName")) or track_title,
                    "track_title": track_title,
                    "artist": first(item.get("artistName")),
                    "date": iso_date(item.get("releaseDate")),
                    "track_count": item.get("trackCount") or 0,
                    "url": first(item.get("collectionViewUrl")) or first(item.get("trackViewUrl")),
                    "cover": first(item.get("artworkUrl100")),
                    "id": str(item.get("collectionId") or item.get("trackId") or ""),
                }
                if title_is_related(track_title, album_name):
                    track_candidates.append(row)
                elif len(apple_song_fallback) < 3:
                    apple_song_fallback.append({**row, "source": "Apple Music 曲目（可能本地化标题）"})
                continue
    except FetchError as exc:
        errors.append({"source": "Apple Music 曲目", "error": str(exc)})
    try:
        if album_name:
            for item in spotify_related_rows(album_name, album_name, kind="track", limits=(12, 11, 13)):
                track_id = first(item.get("id"))
                if not track_id:
                    continue
                track = spotify_track(track_id)
                if not track or not title_is_related(track.get("title"), album_name):
                    continue
                track_candidates.append({
                    "source": "Spotify 曲目",
                    "title": track.get("album") or track.get("title"),
                    "track_title": track.get("title"),
                    "artist": track.get("artist"),
                    "date": track.get("date"),
                    "track_count": 0,
                    "url": track.get("url"),
                    "cover": track.get("image"),
                    "id": track.get("id"),
                })
    except FetchError as exc:
        errors.append({"source": "Spotify 曲目", "error": str(exc)})
    # 只有专辑精确匹配不存在时，才展示歌曲结果；避免「Who am I?」这类重名标题被大量曲目淹没

    # 专辑名搜索对重名专辑很弱，再用艺人维度补一轮 Apple 结果
    artist_terms: list[str] = []
    if artist_name.strip():
        artist_terms.append(artist_name.strip())
    for item in candidates:
        if item["source"] != "Spotify" or not title_match_key(item.get("title")) == title_match_key(album_name):
            continue
        for name in first(item.get("artist")).split(" / "):
            name = name.strip()
            if name and name not in artist_terms:
                artist_terms.append(name)
        if len(artist_terms) >= 3:
            break
    for term in artist_terms[:3]:
        known = {item["id"] for item in candidates if item["source"].startswith("Apple/iTunes")}
        for data in itunes_artist_albums(term):
            if data.get("collection_id") in known:
                continue
            if album_name and not title_is_related(data.get("title"), album_name):
                continue
            candidates.append({
                "source": "Apple/iTunes（按艺人）",
                "title": data.get("title", ""),
                "artist": data.get("artist", ""),
                "date": data.get("date", ""),
                "track_count": data.get("track_count", 0),
                "url": data.get("url", ""),
                "cover": data.get("artwork_url", ""),
                "id": data.get("collection_id", ""),
            })
    try:
        query = f'release:"{mb_query_escape(album_name)}"'
        if artist_name:
            query += f' AND artist:"{mb_query_escape(artist_name)}"'
        search = mb_request("release", {"query": query, "limit": "15", "fmt": "json"})
        for item in search.get("releases") or []:
            if album_name and not title_is_related(item.get("title"), album_name):
                continue
            candidates.append({
                "source": "MusicBrainz",
                "title": first(item.get("title")),
                "artist": mb_search_artist(item),
                "date": first(item.get("date")),
                "track_count": item.get("track-count") or 0,
                "url": f"https://musicbrainz.org/release/{first(item.get('id'))}" if first(item.get("id")) else "",
                "id": first(item.get("id")),
            })
    except FetchError as exc:
        errors.append({"source": "MusicBrainz", "error": str(exc)})

    album_exact = any(
        not item.get("track_title") and title_match_key(item.get("title")) == title_match_key(album_name)
        for item in candidates
    ) if album_name else False
    if not album_exact:
        candidates.extend(track_candidates)
        candidates.extend(apple_song_fallback[:1])

    def candidate_search_title(candidate: dict[str, Any]) -> str:
        return first(candidate.get("track_title")) or first(candidate.get("title"))

    def identity(candidate: dict[str, Any]) -> tuple[str, str]:
        return candidate_search_title(candidate).casefold(), first(candidate.get("artist")).casefold().replace(" ", "")

    # 被多个来源同时命中的专辑更可信（例如 Spotify 与 Apple 都返回了同一张），排序时优先
    corroboration = Counter(identity(item) for item in candidates)

    def rank(candidate: dict[str, Any]) -> tuple[int, int, int, int, int, int, int]:
        title = candidate_search_title(candidate).casefold()
        artist = first(candidate.get("artist")).casefold().replace(" ", "")
        title_exact = int(title_match_key(title) == title_match_key(album_name))
        artist_exact = int(bool(artist_name) and artist == artist_name.casefold().replace(" ", ""))
        track_kind = int(bool(candidate.get("track_title")))
        localized_title = int("本地化" in first(candidate.get("source")))
        cross_source = corroboration.get(identity(candidate), 1)
        title_contains = int(bool(album_name) and album_name.casefold() in title)
        complete = int(bool(candidate.get("date")) and bool(candidate.get("track_count")))
        return title_exact, artist_exact, track_kind, localized_title, cross_source, title_contains, complete

    candidates.sort(key=rank, reverse=True)
    for candidate in candidates:
        candidate["match_type"] = "exact" if title_match_key(candidate_search_title(candidate)) == title_match_key(album_name) else "related"
    visible = candidates[:18]
    exact_found = any(item.get("match_type") == "exact" for item in candidates)
    source_counts = Counter(item.get("source", "") for item in visible)
    return {
        "query": {"album_name": album_name, "artist_name": artist_name},
        "candidates": visible,
        "exact_found": exact_found,
        "source_counts": dict(source_counts),
        "errors": errors,
    }


def build_report(album_name: str, input_url: str = "", input_urls: Any = None, manual_catalog: str = "", artist_name: str = "") -> dict[str, Any]:
    # 清零后统计的是「这一次查询」的命中数，否则长跑的服务会把历史累计算进来，
    # 报告里那句「本次有 N 个命中缓存」就成了假数据
    CACHE_STATS.hit = 0
    CACHE_STATS.miss = 0
    source_errors: list[dict[str, str]] = []
    source_warnings: list[dict[str, str]] = []
    sources: list[dict[str, Any]] = []
    apple_data: dict[str, Any] = {}
    mb_data: dict[str, Any] = {}
    matched_by_title_only = False
    reverse_used = ""
    source_urls = split_source_urls(input_urls if input_urls is not None else input_url, source_warnings)
    if not source_urls and input_url:
        source_urls = split_source_urls(input_url, source_warnings)
    if not source_urls and album_name:
        source_urls = split_source_urls(album_name, source_warnings)
    primary_url = source_urls[0] if source_urls else ""
    if not source_urls and (album_name or artist_name):
        return {"needs_selection": True, "reason": "未填写链接，请先从候选结果中选择一张专辑", "query": {"album_name": album_name, "artist_name": artist_name}, "search": search_candidates(album_name, artist_name)}
    page_summaries = [source_page_summary(url) for url in source_urls]
    page_summaries = [summary for summary in page_summaries if summary]
    page_hint = next((item for item in page_summaries if item.get("status") == "ok" and (item.get("title") or item.get("artist"))), {})
    release_id, release_group_id = extract_mbids(primary_url)
    apple_id = extract_apple_id(primary_url)
    spotify_id = next((found for url in source_urls if (found := extract_spotify_id(url))), "")
    spotify_data: dict[str, Any] = {}
    if spotify_id:
        try:
            spotify_data = spotify_album(spotify_id)
        except FetchError as exc:
            source_warnings.append({"source": "Spotify", "warning": f"Spotify 数据读取失败：{exc}"})
    deezer_id = next((found for url in source_urls if (found := extract_deezer_id(url))), "")
    deezer_data: dict[str, Any] = {}
    deezer_reverse = ""
    if deezer_id:
        try:
            deezer_data = deezer_album(deezer_id)
        except FetchError as exc:
            source_warnings.append({"source": "Deezer", "warning": f"Deezer 数据读取失败：{exc}"})
    if deezer_data and not page_hint and deezer_id:
        # 输入就是 Deezer 链接时数据来自 API 而非页面解析，用它顶替 page_hint，避免误报「页面解析失败」
        page_hint = deezer_data
    title_hint = first(page_hint.get("title")) or first(spotify_data.get("title")) or first(deezer_data.get("title")) or album_name
    artist_hint = first(page_hint.get("artist")) or artist_name.strip() or first(spotify_data.get("artist")) or first(deezer_data.get("artist"))

    apple_url_country = next((extract_apple_country(url) for url in source_urls if extract_apple_country(url)), "")
    # 默认按链接自带的区；apple_id 分支里查到数据后按实际数据来源区更新（整单切换后可能不再是链接区）
    apple_country = apple_url_country
    try:
        if apple_id:
            picked = itunes_album_by_id(apple_id, apple_url_country, artist_hint)
            apple_data = picked["data"]
            apple_country = picked["country"] or apple_url_country
            # 没有标题就是空壳响应，必须当没查到；否则会被当成成功的 Apple 来源，并挡住其他来源补链接
            if not first(apple_data.get("title")) or (artist_hint and first(apple_data.get("artist")) and first(apple_data.get("artist")).casefold().replace(" ", "") != artist_hint.casefold().replace(" ", "")):
                apple_data = {}
            else:
                if picked["note"]:
                    source_warnings.append({"source": "Apple/iTunes", "warning": picked["note"]})
                sources.append({"name": "Apple/iTunes", "status": "ok", "url": apple_data.get("url") or primary_url, "summary": apple_data})
        elif not title_hint:
            source_warnings.append({"source": "Apple/iTunes", "warning": "未提供专辑名，跳过 Apple 搜索以免引入错误结果"})
        else:
            # 搜索词也要去掉「- Single / - EP」这类后缀，否则 Apple 搜不到
            search_title = TITLE_SUFFIX_RE.sub("", title_hint).strip() or title_hint
            apple_term = " ".join(item for item in [artist_hint, search_title] if item)
            apple_raw = fetch_json(f"https://itunes.apple.com/search?term={quote(apple_term)}&entity=album&limit=15")
            apple_candidates = [normalize_itunes({"results": [item]}) for item in apple_raw.get("results") or [] if item.get("wrapperType") == "collection"] if apple_raw else []
            if artist_hint:
                matching = [item for item in apple_candidates if title_match_key(item.get("title")) == title_match_key(title_hint) and first(item.get("artist")).casefold().replace(" ", "") == artist_hint.casefold().replace(" ", "")]
            else:
                matching = [item for item in apple_candidates if title_match_key(item.get("title")) == title_match_key(title_hint)]
            apple_data = matching[0] if matching else {}
            if not apple_data and artist_hint:
                # 专辑名搜索对重名专辑很弱，改按艺人列专辑再按标题匹配
                for data in itunes_artist_albums(artist_hint):
                    if title_match_key(data.get("title")) == title_match_key(title_hint):
                        apple_data = data
                        source_warnings.append({"source": "Apple/iTunes", "warning": f"专辑名搜索没命中，已改用艺人维度找到 Apple 专辑 {data.get('collection_id')}"})
                        break
            if not apple_data and apple_candidates:
                source_warnings.append({"source": "Apple/iTunes", "warning": f"搜索结果前 15 个专辑没有匹配标题 {title_hint}" + (f" 和艺人 {artist_hint}" if artist_hint else "") + "，已跳过以免引入错误结果"})
            elif not apple_data:
                source_warnings.append({"source": "Apple/iTunes", "warning": "没有找到对应专辑，已使用输入页面和其他来源"})
            else:
                sources.append({"name": "Apple/iTunes", "status": "ok", "url": apple_data.get("url") or primary_url, "summary": apple_data})
    except FetchError as exc:
        source_errors.append({"source": "Apple/iTunes", "error": str(exc)})

    # Apple 有时只返回网页播放器外壳，此时用 iTunes API 的结果补上标题和艺人线索
    if not title_hint:
        title_hint = first(apple_data.get("title"))
    if not artist_hint:
        artist_hint = first(apple_data.get("artist"))

    try:
        if not release_id and not release_group_id:
            for url in source_urls[:4]:
                if "musicbrainz.org" in urlparse(url).netloc.lower():
                    continue
                found = mb_reverse_release_ids(url)
                if found:
                    release_id = found[0]
                    reverse_used = url
                    break
        if release_id:
            release = mb_request(f"release/{release_id}", {"inc": "artist-credits+labels+recordings+release-groups+media+url-rels", "fmt": "json"})
            mb_data = normalize_mb_release(release)
        elif release_group_id:
            group = mb_request(f"release-group/{release_group_id}", {"inc": "releases+artist-credits", "fmt": "json"})
            releases = group.get("releases") or []
            if releases:
                release = mb_request(f"release/{releases[0].get('id')}", {"inc": "artist-credits+labels+recordings+release-groups+media+url-rels", "fmt": "json"})
                mb_data = normalize_mb_release(release)
        elif not title_hint:
            source_warnings.append({"source": "MusicBrainz", "warning": "未提供专辑名，跳过 MusicBrainz 搜索以免引入错误结果"})
        else:
            query = f'release:"{mb_query_escape(TITLE_SUFFIX_RE.sub("", title_hint).strip() or title_hint)}"'
            if artist_hint:
                query += f' AND artist:"{mb_query_escape(artist_hint)}"'
            search = mb_request("release", {"query": query, "limit": "15", "fmt": "json"})
            candidates = search.get("releases") or []
            if artist_hint:
                matching = [item for item in candidates if title_match_key(item.get("title")) == title_match_key(title_hint) and artist_hint.casefold().replace(" ", "") in mb_search_artist(item).casefold().replace(" ", "")]
            else:
                matching = [item for item in candidates if title_match_key(item.get("title")) == title_match_key(title_hint) and mb_search_artist(item).strip()]
                if matching:
                    matched_by_title_only = True
                    source_warnings.append({"source": "MusicBrainz", "warning": f"输入页面没有提供艺人，仅按标题「{title_hint}」匹配到发行；请人工确认是否是同一张"})
            selected = matching[0] if matching else {}
            if selected:
                release = mb_request(f"release/{selected.get('id')}", {"inc": "artist-credits+labels+recordings+release-groups+media+url-rels", "fmt": "json"})
                mb_data = normalize_mb_release(release)
        if mb_data:
            if reverse_used:
                sources.append({"name": "MusicBrainz 反向查询", "status": "ok", "url": reverse_used, "summary": {"note": f"通过链接反查到 MusicBrainz 发行 {mb_data.get('release_mbid')}"}})
            sources.append({"name": "MusicBrainz", "status": "ok", "url": f"https://musicbrainz.org/release/{mb_data.get('release_mbid')}", "summary": mb_data})
        elif not release_id and not release_group_id:
            source_warnings.append({"source": "MusicBrainz", "warning": "没有找到对应发行；可先用本资料人工建 Release，再回填 MBID"})
    except FetchError as exc:
        source_errors.append({"source": "MusicBrainz", "error": str(exc)})

    # 通过 Spotify（经 groover.co 代理）补充 UPC / 厂牌 / 曲目，UPC 即条码
    spotify_title = title_hint or first(apple_data.get("title"))
    spotify_artist = artist_hint or first(apple_data.get("artist"))
    spotify_query = "" if spotify_data else " ".join(item for item in [spotify_artist, TITLE_SUFFIX_RE.sub("", spotify_title).strip() or spotify_title] if item).strip()
    if spotify_query:
        try:
            results = spotify_search(spotify_query)
            picked = next((item for item in results if first(item.get("name")).casefold() == spotify_title.casefold() and (not spotify_artist or spotify_artist.casefold().replace(" ", "") in " ".join(first(a.get("name")) for a in item.get("artists") or [] if isinstance(a, dict)).casefold().replace(" ", ""))), {})
            if not picked:
                picked = next((item for item in results if first(item.get("name")).casefold() == spotify_title.casefold()), {})
            if picked:
                spotify_data = spotify_album(first(picked.get("id")))
            else:
                source_warnings.append({"source": "Spotify", "warning": f"没有匹配到「{spotify_query}」的 Spotify 专辑，UPC 与厂牌可能缺失"})
        except FetchError as exc:
            source_warnings.append({"source": "Spotify", "warning": f"UPC / 厂牌补充查询失败：{exc}"})

    # 用 MusicBrainz 记录的外部链接倒查商店页，补齐品番等本地字段
    store_pattern = r"ototoy\.jp|mora\.jp|bandcamp\.com|qobuz\.com|deezer\.com|amazon\."
    known_urls = {normalize_mb_url(url) for url in source_urls}
    store_urls = []
    for relation in mb_data.get("external_urls") or []:
        url = relation.get("url", "")
        if url and re.search(store_pattern, url, re.I) and normalize_mb_url(url) not in known_urls:
            store_urls.append(url)
    for url in store_urls[:3]:
        if not deezer_data and "deezer.com" in urlparse(url).netloc.lower():
            try:
                deezer_data = deezer_album(extract_deezer_id(url))
            except FetchError as exc:
                source_warnings.append({"source": "Deezer", "warning": f"MusicBrainz 记录的 Deezer 链接读取失败：{exc}"})
            if deezer_data:
                deezer_reverse = "MusicBrainz 记录的 Deezer 链接"
                continue
        summary = source_page_summary(url)
        if summary:
            page_summaries.append(summary)
            known_urls.add(normalize_mb_url(url))

    # 只有 Apple / Spotify 链接时用条码反查 Deezer，把 ISRC、imprint 和发行类型补齐
    if not deezer_data and not deezer_id:
        barcode_hint = clean_value(spotify_data.get("upc")) or clean_value(mb_data.get("barcode"))
        if barcode_hint:
            if not barcode_is_plausible(barcode_hint):
                source_warnings.append({"source": "Barcode", "warning": f"条码 {barcode_hint} 不是有效的商品条码（疑似占位值），已跳过 Deezer 反查以免引入无关专辑"})
            else:
                try:
                    deezer_data = deezer_album_by_upc(barcode_hint, title_hint, artist_hint)
                except FetchError as exc:
                    source_warnings.append({"source": "Deezer", "warning": f"条码反查 Deezer 失败：{exc}"})
                if deezer_data:
                    deezer_reverse = f"条码 {barcode_hint}"
                elif barcode_hint:
                    source_warnings.append({"source": "Deezer", "warning": f"条码 {barcode_hint} 在 Deezer 没有反查到与《{title_hint}》相符的专辑，已跳过（避免混入同名或无关发行）"})

    # 曲目单独拉失败时，专辑级字段仍然可用；但必须把原因说出来，
    # 否则「这张碟没有 ISRC」和「Deezer 接口出错」在报告里长得一模一样
    if deezer_data.get("tracks_error"):
        source_warnings.append({"source": "Deezer", "warning": f"{deezer_data['tracks_error']} —— 逐轨 ISRC / 时长可能不完整，可稍后重试或改用其它来源核对"})

    if deezer_data:
        if deezer_reverse:
            sources.append({"name": "Deezer 反查", "status": "ok", "url": deezer_data.get("url") or "", "summary": {"note": f"通过{deezer_reverse}找到 Deezer 专辑 {deezer_data.get('url')}"}})
        sources.append({"name": "Deezer", "status": "ok", "url": deezer_data.get("url") or "", "summary": deezer_data})

    if spotify_data:
        sources.append({"name": "Spotify", "status": "ok", "url": spotify_data.get("url") or "", "summary": spotify_data})

    for page_summary in page_summaries:
        sources.append({"name": page_summary.get("source") or "输入链接页面", "status": page_summary.get("status"), "url": page_summary.get("url"), "summary": page_summary})
        if page_summary.get("status") != "ok":
            source_warnings.append({"source": page_summary.get("source") or "输入链接页面", "warning": f"页面抓取失败（{page_summary.get('error', '未知原因')}），该来源未参与本次整理，可重试或改用其它链接"})

    ok_pages = [item for item in page_summaries if item.get("status") == "ok"]
    page_label = next((clean_value(item.get("label")) for item in ok_pages if clean_value(item.get("label"))), "")
    page_catalog = next((clean_value(item.get("catalog_number")) for item in ok_pages if clean_value(item.get("catalog_number"))), "")
    title = first(mb_data.get("title")) or first(page_hint.get("title")) or first(apple_data.get("title")) or first(spotify_data.get("title")) or first(deezer_data.get("title")) or album_name
    artist = first(mb_data.get("artist")) or first(page_hint.get("artist")) or first(apple_data.get("artist")) or first(spotify_data.get("artist")) or first(deezer_data.get("artist"))
    tracks = merge_tracks(page_hint.get("tracks") or apple_data.get("tracks") or deezer_data.get("tracks") or spotify_data.get("tracks") or [], mb_data.get("tracks") or [])
    isrc_donors = [deezer_data.get("tracks") or [], spotify_data.get("tracks") or [], apple_data.get("tracks") or [], page_hint.get("tracks") or []]
    tracks = fill_missing_isrc(tracks, isrc_donors)
    # 补 ISRC 是按「碟-轨号」对位的：对不上就留空，这是有意的（宁缺勿错），
    # 但得让用户知道「不是没有来源，而是轨号没对上」—— 否则报告里那一片空白看不出原因
    empty_isrc_tracks = [track for track in tracks if not first(track.get("isrc"))]
    donor_slots = {track_slot(track) for donor in isrc_donors for track in donor if first(track.get("isrc"))}
    if empty_isrc_tracks and donor_slots:
        source_warnings.append({
            "source": "ISRC",
            "warning": f"{len(empty_isrc_tracks)} 轨 ISRC 未补齐：来源里有 ISRC，但碟-轨号与当前曲目表没对上，请人工核对后再填（宁可留空，也不猜）",
        })
    date = first(mb_data.get("date")) or first(page_hint.get("date")) or first(spotify_data.get("date")) or first(apple_data.get("date")) or first(deezer_data.get("date"))
    language, script = language_script(title, tracks, apple_url_country)
    is_compilation, compilation_note = likely_compilation(title, [apple_data, mb_data, deezer_data])
    digital = bool(re.search(r"music\.apple\.com|ototoy|mora|bandcamp|spotify|qobuz|tidal|deezer", " ".join(source_urls), re.I)) or bool(apple_data)
    country = "Worldwide" if digital else first(mb_data.get("country"))
    artwork_candidates = [item for item in [first(apple_data.get("artwork_url")), first(page_hint.get("image"))] if item]
    artwork_barcode = next((barcode_from_artwork(item) for item in artwork_candidates if barcode_from_artwork(item)), "")
    spotify_upc = clean_value(spotify_data.get("upc"))
    deezer_upc = clean_value(deezer_data.get("upc"))
    barcode = first(mb_data.get("barcode")) or deezer_upc or spotify_upc or artwork_barcode
    if not first(mb_data.get("barcode")) and deezer_upc:
        source_warnings.append({"source": "Barcode", "warning": f"条码 {deezer_upc} 来自 Deezer 的 UPC，提交前请与发行页面核对"})
    elif not first(mb_data.get("barcode")) and spotify_upc:
        source_warnings.append({"source": "Barcode", "warning": f"条码 {spotify_upc} 来自 Spotify 的 UPC，提交前请与发行页面核对"})
    elif not first(mb_data.get("barcode")) and artwork_barcode:
        source_warnings.append({"source": "Barcode", "warning": f"条码 {artwork_barcode} 取自 Apple 封面文件名（EAN 校验位合法），提交前请与发行页面核对"})
    url_catalogs = [{"source": urlparse(url).netloc, "url": url, "value": catalog_from_url(url)} for url in [*source_urls, *store_urls]]
    url_catalogs = [item for item in url_catalogs if item["value"]]
    manual_catalog = clean_value(manual_catalog).strip()
    mb_catalog = first(mb_data.get("catalog_number"))
    catalog_number = ""
    catalog_origin = ""
    if manual_catalog:
        catalog_number, catalog_origin = manual_catalog, "manual"
    elif page_catalog:
        catalog_number, catalog_origin = page_catalog, "page"
    elif mb_catalog:
        catalog_number, catalog_origin = mb_catalog, "mb"
    elif url_catalogs:
        catalog_number, catalog_origin = url_catalogs[0]["value"], "url"

    if not catalog_number:
        if mb_data:
            source_warnings.append({"source": "Catalog number", "warning": "MusicBrainz 已有该发行但没有品番，且它记录的外部链接里没有 OTOTOY/mora 等商店页；补充商店链接或手工填写即可"})
        else:
            source_warnings.append({"source": "Catalog number", "warning": "MusicBrainz 没有该发行，无法通过倒查拿到商店品番；可用下方辅助链接找到商店页后贴回来，或直接手工填写"})
    elif catalog_origin == "url":
        source_warnings.append({"source": "Catalog number", "warning": f"品番 {catalog_number} 来自链接地址推断，请与发行页面核对"})
    elif catalog_origin == "manual":
        source_warnings.append({"source": "Catalog number", "warning": f"品番 {catalog_number} 为手工填写，请确认与发行页一致"})
    if page_catalog and mb_catalog and page_catalog.casefold() != mb_catalog.casefold():
        source_warnings.append({"source": "Catalog number", "warning": f"发行页面品番 {page_catalog} 与 MusicBrainz 的 {mb_catalog} 不一致，请人工确认"})
    apple_copyright = first(apple_data.get("label"))
    derived_imprint = imprint_from_copyright(apple_copyright)
    spotify_label = clean_value(spotify_data.get("label"))
    deezer_label = clean_value(deezer_data.get("label"))
    label = first(mb_data.get("label")) or page_label or deezer_label or spotify_label or derived_imprint or apple_copyright
    if not first(mb_data.get("label")) and not page_label:
        parts = []
        if deezer_label:
            parts.append(f"Label 取自 Deezer 的 label 字段「{deezer_label}」")
        if spotify_label and spotify_label != deezer_label:
            parts.append(f"Label 取自 Spotify 的 label 字段「{spotify_label}」")
        if derived_imprint:
            parts.append(f"Apple 版权行里可能对应的厂牌是「{derived_imprint}」")
        if apple_copyright:
            parts.append(f"版权方是 {apple_copyright}")
        if parts:
            source_warnings.append({"source": "Label", "warning": "；".join(parts) + "。MusicBrainz 的 Label 字段要填 imprint，请人工确认后填写"})
    artwork_url = first(apple_data.get("artwork_url")) or first(deezer_data.get("image")) or next((first(item.get("image")) for item in page_summaries if first(item.get("image"))), "")
    extra_records = [{"source": item["source"], "url": item["url"], "catalog_number": item["value"]} for item in url_catalogs]
    if artwork_barcode:
        extra_records.append({"source": "Apple 封面文件名", "barcode": artwork_barcode})
    if spotify_data:
        extra_records.append({"source": "Spotify", "url": spotify_data.get("url", ""), "title": spotify_data.get("title", ""), "artist": spotify_data.get("artist", ""), "date": spotify_data.get("date", ""), "label": spotify_label, "barcode": spotify_upc, "track_count": spotify_data.get("track_count", 0)})
    if deezer_data:
        extra_records.append({"source": "Deezer", "url": deezer_data.get("url", ""), "title": deezer_data.get("title", ""), "artist": deezer_data.get("artist", ""), "date": deezer_data.get("date", ""), "label": deezer_label, "barcode": deezer_upc, "track_count": deezer_data.get("track_count", 0), "primary_type": deezer_data.get("primary_type", ""), "record_type": deezer_data.get("record_type", "")})
    if manual_catalog:
        extra_records.append({"source": "手工填写", "catalog_number": manual_catalog})
    lookup_query = search_query_text(" ".join(item for item in [artist, title] if item))
    lookup_links = [
        {"name": "mora 站内", "url": f"https://mora.jp/search/top?keyWord={quote(lookup_query)}"},
        {"name": "OTOTOY 站内", "url": f"https://ototoy.jp/find/?q={quote(lookup_query)}"},
        {"name": "Google 搜 OTOTOY", "url": f"https://www.google.com/search?q={quote(f'site:ototoy.jp {lookup_query}')}"},
        {"name": "Google 搜 mora", "url": f"https://www.google.com/search?q={quote(f'site:mora.jp {lookup_query}')}"},
    ] if lookup_query else []
    known_sites = {site for site, condition in (("Apple Music", bool(apple_id or first(apple_data.get("url")) or first(apple_data.get("collection_id")))), ("Spotify", bool(spotify_data)), ("Deezer", bool(deezer_data))) if condition}
    discovered_links = discover_platform_links(artist, title, barcode, known_sites, source_warnings)
    external_links = build_external_links(source_urls, mb_data, spotify_data, deezer_data, discovered_links)
    auto_sites = sorted({item["site"] for item in external_links if first(item.get("source")).startswith("自动发现")})
    if auto_sites:
        source_warnings.append({"source": "External links", "warning": f"下面来自 {'、'.join(auto_sites)} 的链接是按条码或标题自动检索到的（MusicBrainz 与输入链接都没给），提交前请打开确认是同一张发行"})
    apple_country = apple_country or apple_url_country
    external_links = add_derived_external_links(external_links, apple_id or first(apple_data.get("collection_id")), apple_country, source_urls, first(apple_data.get("url")))
    external_platform_search = platform_search_links(" ".join(item for item in [artist, title] if item), external_links)
    flaky_search_sites = platform_search_notes(external_platform_search)
    source_comparison = comparable_sources(apple_data, mb_data, page_summaries, extra_records)

    # 查重：MusicBrainz 里已经有这个条码的发行吗？（反向命中的那条本身也算）
    duplicates = mb_duplicate_releases(barcode, first(mb_data.get("release_mbid")))
    if reverse_used and first(mb_data.get("release_mbid")):
        duplicates.insert(0, {
            "release_mbid": first(mb_data.get("release_mbid")),
            "title": first(mb_data.get("title")),
            "artist": first(mb_data.get("artist")),
            "date": first(mb_data.get("date")),
            "country": first(mb_data.get("country")),
            "track_count": mb_data.get("track_count") or 0,
            "release_group_mbid": first(mb_data.get("release_group_mbid")),
            "linked_sites": sorted({site_info(item.get("url", ""))[0] for item in mb_data.get("external_urls") or [] if site_info(item.get("url", ""))[0]}),
            "url": f"https://musicbrainz.org/release/{mb_data.get('release_mbid')}",
        })
    seen_releases: set[str] = set()
    duplicates = [item for item in duplicates if not (item["release_mbid"] in seen_releases or seen_releases.add(item["release_mbid"]))]
    # 只比较我们能识别出平台名的那几条链接，避免把裸域名当成平台
    our_sites = sorted({site for item in external_links if (site := site_info(item["url"])[0])})
    for duplicate in duplicates:
        duplicate["missing_sites"] = [site for site in our_sites if site not in duplicate["linked_sites"]]
    if duplicates:
        source_warnings.append({"source": "Duplicate", "warning": f"MusicBrainz 里已经有同一个条码（{barcode}）的发行，先确认是不是同一张：{'、'.join(item['url'] for item in duplicates)}。若是同一张，请去那张发行上补链接与信息，不要重复建。"})

    # 发行事件：优先用 MusicBrainz 已有的，其次用 Deezer 抽样，最后回退到数字发行的默认值
    mb_events = mb_data.get("release_events") or []
    if mb_events:
        real_events = [event for event in mb_events if first(event.get("code")) != "XW"]
        release_events: dict[str, Any] = {
            "mode": "countries" if real_events else "worldwide",
            "date": first((real_events or mb_events)[0].get("date")) or date,
            "countries": real_events or [{"code": "XW", "name": "[Worldwide]", "date": first(mb_events[0].get("date")) or date}],
            "source": "MusicBrainz",
            "note": "直接来自 MusicBrainz 已有的 Release events。",
        }
    else:
        sampled, sampled_count = deezer_available_countries(deezer_data.get("tracks") or []) if deezer_data else ([], 0)
        if sampled:
            release_events = {
                "mode": "countries",
                "date": date,
                "countries": [{"code": code, "name": "", "date": date} for code in sampled],
                "source": f"Deezer 抽样 {sampled_count}/{len(deezer_data.get('tracks') or [])} 轨",
                "note": "Deezer 只在单曲接口给可用地区，这里的国家是抽样并集，提交前请与发行页核对。",
            }
            source_warnings.append({"source": "Release events", "warning": f"发行地区来自 Deezer 单曲接口的抽样（{sampled_count} 轨），逐轨可用地区不完全一致时要以发行页为准"})
        elif digital:
            release_events = {
                "mode": "worldwide",
                "date": date,
                "countries": [{"code": "XW", "name": "[Worldwide]", "date": date}],
                "source": "推断：数字发行",
                "note": "没查到逐国可用性；数字发行通常填 [Worldwide]，多国差异需人工确认。",
            }
        else:
            release_events = {"mode": "unknown", "date": date, "countries": [], "source": "", "note": "没有查到发行事件，请人工补齐。"}

    # 艺人解析：MusicBrainz 已经给了 MBID 的直接用，剩下的最多查 3 个名字
    known_artist_mbids: dict[str, str] = {}
    if artist and first(mb_data.get("artist_mbid")):
        known_artist_mbids[artist] = first(mb_data.get("artist_mbid"))
    for track in tracks:
        name, mbid = first(track.get("artist")), first(track.get("artist_mbid"))
        if name and mbid:
            known_artist_mbids.setdefault(name, mbid)
    artist_credits: list[dict[str, Any]] = [
        {"name": name, "mbid": mbid, "scope": "release" if name == artist else "track", "track": "", "source": "MusicBrainz", "candidates": []}
        for name, mbid in known_artist_mbids.items()
    ]
    pending_artists: list[tuple[str, str, str]] = []
    if artist and artist not in known_artist_mbids:
        pending_artists.append((artist, "release", ""))
    for track in tracks:
        name = first(track.get("artist"))
        if not name or name in known_artist_mbids or any(item[0] == name for item in pending_artists):
            continue
        pending_artists.append((name, "track", f"{first(track.get('disc')) or '1'}-{first(track.get('number'))}"))
        if len(pending_artists) >= 3:
            break
    for name, scope, slot in pending_artists[:3]:
        # 多艺人 credit（A & B / feat.）不能整体当一个艺人解析，否则会把 MBID 填错成主艺人
        joint = multi_credit_name(name)
        candidates = [] if joint else mb_artist_candidates(name)
        artist_credits.append({
            "name": name,
            "mbid": first((candidates[0] if candidates else {}).get("mbid")),
            "scope": scope,
            "track": slot,
            "source": "多艺人 credit：请拆成多个 Artist 逐个填 MBID，不要整体新建一个艺人" if joint else ("MB 艺人检索（需确认）" if candidates else ""),
            "candidates": candidates,
        })

    release_group_candidates = [] if first(mb_data.get("release_group_mbid")) else mb_release_group_candidates(title, artist)

    cover_sources: list[dict[str, str]] = []
    if first(apple_data.get("artwork_url")):
        cover_sources.append({"site": "Apple Music", "url": first(apple_data.get("artwork_url")), "note": "Apple 原图（4000×4000）"})
    if first(deezer_data.get("image")):
        cover_sources.append({"site": "Deezer", "url": first(deezer_data.get("image")), "note": "Deezer 原图（1400×1400）"})
    page_cover = next((first(item.get("image")) for item in page_summaries if first(item.get("image"))), "")
    if page_cover and page_cover not in {item["url"] for item in cover_sources}:
        cover_sources.append({"site": urlparse(page_cover).netloc, "url": page_cover, "note": "输入页面提供的封面"})
    cover_upload_url = f"https://musicbrainz.org/release/{first(mb_data.get('release_mbid'))}/add-cover-art" if first(mb_data.get("release_mbid")) else ""

    # Annotation 草稿：版权行 + 可用地区，可直接粘进发行注释
    copyright_lines: list[str] = []
    for line in [apple_copyright, *(spotify_data.get("copyrights") or [])]:
        text = first(line).strip()
        if text and text not in copyright_lines:
            copyright_lines.append(text)
    annotation_available = ""
    if release_events.get("countries"):
        annotation_available = f"== Countries where available ==\nSource: {release_events.get('source') or '未确认'} · As of {time.strftime('%Y-%m-%d')}.\n" + "".join(
            f"\n    * {country.get('name') or country.get('code')}" + (f" ({first(country.get('code')).casefold()})" if country.get("name") and first(country.get("code")) else "")
            for country in release_events["countries"]
        )
    annotation_copyright = "\n".join(line if line.startswith(("℗", "©")) else f"℗/© {line}" for line in copyright_lines)
    annotation = {
        "copyright": annotation_copyright,
        "available": annotation_available,
        "combined": "\n\n".join(part for part in [annotation_copyright, annotation_available] if part),
    }

    catalog_candidates = []
    if not catalog_number:
        for value, name in ((deezer_upc, "Deezer UPC"), (spotify_upc, "Spotify UPC")):
            if not value or value in {item["value"] for item in catalog_candidates}:
                continue
            catalog_candidates.append({"value": value, "source": name, "note": "mora 等商店对纯数字发行会把 UPC 直接当品番；去商店页确认显示的是同一个号后即可采用"})
    missing_fields = []
    if not catalog_number:
        hint = "补充 mora / OTOTOY 链接，或用下方辅助链接找到后贴回，也可手工填写"
        if catalog_candidates:
            hint = f"公开来源没有品番；本张的 UPC 是 {catalog_candidates[0]['value']}，mora 等商店常直接用它当品番，确认后可用下方候选一键填入"
        missing_fields.append({"field": "Catalog number", "hint": hint})
    if not barcode:
        missing_fields.append({"field": "Barcode", "hint": "查不到就勾选「无条码」，不要编造"})
    if not first(mb_data.get("release_mbid")):
        missing_fields.append({"field": "Release MBID", "hint": "MusicBrainz 里还没有这张发行，需要先人工建 Release"})
    if not page_label and not first(mb_data.get("label")) and not derived_imprint and not spotify_label:
        missing_fields.append({"field": "Label / imprint", "hint": "平台只给了版权方，厂牌（imprint）需要人工确认"})
    report = {
        "input": {"album_name": album_name, "url": primary_url, "urls": source_urls, "apple_id": apple_id, "deezer_id": deezer_id, "musicbrainz_release_id": release_id, "musicbrainz_release_group_id": release_group_id},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "confidence": {
            "overall": "low" if (source_errors or matched_by_title_only or not page_hint) else "medium",
            "notes": ["自动整理结果必须以发行页面、封面和官方 credits 人工核对后再提交 MusicBrainz。", compilation_note] + (["本次 MusicBrainz 匹配只用了标题，未使用艺人，存在同名误配风险。"] if matched_by_title_only else []) + (["输入链接页面未能成功解析，关键字段可能缺失，建议重试或补充其它来源链接。"] if not page_hint else []),
        },
        "release": {
            "title": title,
            "artist": artist,
            "artist_mbid": first(mb_data.get("artist_mbid")),
            "release_group": title,
            "primary_type": first(mb_data.get("primary_type")) or first(deezer_data.get("primary_type")) or "Album",
            "secondary_types": mb_data.get("secondary_types") or (["Compilation"] if is_compilation else []),
            "status": first(mb_data.get("status")) or "Official",
            "language": language,
            "script": script,
            "date": date,
            "country": country,
            "label": label,
            "catalog_number": catalog_number,
            "barcode": barcode,
            "barcode_status": ("已从 MusicBrainz 读取" if first(mb_data.get("barcode")) else "取自 Apple 封面文件名，需核对") if barcode else "未确认：不要编造，留空或勾选无条码",
            "packaging": "None" if digital else "",
            "format": "Digital Media" if digital else first(mb_data.get("format")),
            "cover_art_url": artwork_url,
            "cover_sources": cover_sources,
            "cover_upload_url": cover_upload_url,
            "musicbrainz_release_mbid": first(mb_data.get("release_mbid")),
            "musicbrainz_release_group_mbid": first(mb_data.get("release_group_mbid")),
        },
        "tracks": tracks,
        "sources": sources,
        "missing_fields": missing_fields,
        "duplicates": duplicates,
        "release_events": release_events,
        "annotation": annotation,
        "artist_credits": artist_credits,
        "release_group_candidates": release_group_candidates,
        "catalog_candidates": catalog_candidates,
        "external_links": external_links,
        "external_platform_search": external_platform_search,
        "external_platform_search_note": (
            f"{'、'.join(flaky_search_sites)} 的搜索页有防爬验证（可能显示 Access Denied 或人机校验），"
            "看到报错页刷新一次或换个网络再试，地址格式没问题。"
            if flaky_search_sites else ""
        ),
        "lookup_links": lookup_links,
        "source_comparison": source_comparison,
        "source_errors": source_errors,
        "source_warnings": source_warnings,
        "manual_review": [
            {"key": "artist_kind", "label": "确认是否应使用 Various Artists", "reason": "有明确主打艺人时通常不要误用 VA。"},
            {"key": "label_imprint", "label": "确认 Label 是 imprint 而非版权公司", "reason": "平台显示的版权方不一定等于 MusicBrainz 的厂牌字段。"},
            {"key": "artist_credits", "label": "逐轨检查 feat. / artist credit", "reason": "feat. 应放 Artist Credit，不要写入曲名；不要误改全专辑。"},
            {"key": "recordings", "label": "逐轨确认是否复用已有 Recording", "reason": "同艺人、同标题、时长吻合才复用；拿不准宁可新建。"},
            {"key": "works", "label": "补 Work、作词/作曲和制作关系", "reason": "自动查询到的 credits 需要挂到正确的 Work 或 Recording。"},
            {"key": "iswc", "label": "ISWC / 著作权登记号", "reason": "查不到就留空，不要从别的歌曲复制。"},
            {"key": "cover", "label": "确认封面是该数字发行的原图", "reason": "禁止 AI 放大、裁剪、加水印或使用粉丝制作图。"},
        ],
        "edit_notes": {
            "release": f"Digital release preparation for {title} by {artist}.\n\nSources:\n" + "\n".join(f"- {item.get('url')}" for item in sources if item.get("url")) + "\n\nAutomatically collected fields require manual verification before submission. Barcode was left blank when no reliable public value was found.",
            "work": f"Work/recording credit follow-up for {title}.\n\nUse only credits confirmed by the linked official or authorized source. Leave ISWC and collecting-society IDs blank when they cannot be verified.",
            "cover": f"Front cover taken from the release's own digital artwork source (unmodified):\n{artwork_url}" if artwork_url else "Front cover source still needs to be confirmed.",
        },
        "api_notes": [
            "MusicBrainz read API requires a meaningful User-Agent and should be throttled to no more than one request per second per application.",
            "This tool only prepares data; it does not submit edits to MusicBrainz.",
            *([cache_hit_note()] if cache_hit_note() else []),
        ],
    }
    return report


# POST 体上限：正常请求就是几个链接加几个字段，1 MiB 已经非常宽裕；
# 原来没有上限，谁都能一次灌几百 MB 进内存
MAX_REQUEST_BODY = 1 << 20


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_plain(self, status: int, message: str, extra_headers: dict[str, str] | None = None) -> None:
        data = (message + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def read_json_body(self) -> dict[str, Any] | None:
        """读并解析请求体；非法 Content-Length / 超大 / 非 JSON / 非对象都回 4xx 并返回 None。

        原来直接 `int(self.headers.get("Content-Length", "0"))`：
          · `Content-Length: abc` 抛 ValueError，而它不在 except 里 → handler 线程
            直接 traceback、连接挂断，而不是干净的 400；
          · `Content-Length: -1` 会让 read(-1) 变成「读到连接关闭为止」，
            可以慢慢吊住一个连接；
          · 也没有上限，有鉴权（或没配限流）时可以一次灌几百 MB 进内存。
        """
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            self.send_json({"error": "Content-Length 不是合法数字"}, 400)
            return None
        if length < 0:
            self.send_json({"error": "Content-Length 不能为负数"}, 400)
            return None
        if length > MAX_REQUEST_BODY:
            # 体不读了，直接断开：别让残留的字节被当成下一个请求
            self.close_connection = True
            self.send_json({"error": f"请求体过大（上限 {MAX_REQUEST_BODY} 字节）"}, 413)
            return None
        if not length:
            return {}
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json({"error": "请求体不是合法 JSON"}, 400)
            return None
        if not isinstance(body, dict):
            self.send_json({"error": "请求体应为 JSON 对象"}, 400)
            return None
        return body

    def send_internal_error(self, action: str, exc: BaseException) -> None:
        """500 的错误详情只进服务端日志。

        原来把 `f"查询失败：{exc}"` 直接回给客户端，异常原文里可能带着上游报错、
        内网主机名和路径。本地回环部署仍然返回详情（排查方便），对外监听时
        只回一句「详情见服务端日志」。
        """
        print(f"[error] {action}失败：{exc!r}", file=sys.stderr, flush=True)
        detail = f"：{exc}" if DETAIL_IN_ERRORS else "（详情见服务端日志）"
        self.send_json({"error": f"{action}失败{detail}"}, 500)

    def require_access(self) -> bool:
        """鉴权与限流的总闸。返回 True 才能继续；否则已经回过 401/429，调用方直接 return。

        认证**不挡静态资源**：前端 shell（public/ 与 /app.js、/styles.css）必须
        无需凭据即可加载，否则自定义登录页无从呈现。认证只覆盖 /api/* 数据入口
        （真正会泄漏数据、或作为开放代理扇出到上游的部分）；/api/health 与
        /api/login 豁免 —— 前者是健康探针（响应里带 auth 标志供前端探测），
        后者是登录入口，凭据在 do_POST 内自行校验。
        401 不再携带 WWW-Authenticate 头：那会触发浏览器原生 Basic 弹窗，
        自定义登录页依赖的是普通 401 响应。
        限流（见下）只覆盖 /api/*。
        """
        path = urlparse(self.path).path
        if path == "/api/health" or path == "/api/login":
            return True
        if AUTH_HEADER and path.startswith("/api/"):
            supplied = self.headers.get("Authorization", "").encode("utf-8")
            # 常量时间比较，避免按字符逐位泄漏口令信息（成本为零，没有理由不用）
            if not hmac.compare_digest(supplied, AUTH_HEADER.encode("utf-8")):
                self.send_json(
                    {"error": "unauthorized", "message": "未认证或凭据无效"},
                    401,
                )
                return False
        # 限流只盯 /api/*：静态资源是一次本地读盘、不扇出到上游，限它只会让
        # 「刷新一下页面」就吃掉配额；真正会把额度打光的是 /api/lookup 那一串外部请求。
        if path.startswith("/api/") and not rate_limit_allow(self.client_address[0]):
            self.send_plain(
                429,
                f"请求过于频繁：每 {RATE_LIMIT_WINDOW} 秒最多 {RATE_LIMIT_MAX} 次，请稍后再试。",
                {"Retry-After": str(RATE_LIMIT_WINDOW)},
            )
            return False
        return True

    def handle_login(self, body: dict[str, Any]) -> None:
        """自定义登录页的凭据校验（POST /api/login）。成功 200；失败 401。

        优先读 Authorization: Basic 头（前端登录页按此方式提交），其次读
        JSON body 的 username/password，两种提交方式都支持。未启用认证时
        返回 auth:false，前端据此直接隐藏登录层。
        """
        if not AUTH_HEADER:
            self.send_json({"ok": True, "auth": False, "message": "未启用认证"})
            return
        supplied = self.headers.get("Authorization", "").encode("utf-8")
        if hmac.compare_digest(supplied, AUTH_HEADER.encode("utf-8")):
            self.send_json({"ok": True, "auth": True})
            return
        username = first(str(body.get("username", ""))).strip()
        password = str(body.get("password", ""))
        candidate = "Basic " + base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        if hmac.compare_digest(candidate.encode("utf-8"), AUTH_HEADER.encode("utf-8")):
            self.send_json({"ok": True, "auth": True})
        else:
            self.send_json({"error": "用户名或密码错误"}, 401)

    def send_file(self, path: Path, content_type: str) -> None:
        data = path.read_bytes()
        if content_type.startswith("text/html"):
            # 版本注入：index.html 徽标里的 __VERSION__ 占位符换成当前版本；
            # 页面没有占位符时 replace 是无操作，不会出错。
            # 进 HTML 前先过 html.escape：版本号来源虽是 CI 校验过的 SemVer 标签，
            # 但本地环境变量可任意设置，转义是零成本的防线（代码审查任务 1 的前瞻建议）
            data = data.replace(b"__VERSION__", escape(VERSION).encode("utf-8"))
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if not self.require_access():
            return
        if urlparse(self.path).path == "/api/health":
            self.send_json({"ok": True, "service": "Sleeve", "version": VERSION, "auth": bool(AUTH_HEADER)})
            return
        route = urlparse(self.path).path

        # 前端脚本与样式：路径取自写死的白名单，不拼接任何用户输入。
        frontend = FRONTEND_ASSETS.get(route)
        if frontend:
            asset = SRC_DIR / frontend[0]
            if asset.is_file():
                self.send_file(asset, frontend[1])
            else:
                self.send_json({"error": "Not found"}, 404)
            return

        # 其余一切从 public/ 取。
        #
        # ⚠ 必须 resolve() 之后再判断包含关系。原来写的是
        #   `target.exists() and target.is_file() and ROOT in target.parents`
        # 而那是**字符串**层面的比较 —— Path 不会规范化 ".."，于是
        # 'public/../Dockerfile'.parents 里确实含有 'public'，判断照样通过。
        # 实测（未修前）：/../README.md、/../.gitignore、/../.git/config 全部 200，
        # 连 /../../../../../../../../Windows/win.ini 都能读到 —— 相当于无鉴权的
        # 任意文件读取。resolve() 会规范化 ".." 与符号链接，再比包含关系才算真越界检查。
        try:
            candidate = (ROOT / ("index.html" if route in ("/", "") else route.lstrip("/"))).resolve()
            inside = candidate.is_file() and candidate.is_relative_to(ROOT.resolve())
        except (OSError, ValueError):
            # 路径里带 NUL 之类会让 Path 直接抛错，不能让它变成 500
            inside = False
        if inside:
            self.send_file(candidate, STATIC_CONTENT_TYPES.get(candidate.suffix.lower(), "application/octet-stream"))
            return
        self.send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        if not self.require_access():
            return
        path = urlparse(self.path).path
        body = self.read_json_body()
        if body is None:
            return
        if path == "/api/login":
            self.handle_login(body)
            return
        if path == "/api/search":
            album_name = first(body.get("album_name")).strip()
            artist_name = first(body.get("artist_name")).strip()
            if not album_name and not artist_name:
                self.send_json({"error": "请填写专辑名或艺人名"}, 400)
                return
            try:
                self.send_json(search_candidates(album_name, artist_name))
            except Exception as exc:
                self.send_internal_error("搜索", exc)
            return
        if path != "/api/lookup":
            self.send_json({"error": "Not found"}, 404)
            return
        try:
            album_name = first(body.get("album_name")).strip()
            input_url = first(body.get("url")).strip()
            input_urls = body.get("urls")
            manual_catalog = first(body.get("catalog")).strip()
            artist_name = first(body.get("artist_name")).strip()
            source_urls = split_source_urls(input_urls if input_urls is not None else input_url)
            if not album_name and not source_urls:
                source_urls = split_source_urls(body.get("album_name") or body.get("url") or "")
            if not album_name and not artist_name and not source_urls:
                self.send_json({"error": "请填写链接，或填写专辑名/艺人名后从候选结果中选择"}, 400)
                return
            self.send_json(build_report(album_name, input_url, input_urls, manual_catalog, artist_name))
        except Exception as exc:
            self.send_internal_error("查询", exc)


class Server(ThreadingHTTPServer):
    # Windows 的 SO_REUSEADDR 语义和 Linux 不同：它允许两个进程绑定同一个端口，
    # 于是「改了代码 → 重启」时后启动的实例会静默失败，请求仍然由旧进程处理。
    # 宁可启动就报错，也不要让人对着旧版本排查半天。
    allow_reuse_address = os.name != "nt"


if __name__ == "__main__":
    print(f"Sleeve running at http://{HOST}:{PORT}", flush=True)
    try:
        Server((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        # Ctrl+C 直接打断 serve_forever() 时会抛 KeyboardInterrupt；
        # 不接住的话终端会甩一大段 Traceback，看起来像程序崩了。
        # 这里接住并给一句明确的退出提示（ThreadingHTTPServer 的
        # daemon_threads=True，请求线程不会拖住进程退出）。
        print("\nSleeve 已停止（Ctrl+C）", flush=True)
    except OSError as exc:
        print(f"启动失败：{exc}")
        print(f"端口 {PORT} 上似乎已经有实例在运行。请先结束旧进程：")
        print(f"  netstat -ano | findstr :{PORT}      # 记下最后一列的 PID")
        print(f"  taskkill /F /PID <PID>")
        raise SystemExit(1)
