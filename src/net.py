"""出网：缓存、重试、SSRF 闸门、并发抓取。

这个模块是 app.py 里最该先抽出来的一块 —— 它是唯一额外交互面（网络），
也几乎全部测试的接缝都在这里（`patch_seam` 打补丁最多的就是 fetch_json）。

顺序上刻意保持「闸门 → 缓存 → 请求」：URL 要过 check_outbound 才能出网，
出网前先查缓存，缓存未命中才真正发请求。读代码时这个顺序就是实际执行顺序。

三个不属于「业务」但必须和出网绑在一起的东西也在这里：

  * IPv4 优先的 getaddrinfo 补丁 —— IPv6 解析得到、连不通的网络环境下，
    urllib 会把整个超时耗在死路上，重试叠加后单次调用能拖到 80 秒以上。
  * GuardedRedirectHandler —— 3xx 跳转也要过 SSRF 检查，否则
    「先给个公网地址，再 302 到 127.0.0.1」就能绕过 check_outbound。
  * 并发抓取的缓存计数汇总 —— 见 merge_cache_stats 的注释。
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from itertools import count
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import HTTPError, URLError
from uuid import uuid4

# 上游模块（拆分前这些是 app.py 里的同级定义）
from sites import site_info
from version import USER_AGENT


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

    但线程局部在**线程池**里会失效：并行抓多个来源时，命中计数记在 worker 线程
    自己的副本上，请求线程读到的一直是 0 —— 报告里「本次有 N 个命中缓存」整条消失。
    所以并行场景下 worker 必须把计数带回来，由请求线程汇总（见 merge_into）。
    """

    def __init__(self) -> None:
        self.hit = 0
        self.miss = 0

    def snapshot(self) -> tuple[int, int]:
        return (self.hit, self.miss)

    def merge_into(self, other: CacheStats) -> None:
        """把另一个计数器的增量并进来（worker → 主线程汇总用）。"""
        other.hit += self.hit
        other.miss += self.miss


CACHE_STATS = CacheStats()


def ensure_cache_dir() -> None:
    """建缓存目录，并收紧权限。

    缓存默认落在系统公共临时目录（/tmp/sleeve-cache）。多用户共享的主机上，
    公共目录里的缓存文件可能被同机的其他本地用户读取或篡改 —— 而缓存内容
    是出网请求的响应，篡改它等于让报告出现**看似合法的错误数据**。

    非 Windows 上显式设 0o700（仅属主可读写）。Windows 没有 POSIX 权限位，
    靠 ACL 控制，跳过即可（容器里跑在 appuser 上，卷权限由 Dockerfile 保证）。

    幂等：权限已经对时不再重复 chmod（每次写缓存都调它，stat 比 chmod 便宜得多）。
    """
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            return
        mode = CACHE_DIR.stat().st_mode & 0o777
        if mode != 0o700:
            os.chmod(CACHE_DIR, 0o700)
    except OSError:
        # 目录建不出来 / 改不了权限：缓存只是加速手段，不该让服务起不来
        pass


PARALLEL_FETCH_MAX_WORKERS = 6


class _FetchOutcome:
    """一个并行任务的结果：值 + 该 worker 线程的缓存计数增量。"""

    __slots__ = ("value", "error", "hit_delta", "miss_delta")

    def __init__(self, value: Any, error: Exception | None, hit_delta: int, miss_delta: int) -> None:
        self.value = value
        self.error = error
        self.hit_delta = hit_delta
        self.miss_delta = miss_delta


def _run_one(task: Any) -> _FetchOutcome:
    """在 worker 线程里跑一个任务，并把该线程的缓存计数增量带回来。

    CACHE_STATS 是 threading.local，worker 线程天然有一份独立的副本 ——
    正因为如此，命中数必须显式带回主线程，否则统计会静默变成 0。

    只捕获 Exception（不捕获 BaseException）：KeyboardInterrupt / SystemExit
    应当继续往外抛，由主线程处理，不能在 worker 里被吞掉。
    """
    before = CACHE_STATS.snapshot()
    try:
        value = task()
        error: Exception | None = None
    except Exception as exc:  # noqa: BLE001 - 单个来源失败不该拖垮整次查询
        value = None
        error = exc
    after = CACHE_STATS.snapshot()
    return _FetchOutcome(value, error, after[0] - before[0], after[1] - before[1])


def run_parallel(tasks: list[Any]) -> list[_FetchOutcome]:
    """并行跑一批互不依赖的任务，返回与入参同序的结果。

    失败不抛异常：单个来源挂了就返回 error，由调用方决定是降级还是记警告 ——
    这与串行版各来源各自 try/except 的语义一致。
    """
    if not tasks:
        return []
    if len(tasks) == 1:
        return [_run_one(tasks[0])]
    workers = min(PARALLEL_FETCH_MAX_WORKERS, len(tasks))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sleeve-fetch") as executor:
        return list(executor.map(_run_one, tasks))


def merge_cache_stats(deltas: list[tuple[int, int]]) -> None:
    """把各 worker 的缓存计数增量汇总到当前（请求）线程。

    没有这一步，并行抓取会让「本次有 N 个命中缓存」永远显示不出来。
    """
    for hit_delta, miss_delta in deltas:
        CACHE_STATS.hit += hit_delta
        CACHE_STATS.miss += miss_delta


def cache_key(kind: str, url: str, body: str = "") -> str:
    return hashlib.sha1(f"{kind}|{url}|{body}".encode()).hexdigest()


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
        ensure_cache_dir()
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


def fetch_json(url: str, headers: dict[str, str] | None = None, timeout: int = 20, retries: int = 2, before_attempt: Any = None) -> Any:
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
        # 每次**真正发起**请求前都要过一遍闸（before_attempt）。
        # 重试也是一次真实的出网请求：限速必须覆盖重试，否则「503 → 立刻重试」
        # 会绕过限速闸，和别的线程的请求撞在一起。
        if before_attempt is not None:
            before_attempt()
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


