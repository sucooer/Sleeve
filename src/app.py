from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import os
import re
import sys
import threading
import time
from collections import Counter
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlparse

SRC_DIR = Path(__file__).resolve().parent
ROOT = SRC_DIR.parent / "public"
HOST = os.environ.get("SLEEVE_HOST", "127.0.0.1")
PORT = int(os.environ.get("SLEEVE_PORT", "8765"))

# ------------------------------------------------------------------ 模块拆分
#
# 单文件已经到 4000+ 行，继续往一个文件里加代码的边际成本已经明显为负：
# 改一张 URL 规则表要跨一千多行来回跳，审阅一个功能要在一整屏无关代码里找。
# 按关注点往外抽模块，app.py 保留**门面**（下面这些 re-export）——
# `app.X` 依旧可用，测试与调用方一行都不用改。
#
# 放在这里而不是文件开头，是刻意让每个 import 落在「它替代的那段代码原址」，
# 这样读 app.py 的人一眼能看出「这东西现在住在别处」，而不是在顶部堆成一片
# 看不出所以然的 import 墙。
# 门面：version 模块已移至 version.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from version import (  # noqa: E402,F401
    USER_AGENT,
    VERSION,
    resolve_version,
)

# 门面：musicbrainz 模块已移至 musicbrainz.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from musicbrainz import (  # noqa: E402,F401
    MAX_WORK_RELS_TRACKS,
    MAX_WORK_RELS_WORKS,
    MB_BASE,
    MB_LAST_REQUEST,
    MB_LOCK,
    MULTI_CREDIT_RE,
    barcode_from_artwork,
    extract_mbids,
    is_valid_ean,
    language_script,
    mb_artist_candidates,
    mb_artist_credit,
    mb_duplicate_releases,
    mb_query_escape,
    mb_release_events,
    mb_release_group_candidates,
    mb_release_sites,
    mb_request,
    mb_reverse_release_ids,
    mb_search_artist,
    mb_search_recording,
    mb_tracks,
    mb_work_relation_artist,
    mb_work_rels_for_recording,
    multi_credit_name,
    normalize_mb_release,
    single_credit_mbid,
)

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

# 出网、缓存、并发抓取搬到 net.py 了（含 IPv4 优先的 getaddrinfo 补丁）。
# 这里只列出 app.py 自己还在用的名字 —— 门面不需要把 net.py 的每个内部细节
# 都再暴露一遍，多余的 re-export 只会让「谁在用这个」更难查。
# 测试要打补丁的内部名（_run_one / _FetchOutcome / CACHE_STORE_*）一律直接
# patch 到 net 模块上，不经 app。
# 门面：net 模块已移至 net.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from net import (  # noqa: E402,F401
    ALLOW_ANY_USER_HOST,
    CACHE_DIR,
    CACHE_ENABLED,
    CACHE_STATS,
    CACHE_STORE_COUNT,
    CACHE_STORE_SWEEP_EVERY,
    CACHE_SWEEP_LOCK,
    CACHE_TTL,
    CacheStats,
    FetchError,
    GUARDED_OPENER,
    GuardedRedirectHandler,
    PARALLEL_FETCH_MAX_WORKERS,
    RETRYABLE_HTTP_STATUS,
    address_is_public,
    ascii_url,
    cache_hit_note,
    cache_key,
    cache_load,
    cache_store,
    cache_sweep_expired,
    cache_usable,
    check_outbound,
    ensure_cache_dir,
    fetch_json,
    fetch_text,
    is_permanent_failure,
    is_timeout_failure,
    merge_cache_stats,
    post_json,
    run_parallel,
    sweep_cache_once_in_a_while,
)

# ------------------------------------------------------------------ 并行抓取
#
# 一次专辑查询要扇出到好几个互不相干的来源（用户贴的商店页、iTunes、Spotify、
# Deezer），它们各自独立、互不依赖，串行等着就是白等 —— 慢的那个决定总时长。
#
# 但**并行是有前提的**，不能照着「这些源互不依赖」想当然：
#   1) Apple（itunes_album_by_id）**依赖**其它源的 artist_hint / title_hint ——
#      它的整单区域切换（链接区 → JP 区 → 美区）就是拿 artist_hint 跟各区返回的
#      艺人名比对的。artist_hint 为空时整条判据失效，日文专辑会被错误丢弃或污染。
#      所以 Apple 必须放到**第二阶段**，等其它源的结果齐了再查。
#   2) CACHE_STATS 是线程局部的：worker 线程里的命中计数记在 worker 自己的副本上，
#      请求线程读到的一直是 0，报告里「本次有 N 个命中缓存」整条消失。
#      所以 worker 必须把自己那份计数带回来，由请求线程汇总。
#   3) MusicBrainz 有 1 req/s 的硬限制，**绝不能**放进线程池并发打，
#      MB 的限速与锁见 mb_request。

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

# 认证有效期（秒）：登录后超过该时长需要重新认证。默认 12 小时；0 = 永不过期。
# 服务端是无状态 Basic 校验，本身没有「会话」概念；TTL 作为约定下发给前端，
# 前端把登录时间戳与 TTL 一起保存，到点自动清除本地凭据并回到登录页。
# 未设置时沿用默认 12h（安全管理上，不设 = 永不过期是一个坑）。
AUTH_TTL_DEFAULT = 12 * 60 * 60


def parse_auth_ttl(raw: str | None) -> int:
    """解析 SLEEVE_AUTH_TTL：未设置 / 空串 / 非法值一律回落默认 12h；显式 "0" 才是永不过期。

    空串必须走默认值：`SLEEVE_AUTH_TTL=` 这种「写了但没填」的配置很常见，
    当成 0 就等于悄悄把凭据改成永不过期，正好与上一行的约定相反。
    """
    text = (raw or "").strip()
    if not text:
        return AUTH_TTL_DEFAULT
    try:
        return int(text)
    except ValueError:
        print(f"[warn] SLEEVE_AUTH_TTL 应为秒数，忽略当前值「{text}」，使用默认 {AUTH_TTL_DEFAULT}。", flush=True)
        return AUTH_TTL_DEFAULT


AUTH_TTL = parse_auth_ttl(os.environ.get("SLEEVE_AUTH_TTL"))

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


# 门面：values 模块已移至 values.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from values import (  # noqa: E402,F401
    MB_PLACEHOLDERS,
    TITLE_SUFFIX_RE,
    clean_value,
    first,
    format_duration,
    iso_date,
    named_text,
    normalize_mb_url,
    title_is_related,
    title_match_key,
)
# 门面：itunes 模块已移至 itunes.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from itunes import (  # noqa: E402,F401
    CREDIT_SECTION_KEYS,
    WAF_FLAKY_SITES,
    apple_storefront_chain,
    choose_itunes_candidate,
    collect_apple_credits,
    extract_apple_country,
    extract_apple_id,
    extract_apple_song_id,
    itunes_album_by_id,
    itunes_album_from_song,
    itunes_artist_albums,
    normalize_itunes,
    parse_apple_credits,
)

# 门面：spotify 模块已移至 spotify.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from spotify import (  # noqa: E402,F401
    SPOTIFY_API_BASE,
    SPOTIFY_CLIENT_ID,
    SPOTIFY_CLIENT_SECRET,
    SPOTIFY_PROXY_BASE,
    SPOTIFY_PROXY_HEADERS,
    SPOTIFY_TOKEN_CACHE,
    SPOTIFY_TOKEN_URL,
    extract_spotify_id,
    extract_spotify_track_id,
    item_isrc,
    spotify_album,
    spotify_api_get,
    spotify_auth_headers,
    spotify_configured,
    spotify_normalize_album,
    spotify_related_rows,
    spotify_search,
    spotify_track,
)

# 门面：deezer 模块已移至 deezer.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from deezer import (  # noqa: E402,F401
    DEEZER_BASE,
    DEEZER_TYPE_MAP,
    barcode_is_plausible,
    deezer_album,
    deezer_album_by_upc,
    deezer_album_matches,
    deezer_available_countries,
    deezer_cover_large,
    deezer_error,
    deezer_track,
    deezer_track_rows,
    extract_deezer_track_id,
)

def detect_song_url(url: str) -> dict[str, str]:
    """识别「单曲链接」并给出平台标识；专辑 / 播放列表 / 其他页面返回 {}。

    单曲报告（build_song_report）与专辑报告的信息几乎不重叠，各平台 track
    链接都应路由到单曲报告。平台返回值：apple / spotify / deezer。
    """
    if "apple.com" in urlparse(url or "").netloc.lower():
        apple_song = extract_apple_song_id(url)
        if apple_song and not extract_apple_id(url):
            return {"source": "apple", "track_id": apple_song}
        return {}
    spotify_id = extract_spotify_track_id(url)
    if spotify_id:
        return {"source": "spotify", "track_id": spotify_id}
    deezer_id = extract_deezer_track_id(url)
    if deezer_id:
        return {"source": "deezer", "track_id": deezer_id}
    return {}


# 门面：soundcharts 模块已移至 soundcharts.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from soundcharts import (  # noqa: E402,F401
    SONOVAULT_API_KEY,
    SONOVAULT_BASE,
    SOUNDCHARTS_API_KEY,
    SOUNDCHARTS_APP_ID,
    SOUNDCHARTS_BASE,
    SOUNDCHARTS_CLIENT_ID,
    SOUNDCHARTS_CLIENT_SECRET,
    SOUNDCHARTS_PLATFORMS,
    SOUNDCHARTS_TOKEN_CACHE,
    SOUNDCHARTS_TOKEN_URL,
    collect_usage_status,
    sonovault_track_search,
    soundcharts_auth_headers,
    soundcharts_configured,
    soundcharts_song_by_platform_id,
    soundcharts_team_usage,
)


# 门面：parsers 模块已移至 parsers.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from parsers import (  # noqa: E402,F401
    catalog_from_url,
    extract_catalog,
    extract_date_text,
    extract_deezer_id,
    html_meta,
    json_ld_summary,
    parse_apple_html,
    parse_bandcamp_html,
    parse_iso_duration,
    parse_mora_html,
    parse_ototoy_html,
    source_page_summary,
    strip_html,
)

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


# 门面：sites 模块已移至 sites.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from sites import (  # noqa: E402,F401
    PUBLIC_SUFFIX_TAIL_RE,
    URL_SITE_RULES,
    host_matches_site_rule,
    site_info,
)


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


# ---------------------------------------------------------------------------
# Work relationships：只查询、只展示；建库（建 Work / 挂关系）由人工在 MusicBrainz 完成
# ---------------------------------------------------------------------------

def build_work_relations(tracks: list[dict[str, Any]], apple_credits: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """逐轨查询 MusicBrainz 的 work relationships，并合并 Apple 页面 Credits，产出报告区块数据。

    用途是给「新建/核对 Work 与 Recording 关系」人工操作当参考：
      - apple_credits：Apple Music 页面 Credits（作曲/作词/制作/表演），**不依赖 MB**，
        即使 MB 尚无该发行也照常给出 —— 这正是建一个「MB 里还不存在的 work」时需要的资料；
      - MB 查询：仅当本发行匹配到 MB 且曲目有 recording_mbid 时执行，展示现有关联供核对。

    只查询、绝不提交：MusicBrainz 的编辑必须登录账号由人工完成。查失败不阻塞报告。
    """
    apple_credits = apple_credits or []
    recorded = [track for track in tracks if track.get("recording_mbid")]
    if not recorded:
        if apple_credits:
            return {
                "status": "credits_only",
                "notice": "MB 尚无此曲目的 recording（或本发行未匹配到 MusicBrainz），无法查现有关联；已从 Apple Music 页面抓到 Credits，可直接作为新建 Work / Recording 时挂 relationship 的依据。",
                "items": [], "query_count": 0, "failed": 0, "limited": 0,
                "work_count": 0, "relation_count": 0,
                "apple_credits": apple_credits,
                "markdown": work_relations_markdown([], apple_credits),
            }
        return {
            "status": "skipped",
            "notice": "没有可查询的 recording：本发行未匹配到 MusicBrainz，且 Apple 页面也没有抓到该曲目的 Credits。先建好 Release / 补贴歌曲页链接后再来。",
            "items": [], "query_count": 0, "failed": 0, "limited": 0,
            "work_count": 0, "relation_count": 0, "apple_credits": [],
            "markdown": "",
        }
    items: list[dict[str, Any]] = []
    queried = 0
    failed = 0
    limited = 0
    for track in recorded:
        if queried >= MAX_WORK_RELS_TRACKS:
            limited += 1
            continue
        queried += 1
        entry = {
            "track": first(track.get("title")),
            "recording_mbid": track.get("recording_mbid"),
            "recording_url": f"https://musicbrainz.org/recording/{track.get('recording_mbid')}",
            "works": [],
            "recording_relations": [],
            "error": "",
        }
        try:
            result = mb_work_rels_for_recording(track["recording_mbid"])
        except FetchError as exc:
            entry["error"] = str(exc)
            failed += 1
            items.append(entry)
            continue
        entry["works"] = result["works"]
        entry["recording_relations"] = result["recording_relations"]
        items.append(entry)
    work_count = sum(len(item["works"]) for item in items)
    relation_count = sum(len(item["works"]) + len(item["recording_relations"]) for item in items)
    parts = []
    if items:
        parts.append(f"已查询 {len(items)} 首曲目的 recording，找到 {work_count} 个 work、{relation_count} 条关系")
    if failed:
        parts.append(f"{failed} 首查询失败")
    if limited:
        parts.append(f"{limited} 首超出查询预算（单次最多 {MAX_WORK_RELS_TRACKS} 首），请在 MusicBrainz 页面人工确认")
    status = "ok" if items and not failed and not limited else ("partial" if items else "failed")
    return {
        "status": status,
        "notice": ("；".join(parts) or "没有查到任何 work 关系。") + ("。另有 Apple Music 页面 Credits 一并列出，供交叉核对。" if apple_credits else ""),
        "items": items,
        "query_count": queried,
        "failed": failed,
        "limited": limited,
        "work_count": work_count,
        "relation_count": relation_count,
        "apple_credits": apple_credits,
        "markdown": work_relations_markdown(items, apple_credits),
    }


def work_relations_markdown(items: list[dict[str, Any]], apple_credits: list[dict[str, Any]] | None = None) -> str:
    """把 Apple Credits + MB 现有关联转成可复制进编辑说明的 Markdown。"""
    lines: list[str] = []
    for credit in apple_credits or []:
        lines.append(f"### {credit.get('track') or '(歌曲)'} — Apple Music Credits（来源 {credit.get('source_url') or ''}）")
        for group in credit.get("groups") or []:
            lines.append(f"- **{group.get('title') or group.get('id')}**")
            for item in group.get("items") or []:
                roles = "、".join(item.get("roles") or [])
                lines.append(f"  - {item.get('name')}" + (f"（{roles}）" if roles else ""))
        lines.append("")
    for item in items:
        lines.append(f"### {item.get('track') or '(无标题)'} — recording `{item.get('recording_mbid') or ''}`")
        if item.get("error"):
            lines.append(f"- 查询失败：{item['error']}")
            continue
        for rel in item.get("recording_relations") or []:
            mbid = f" ({rel.get('artist_mbid')})" if rel.get("artist_mbid") else ""
            lines.append(f"- (recording) {rel.get('type') or '?'}: {rel.get('artist') or ''}{mbid}")
        for work in item.get("works") or []:
            suffix = f" [{work.get('iswc')}]" if work.get("iswc") else ""
            lines.append(f"- Work: {work.get('title') or '(无标题 work)'} ({work.get('type') or '类型未确认'}){suffix} `{work.get('mbid') or ''}`")
            for rel in work.get("relations") or []:
                attr = f"（{', '.join(rel.get('attributes') or [])}）" if rel.get("attributes") else ""
                mbid = f" ({rel.get('artist_mbid')})" if rel.get("artist_mbid") else ""
                lines.append(f"  - {rel.get('type') or '?'}: {rel.get('artist') or ''}{attr}{mbid}")
        if not item.get("works") and not item.get("recording_relations") and not item.get("error"):
            lines.append("- 无关联 work（建 Work 时注意别与已有同名词条重复）")
    if not lines:
        return ""
    return "\n".join(lines).rstrip() + "\n\n以上为自动查询/抓取结果，必须逐条人工核对后再挂载；ISWC 查不到就留空。"

# ---------------------------------------------------------------------------
# Lyrics URL relationship 候选：MB 的 lyrics relationship 只允许白名单站点
# ---------------------------------------------------------------------------

LYRIC_SITE_INTERNATIONAL = (
    {"name": "Genius", "url": "https://genius.com/search?q={q}"},
    {"name": "Musixmatch", "url": "https://www.musixmatch.com/search/{q}"},
    {"name": "LyricsTranslate", "url": "https://lyricstranslate.com/en/search?q={q}"},
)
LYRIC_SITE_JAPANESE = (
    {"name": "J-Lyric.net", "url": "https://search.j-lyric.net/index.php?kt={q}&ct=2"},
    {"name": "Uta-Net", "url": "https://www.uta-net.com/search/?Keyword={q}"},
    {"name": "UtaMap", "url": "https://www.utamap.com/searchkasi.php?searchname={q}&act=search"},
    {"name": "UtaTen", "url": "https://utaten.com/search?keyword={q}"},
)
JAPANESE_TEXT_RE = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf]")
MAX_LYRICS_CANDIDATE_TRACKS = 12


def looks_japanese(text: str) -> bool:
    """标题/艺人含日文假名或 CJK 扩展区时，追加日文歌词站候选。"""
    return bool(JAPANESE_TEXT_RE.search(text or ""))


def lyrics_search_candidates(track_title: str, artist: str) -> list[dict[str, str]]:
    """为单曲构造 MB lyrics relationship 白名单站点的歌词搜索链接。

    输出的是各站「搜索页」直达链接——用户进站确认最终歌词页后，把那条 URL
    挂到 Work / Recording 的 lyrics relationship 上即可（白名单外站点会被 MB 拒绝）。
    纯离线构造，不触发任何网络请求。
    """
    query = quote(f"{track_title} {artist}".strip())
    if not track_title or not query:
        return []
    sites = list(LYRIC_SITE_INTERNATIONAL)
    if looks_japanese(f"{track_title} {artist}"):
        sites += LYRIC_SITE_JAPANESE
    return [{"site": site["name"], "url": site["url"].format(q=query), "whitelisted": True} for site in sites]


def lyrics_candidates_for_tracks(tracks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """逐曲生成 lyrics 候选；超过预算的曲目跳过（提示人工）。

    只生成不抓取：白名单站点普遍有 WAF，自动解析留给部署环境验证后可做增强。
    """
    items: list[dict[str, Any]] = []
    for track in tracks[:MAX_LYRICS_CANDIDATE_TRACKS]:
        title = first(track.get("title")) or ""
        artist = first(track.get("artist")) or ""
        if not title:
            continue
        links = lyrics_search_candidates(title, artist)
        if not links:
            continue
        items.append({"track": title, "artist": artist, "links": links})
    return items


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


def song_recording_edit_note(
    song: dict[str, Any],
    recording: dict[str, Any],
    source_urls: list[str],
    isrc_provenance: str = "",
    apple_credits: list[dict[str, Any]] | None = None,
) -> str:
    """单曲模式的 Recording Edit note 草稿。

    专辑模式那边已经是 MB 社区通行的「Action + Sources」写法（见 build_report
    的 edit_notes["release"]），单曲模式原来还是中文说明句 + 中文键名，两边风格
    不一致，复制到 MB 编辑框时显得突兀。这里统一成同一套结构。

    **字段一个都不能少**：原来那份草稿里的时长 / ISRC / ISWC / 发行日期，以及
    「现有 recording：<url>」这条消歧指针，都是 MB 志愿者判断「该复用还是该新建」
    的依据 —— 只换成漂亮模板而删掉它们，note 反而不如原来有用。所以这里是
    **重排 + 补充**，不是替换。

    溯源说明同样重要：ISRC 到底是平台自己给的，还是第三方目录（Sonovault /
    Soundcharts）交叉引用来的，可信度不同，必须写清楚。
    """
    title = first(song.get("title")) or "(untitled)"
    artist = first(song.get("artist")) or "(unknown artist)"
    lines: list[str] = [
        f"Recording/work metadata preparation for {title} by {artist}.",
        "",
        "Sources:",
    ]
    for url in source_urls:
        if url:
            lines.append(f"- {url}")
    if not source_urls:
        lines.append("- (no source URL provided)")

    # 已核对的字段：逐条写清楚，空值直接说「未确认」，不让人猜
    verified: list[str] = []
    if song.get("length"):
        verified.append(f"Length: {song['length']}")
    if song.get("isrc"):
        verified.append(f"ISRC: {song['isrc']}" + (f" (verified via {isrc_provenance})" if isrc_provenance else ""))
    if song.get("iswc"):
        verified.append(f"ISWC: {song['iswc']}")
    if song.get("release_date"):
        verified.append(f"Release date: {song['release_date']}")
    if song.get("album"):
        verified.append(f"Album: {song['album']}")
    if verified:
        lines += ["", "Verified metadata:"] + [f"- {item}" for item in verified]

    # 词曲 Credits 的出处：Apple 页面是版权方侧数据，值得单独说一句
    credits_urls = [first(credit.get("source_url")) for credit in (apple_credits or []) if credit.get("source_url")]
    if credits_urls:
        lines += ["", "Composer/Lyricist credits sourced from Apple Music credits page:"] + [f"- {url}" for url in credits_urls]

    # 消歧指针：MB 里已经有这条 recording 时，明确给出，避免重复建
    if recording.get("mbid"):
        lines += [
            "",
            f"Existing recording already in MusicBrainz: {recording.get('url') or ''}",
            "Please confirm this is the same version (check artist / length / ISRC against the release) "
            "and reuse it rather than creating a duplicate. Note that studio, live, cover and re-recordings "
            "are separate recordings.",
        ]
    else:
        lines += [
            "",
            "No existing recording was found in MusicBrainz for this track. "
            "This is a new recording entry to be added under the release it belongs to.",
        ]

    lines += [
        "",
        "ISWC and collecting-society identifiers are left blank unless they can be verified from an "
        "authoritative source. ISRC is taken from the release side.",
    ]
    return "\n".join(lines)


def build_song_report(primary_url: str, source_urls: list[str], song_source: str = "apple", song_id: str = "", album_name: str = "", artist_name: str = "") -> dict[str, Any]:
    """单曲链接的独立报告：聚焦「这一首歌」的资料（recording / work / credits / 歌词候选）。

    平台支持：apple（music.apple.com/…/song/…）、spotify（open.spotify.com/track/…）、
    deezer（deezer.com/track/…）。三种来源都归一化成同样的 song 字段，MB 检索与
    歌词候选等下游逻辑与平台无关。

    与专辑报告（build_report）并列：单曲查询里有用的是 recording、ISRC、词曲作者、
    Apple Credits、歌词页候选这些「歌曲级」信息；专辑的条码、品番、发行地区、整张
    tracklist 与它无关，所以不复用专辑模板。所属专辑只作为一条「线索」给出，并带
    一键切到专辑资料查询的链接，需要建专辑时再走专辑报告。
    """
    CACHE_STATS.hit = 0
    CACHE_STATS.miss = 0
    source_errors: list[dict[str, str]] = []
    source_warnings: list[dict[str, str]] = []
    api_notes: list[str] = []
    sources: list[dict[str, Any]] = []

    # ---- 1. 平台数据源：单曲的权威基础字段（时长 / ISRC / 所属专辑）----
    song: dict[str, Any] = {}
    platform_label = {"apple": "Apple Music", "spotify": "Spotify", "deezer": "Deezer"}.get(song_source, song_source)
    if song_source == "apple":
        try:
            data = fetch_json(f"https://itunes.apple.com/lookup?id={quote(song_id)}")
            track = next((item for item in data.get("results") or [] if item.get("wrapperType") == "track"), {})
            if track:
                artwork = first(track.get("artworkUrl100"))
                if artwork:
                    artwork = artwork.replace("100x100bb", "1000x1000-999")
                song = {
                    "title": first(track.get("trackName")),
                    "artist": first(track.get("artistName")),
                    "album": first(track.get("collectionName")),
                    "album_platform_id": str(track.get("collectionId") or ""),
                    "album_source": platform_label,
                    "album_url": normalize_mb_url(first(track.get("collectionViewUrl"))),
                    "track_url": first(track.get("trackViewUrl")).split("&uo=")[0],
                    "length": format_duration(track.get("trackTimeMillis")),
                    "isrc": clean_value(track.get("isrc")),
                    "iswc": "",
                    "release_date": iso_date(track.get("releaseDate")),
                    "genre": first(track.get("primaryGenreName")),
                    "copyright": clean_value(track.get("copyright")),
                    "artwork_url": artwork,
                }
                sources.append({"name": platform_label, "status": "ok", "url": song.get("track_url") or primary_url, "summary": song})
        except FetchError as exc:
            source_errors.append({"source": "Apple/iTunes", "error": f"单曲查询失败：{exc}"})
    elif song_source == "spotify":
        try:
            data = spotify_track(song_id)
            if data.get("id"):
                song = {
                    "title": data["title"],
                    "artist": data["artist"],
                    "album": data["album"],
                    "album_platform_id": data["album_id"],
                    "album_source": platform_label,
                    "album_url": data["album_url"],
                    "track_url": data["url"],
                    "length": data["length"],
                    "isrc": clean_value(data["isrc"]),
                    "iswc": "",
                    "release_date": data["date"],
                    "genre": "",
                    "artwork_url": data["image"],
                }
                sources.append({"name": "Spotify", "status": "ok", "url": data["url"], "summary": song})
        except FetchError as exc:
            source_errors.append({"source": "Spotify", "error": f"单曲查询失败：{exc}"})
    elif song_source == "deezer":
        try:
            data = deezer_track(song_id)
            if data.get("id"):
                song = {
                    "title": data["title"],
                    "artist": data["artist"],
                    "album": data["album"],
                    "album_platform_id": data["album_id"],
                    "album_source": platform_label,
                    "album_url": data["album_url"],
                    "track_url": data["url"],
                    "length": data["length"],
                    "isrc": clean_value(data["isrc"]),
                    "iswc": "",
                    "release_date": data["date"],
                    "genre": "",
                    "artwork_url": data["image"],
                }
                sources.append({"name": "Deezer", "status": "ok", "url": data["url"], "summary": song})
        except FetchError as exc:
            source_errors.append({"source": "Deezer", "error": f"单曲查询失败：{exc}"})
    sources_ok = any(item.get("status") == "ok" for item in sources)
    if not first(song.get("title")) or not sources_ok:
        return {
            "needs_selection": True,
            "reason": f"无法解析该单曲链接（{platform_label} 查不到这首歌）。请确认链接有效，或改用专辑 / 播放列表链接。",
            "query": {"album_name": album_name, "artist_name": artist_name},
        }

    # ---- 1.5 Sonovault / Soundcharts 补 ISRC / ISWC（可选：配置对应环境变量后生效）----
    #    平台没给 ISRC（主要是 Spotify 代理）时，先用 Sonovault 免费 API 交叉引用补；
    #    Sonovault 未命中（曲库未收录 / CJK 标题不索引）且单曲来源是 apple/spotify/deezer
    #    时，再用 Soundcharts 按平台曲目 ID 直查（不依赖模糊搜索，更精确）。
    #    两边都搜不到就静默，不制造噪音；平台已给的 ISRC 绝不覆盖。
    #    isrc_provenance 记录 ISRC 的出处，Edit note 要写「这个 ISRC 是谁给的」，
    #    MB 志愿者才能判断可不可信（平台自己给的 vs 第三方目录交叉引用的可信度不同）。
    isrc_provenance = ""
    if not song.get("isrc"):
        try:
            sv = sonovault_track_search(song.get("title") or "", song.get("artist") or "")
        except FetchError as exc:
            sv = {}
            source_errors.append({"source": "Sonovault", "error": f"ISRC 补查失败：{exc}"})
        if sv:
            if not song.get("isrc") and sv.get("isrc"):
                song["isrc"] = sv["isrc"]
                isrc_provenance = "Sonovault"
            if sv.get("iswc"):
                song["iswc"] = sv["iswc"]
            api_notes.append(f"ISRC 来自 Sonovault 交叉引用（{sv.get('title') or '同名单曲'} · {sv.get('source_url') or 'sonovault.now'}）")
        elif song_source in SOUNDCHARTS_PLATFORMS:
            try:
                sc = soundcharts_song_by_platform_id(song_source, song_id)
            except FetchError as exc:
                sc = {}
                source_warnings.append({"source": "Soundcharts", "warning": f"ISRC 补查失败（可选数据源，已跳过）：{exc}"})
            if sc:
                if not song.get("isrc") and sc.get("isrc"):
                    song["isrc"] = sc["isrc"]
                    isrc_provenance = "Soundcharts"
                if sc.get("iswc"):
                    song["iswc"] = sc["iswc"]
                api_notes.append(f"ISRC 来自 Soundcharts 交叉引用（{sc.get('title') or '同名单曲'} · {sc.get('source_url') or 'soundcharts.com'}）")
    elif song.get("isrc"):
        isrc_provenance = platform_label

    # ---- 2. MusicBrainz recording 搜索（歌名 + 艺人）----
    recording: dict[str, Any] = {}
    mb_error = ""
    try:
        rows = mb_search_recording(song["title"], song["artist"])
        if rows:
            best = rows[0]
            recording = {
                "mbid": best["mbid"],
                "url": best["url"],
                "title": best["title"],
                "artist": best["artist"],
                "isrc": best["isrc"],
                "length": best["length"],
                "score": best["score"],
                "releases": best["releases"],
                "suggested": len(rows) > 1,
            }
    except FetchError as exc:
        mb_error = f"recording 搜索失败：{exc}"
        source_errors.append({"source": "MusicBrainz", "error": mb_error})
    # 这条提示只看 MusicBrainz 自己的成败：source_errors 里混着 Apple/Spotify/Deezer/
    # Sonovault 的错误，拿它判断 MB 会把「正常」说成「不可用」；而 MB 真的挂了时
    # （mb_error 非空）又一条提示都不写，恰好漏掉最该看到的那句。
    if mb_error:
        api_notes.append("MusicBrainz 查询在本次环境中不可用")
    elif song["title"] or song["artist"]:
        # 歌名与艺人都为空时 mb_search_recording 直接返回空列表、根本没发请求，别报「正常」
        api_notes.append("MusicBrainz recording 搜索正常（MB 限速 1 req/s，慢属正常）")

    # ---- 3. Work 关系：recording → work / composer / lyricist ----
    work_relations: dict[str, Any] = {
        "status": "skipped",
        "notice": "没有可查询的 recording：MusicBrainz 里没找到这首歌的录音。先在 MB 建好 recording（或先从专辑发行建库），再来查询它已挂的 work 关系。",
        "items": [], "query_count": 0, "failed": 0, "limited": 0,
        "work_count": 0, "relation_count": 0, "apple_credits": [],
        "markdown": "",
    }
    if recording.get("mbid"):
        try:
            result = mb_work_rels_for_recording(recording["mbid"])
            works = result["works"]
            rec_rels = result["recording_relations"]
            work_count = len(works)
            relation_count = len(works) + len(rec_rels)
            work_relations = {
                "status": "ok" if work_count or relation_count else "empty",
                "notice": (f"已查到 MusicBrainz 上这首歌的 recording（{recording['mbid']}）下的 {relation_count} 条关系" if work_count or relation_count
                           else "recording 已存在，但它还没挂任何 work / artist 关系——可在 MB 页面上直接新建 Work 并挂 composer / lyricist / producer。"),
                "items": [{
                    "track": song["title"],
                    "recording_mbid": recording["mbid"],
                    "recording_url": recording["url"],
                    "works": works,
                    "recording_relations": rec_rels,
                    "error": "",
                }],
                "query_count": 1, "failed": 0, "limited": 0,
                "work_count": work_count, "relation_count": relation_count,
                "apple_credits": [],
                "markdown": "",
            }
        except FetchError as exc:
            work_relations["status"] = "failed"
            work_relations["failed"] = 1
            work_relations["notice"] = f"查询 recording 的 work 关系失败：{exc}"

    # ---- 4. Apple 歌曲页 Credits（版权方侧，不依赖 MB）----
    #    apple 来源直接用输入页；spotify/deezer 来源先在 iTunes 搜同名同艺人的单曲，
    #    拿到 Apple Music 页面再抓 Credits（同一首歌，词曲/制作团队通用）。
    apple_credits: list[dict[str, Any]] = []
    credit_url = primary_url if song_source == "apple" else ""
    if song_source != "apple":
        try:
            term = quote(f"{song['title']} {song['artist']}")
            search = fetch_json(f"https://itunes.apple.com/search?term={term}&entity=song&limit=5")
            for item in search.get("results") or []:
                if item.get("wrapperType") != "track":
                    continue
                candidate = first(item.get("trackViewUrl"))
                found_name = first(item.get("trackName"))
                found_artist = first(item.get("artistName"))
                if not candidate:
                    continue
                # Apple 标题可能把全角标点换成半角（"その結婚、正気ですか？" vs "?"），
                # 用艺人完全一致 + 标题模糊匹配来判定是同一首歌
                if (found_artist and found_artist == song["artist"]) or (found_name and title_is_related(found_name, song["title"])):
                    credit_url = candidate.split("&uo=")[0]
                    break
        except FetchError:
            pass
    credit = collect_apple_credits(credit_url, song["title"]) if credit_url else {}
    if credit:
        apple_credits.append(credit)
        work_relations["apple_credits"] = apple_credits
        if work_relations["status"] == "skipped":
            work_relations["status"] = "credits_only"
            work_relations["notice"] = "MB 尚未匹配到这首歌的 recording，无法查现有关联；已从 Apple Music 页面抓到 Credits，可直接作为新建 Work / Recording 时挂 relationship 的依据。"
        work_relations["markdown"] = work_relations_markdown(work_relations.get("items") or [], apple_credits)
    else:
        source_warnings.append({"source": "Apple Music Credits", "warning": "没抓到对应歌曲页的 Credits（可能是 WAF / 页面结构变化 / iTunes 搜不到同名单曲）。词曲作者/制作信息需从其他官方渠道人工补齐。"})

    # ---- 5. 歌词 URL relationship 候选（白名单站点搜索页直达）----
    lyric_links = lyrics_search_candidates(song["title"], song["artist"])
    lyrics_candidates = [{"track": song["title"], "artist": song["artist"], "links": lyric_links}] if lyric_links else []

    # ---- 6. 外部链接：当前平台单曲页 + MB recording 已挂的 URL ----
    external_links: list[dict[str, str]] = []
    track_rel = "purchase for download" if song_source == "apple" else "streaming"
    if song.get("track_url"):
        external_links.append({"site": platform_label, "relationship": track_rel, "url": song["track_url"], "source": platform_label})
    if recording.get("mbid"):
        try:
            rec_urls = mb_request(f"recording/{recording['mbid']}", {"inc": "url-rels", "fmt": "json"})
            for relation in rec_urls.get("relations") or []:
                resource = first((relation.get("url") or {}).get("resource"))
                site, _ = site_info(resource)
                if site and resource and resource != song.get("track_url"):
                    external_links.append({"site": site, "relationship": first(relation.get("type")) or "url", "url": resource, "source": "MusicBrainz"})
        except FetchError:
            pass

    # ---- 7. 交付材料：核对清单 / Edit note 草稿 ----
    checklist: list[dict[str, str]] = []
    if recording.get("mbid"):
        checklist.append({"label": "确认 recording 就是这一版", "reason": f"MB 匹配到录音 {recording['mbid']}（score {recording.get('score')}）。看艺人/时长/ISRC 与发行版本一致；同名不同版（现场、翻唱、重录）别混。"})
        if recording.get("releases"):
            checklist.append({"label": "确认 recording 归属的发行", "reason": f"这首歌已出现在：{'、'.join(recording['releases'])}。挂关系时 recording 选对，别在别的发行下重复建。"})
    else:
        checklist.append({"label": "先在 MusicBrainz 建 / 找 recording", "reason": "MB 里还没有这首歌的录音。Add recording 时用下方 Edit note 草稿的字段；或在所属专辑 Release 的曲目表里建。"})
    checklist.append({"label": "逐条核对 Apple Credits 后再挂关系", "reason": "Apple 页面 Credits 是版权方侧数据，作曲/作词/制作/工程按页面角色挂；角色名随页面语言变化，别硬译。"})
    if lyric_links:
        checklist.append({"label": "歌词页候选人工确认后挂 lyrics 关系", "reason": "MB 的 lyrics relationship 只允许白名单站点。在各站搜索页确认到歌词页后，把最终 URL 挂到 Work / Recording 上，别挂搜索页。"})
    checklist.append({"label": "ISRC / ISWC 原则", "reason": "ISRC 以发行侧数据为准；ISWC 查不到就留空，不要从别的歌曲复制。"})

    edit_notes: dict[str, str] = {}
    edit_notes["recording"] = song_recording_edit_note(
        song, recording, source_urls, isrc_provenance, apple_credits
    )
    if work_relations.get("markdown"):
        edit_notes["work"] = work_relations["markdown"]

    return {
        "report_type": "song",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "input": {"url": primary_url, "urls": source_urls, "song_source": song_source, "song_id": song_id},
        "song": song,
        "recording": recording,
        "apple_credits": apple_credits,
        "work_relations": work_relations,
        "lyrics_candidates": lyrics_candidates,
        "external_links": external_links,
        "manual_review": checklist,
        "edit_notes": edit_notes,
        "source_warnings": source_warnings,
        "source_errors": source_errors,
        "api_notes": api_notes,
        "sources": sources,
        "markdown": song_report_markdown(song, recording, work_relations, lyrics_candidates),
    }


def song_report_markdown(song: dict[str, Any], recording: dict[str, Any], work_relations: dict[str, Any], lyrics_candidates: list[dict[str, Any]]) -> str:
    """单曲报告的一份紧凑 Markdown，供「复制 / 下载」用。"""
    lines = [
        f"# {first(song.get('title'))}",
        "",
        f"- Artist: {first(song.get('artist'))}",
        f"- 时长: {first(song.get('length')) or '未确认'}",
        f"- ISRC: {first(song.get('isrc')) or '未确认'}",
        f"- ISWC: {first(song.get('iswc')) or '未确认'}",
        f"- 所属专辑: {first(song.get('album')) or '未确认'}（{first(song.get('album_url')) or '无链接'}）",
        f"- 发行日期: {first(song.get('release_date')) or '未确认'}",
        f"- 类型: {first(song.get('genre')) or '未确认'}",
    ]
    if song.get("track_url"):
        lines.append(f"- {first(song.get('album_source')) or '平台'}: {song['track_url']}")
    if recording.get("mbid"):
        lines += ["", "## MusicBrainz recording", f"- MBID: {recording['mbid']}", f"- URL: {recording['url']}",
                  f"- 匹配评分: {recording.get('score') or 0}", f"- 所在发行: {'、'.join(recording.get('releases') or []) or '未确认'}"]
    for credit in (work_relations.get("apple_credits") or []):
        lines += ["", f"## Apple Music Credits（{first(credit.get('source_url'))}）"]
        for group in credit.get("groups") or []:
            lines.append(f"- **{first(group.get('title')) or first(group.get('id'))}**")
            for item in group.get("items") or []:
                roles = "、".join(item.get("roles") or [])
                lines.append(f"  - {first(item.get('name'))}" + (f"（{roles}）" if roles else ""))
    if lyrics_candidates:
        lines += ["", "## Lyrics 候选（MB 白名单站点）"]
        for link in (lyrics_candidates[0].get("links") or []):
            lines.append(f"- {link.get('site')}: {link.get('url')}")
    return "\n".join(lines).rstrip() + "\n"


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
    # 单曲链接走单曲报告：需要的字段（recording / work / credits / 歌词候选）与专辑报告几乎不重叠
    song_url_info = detect_song_url(primary_url) if source_urls else {}
    if song_url_info:
        return build_song_report(primary_url, source_urls, song_url_info["source"], song_url_info["track_id"], album_name, artist_name)
    # ---- 并行阶段 1：互相独立的上游来源 ----
    # 这些来源彼此不依赖（谁也不知道谁的结果），串行等着就是白等慢的那个。
    # Apple 故意不在这一批里：itunes_album_by_id 的整单区域切换要用 artist_hint，
    # 而 artist_hint 来自下面 page / Spotify / Deezer 的结果 —— 必须放到第二阶段。
    # MusicBrainz 也不在这一批：它有 1 req/s 的硬限制，走自己的限速通道（mb_request）。
    page_summaries: list[dict[str, Any]] = []
    spotify_data: dict[str, Any] = {}
    deezer_data: dict[str, Any] = {}
    deezer_reverse = ""

    stage1_tasks: list[Any] = []
    stage1_kinds: list[str] = []
    for url in source_urls:
        stage1_tasks.append(lambda u=url: source_page_summary(u))
        stage1_kinds.append("page")
    spotify_id = next((found for url in source_urls if (found := extract_spotify_id(url))), "")
    if spotify_id:
        stage1_tasks.append(lambda sid=spotify_id: spotify_album(sid))
        stage1_kinds.append("spotify")
    deezer_id = next((found for url in source_urls if (found := extract_deezer_id(url))), "")
    if deezer_id:
        stage1_tasks.append(lambda did=deezer_id: deezer_album(did))
        stage1_kinds.append("deezer")

    stage1_results = run_parallel(stage1_tasks)
    # 把 worker 线程里的缓存命中计数汇总回请求线程，否则「本次有 N 个命中缓存」恒为空
    merge_cache_stats([(item.hit_delta, item.miss_delta) for item in stage1_results])

    for index, outcome in enumerate(stage1_results):
        kind = stage1_kinds[index]
        if kind == "page":
            if outcome.error is not None:
                # source_page_summary 内部已经兜住 FetchError 并返回 unavailable，
                # 走到这里说明是意外异常：记一条警告，别让整次查询失败
                source_warnings.append({"source": "页面解析", "warning": f"读取页面失败：{outcome.error}"})
                continue
            summary = outcome.value
            if summary:
                page_summaries.append(summary)
        elif kind == "spotify":
            if outcome.error is not None:
                source_warnings.append({"source": "Spotify", "warning": f"Spotify 数据读取失败：{outcome.error}"})
            else:
                spotify_data = outcome.value or {}
        elif kind == "deezer":
            if outcome.error is not None:
                source_warnings.append({"source": "Deezer", "warning": f"Deezer 数据读取失败：{outcome.error}"})
            else:
                deezer_data = outcome.value or {}

    page_hint = next((item for item in page_summaries if item.get("status") == "ok" and (item.get("title") or item.get("artist"))), {})
    release_id, release_group_id = extract_mbids(primary_url)
    apple_id = extract_apple_id(primary_url)
    # Apple 的「专辑展开页」`.../album/<slug>/<albumId>?i=<trackId>`：apple_id 是专辑，
    # `?i=` 指向用户当前打开的那一轨。词曲/制作 Credits 只渲染在歌曲页（专辑页不渲染），
    # collect_apple_credits() 会按 trackId 改写成歌曲页去抓，所以这里要先把 trackId 取出来，
    # 并借 iTunes lookup 拿到曲目名做 Credits 的标题（拿不到就留空，报告里回落成「(歌曲)」）。
    # 纯单曲链接（没有 albumId）到不了这里：上面 detect_song_url() 已把它路由进单曲报告。
    apple_track_id = extract_apple_song_id(primary_url) if apple_id else ""
    apple_track_album: dict[str, Any] = {}
    if apple_track_id:
        try:
            apple_track_album = itunes_album_from_song(apple_track_id)
        except FetchError as exc:
            source_warnings.append({"source": "Apple/iTunes", "warning": f"链接里的曲目信息读取失败，Apple Credits 会缺曲目名：{exc}"})
        linked_album = apple_track_album.get("collection_id")
        if linked_album and linked_album != apple_id:
            # `?i=` 指的是另一张专辑里的曲目（分享链接里常见）：那份 credits 属于那张专辑，
            # 贴到本张上就是错数据，宁可留空。
            source_warnings.append({"source": "Apple/iTunes", "warning": f"链接里的 ?i={apple_track_id} 属于专辑 {linked_album}，与链接的专辑 {apple_id} 不一致，已跳过 Apple Credits 采集"})
            apple_track_id = ""
    if deezer_data and not page_hint and deezer_id:
        # 输入就是 Deezer 链接时数据来自 API 而非页面解析，用它顶替 page_hint，避免误报「页面解析失败」
        page_hint = deezer_data
    title_hint = first(page_hint.get("title")) or first(spotify_data.get("title")) or first(deezer_data.get("title")) or album_name or first(apple_track_album.get("collection_name"))
    artist_hint = first(page_hint.get("artist")) or artist_name.strip() or first(spotify_data.get("artist")) or first(deezer_data.get("artist")) or first(apple_track_album.get("artist"))

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
            # 「反向查询」是拿到 MBID 的途径，不是来源：它指向的商店页本身已经作为
            # 输入链接页面列在 sources 里，再单列一条既重复、名字（MusicBrainz）又和
            # URL（商店页）对不上。只在 summary 里留一句溯源，列表不再多一行。
            mb_summary = dict(mb_data)
            if reverse_used:
                mb_summary["reverse_lookup"] = f"通过链接 {reverse_used} 反查到本发行"
            sources.append({"name": "MusicBrainz", "status": "ok", "url": f"https://musicbrainz.org/release/{mb_data.get('release_mbid')}", "summary": mb_summary})
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
        # 「Deezer 反查」和下面的「Deezer」指向同一个 URL，是一条重复行；反查只是
        # 拿到这张专辑的手段，合并成一行，溯源写进 summary。
        deezer_summary = dict(deezer_data)
        if deezer_reverse:
            deezer_summary["reverse_lookup"] = f"通过{deezer_reverse}反查到本专辑"
        sources.append({"name": "Deezer", "status": "ok", "url": deezer_data.get("url") or "", "summary": deezer_summary})

    if spotify_data:
        sources.append({"name": "Spotify", "status": "ok", "url": spotify_data.get("url") or "", "summary": spotify_data})

    # page_summaries 来自用户输入的原始链接（Apple Music / OTOTOY / mora 等），
    # Apple Music 链接的 page summary URL 与 Apple/iTunes API 来源的 URL 通常相同或等价，
    # 不做去重直接 append 会导致同一个链接在 sources 列表里出现两次。
    _existing_source_urls = {normalize_mb_url(item["url"]) for item in sources if item.get("url")}
    for page_summary in page_summaries:
        page_url = page_summary.get("url") or ""
        if page_url and normalize_mb_url(page_url) in _existing_source_urls:
            # 这条页面链接已经被 Apple/iTunes 或其他 API 来源录入，跳过，避免重复
            if page_summary.get("status") != "ok":
                source_warnings.append({"source": page_summary.get("source") or "输入链接页面", "warning": f"页面抓取失败（{page_summary.get('error', '未知原因')}），该来源未参与本次整理，可重试或改用其它链接"})
            continue
        sources.append({"name": page_summary.get("source") or "输入链接页面", "status": page_summary.get("status"), "url": page_url, "summary": page_summary})
        if page_url:
            _existing_source_urls.add(normalize_mb_url(page_url))
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
    # Apple Music 页面 Credits：作曲/作词/制作/表演 —— 版权方侧数据，不依赖 MB，
    # 建一个「MB 里还不存在的 work」时正是靠它挂 relationship。
    # 专辑报告只在链接指向具体曲目（`?i=` 展开页）时才抓得到：专辑页本身不渲染 Credits。
    apple_credits: list[dict[str, Any]] = []
    if apple_track_id:
        credit = collect_apple_credits(primary_url, first(apple_track_album.get("track_name")))
        if credit:
            apple_credits.append(credit)
    # Work relationships：逐轨查询 MusicBrainz 的 work / composer / lyricist 关系。
    # 只查询展示，建库（建 Work、挂关系）由人工在 MusicBrainz 完成。
    work_relations = build_work_relations(tracks, apple_credits)
    # Lyrics URL relationship 候选：MB 只允许白名单站点，给出各站搜索页直达链接
    lyrics_candidates = lyrics_candidates_for_tracks(tracks)
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
    if work_relations["items"]:
        if work_relations["failed"] or work_relations["limited"]:
            work_tail = f"{work_relations['failed']} 首查询失败、{work_relations['limited']} 首超出查询预算未查，请在 MusicBrainz 页面人工确认。"
        elif work_relations.get("apple_credits"):
            work_tail = "另有 Apple 页面 Credits 可交叉核对。"
        else:
            # 不能无条件写「另有 Apple 页面 Credits」：专辑链接没指向具体曲目（无 ?i=）时根本没抓到
            work_tail = "本次没有抓到 Apple 页面 Credits，词曲 / 制作信息请从官方页面人工补齐。"
        work_review_reason = (
            f"已自动查询 {work_relations['query_count']} 首曲目，找到 {work_relations['work_count']} 个 work / {work_relations['relation_count']} 条关系，人工核对后挂载；"
            + work_tail
        )
    elif work_relations.get("apple_credits"):
        work_review_reason = "MB 尚无此曲目的 work/recording：下列 Apple Music Credits（作曲/作词/制作/表演）可直接作为新建 Work 与 Recording 关系挂载的依据，挂载前人工核对。"
    else:
        work_review_reason = "自动查询到的 credits 需要挂到正确的 Work 或 Recording。"
    work_edit_note = f"Work/recording credit follow-up for {title}.\n\nUse only credits confirmed by the linked official or authorized source. Leave ISWC and collecting-society IDs blank when they cannot be verified."
    if work_relations["markdown"]:
        work_edit_note += "\n\n" + work_relations["markdown"]
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
        "work_relations": work_relations,
        "lyrics_candidates": lyrics_candidates,
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
            {"key": "works", "label": "补 Work、作词/作曲和制作关系", "reason": work_review_reason},
            {"key": "iswc", "label": "ISWC / 著作权登记号", "reason": "查不到就留空，不要从别的歌曲复制。"},
            {"key": "cover", "label": "确认封面是该数字发行的原图", "reason": "禁止 AI 放大、裁剪、加水印或使用粉丝制作图。"},
        ],
        "edit_notes": {
            "release": f"Digital release preparation for {title} by {artist}.\n\nSources:\n" + "\n".join(f"- {item.get('url')}" for item in sources if item.get("url")),
            "work": work_edit_note,
            "cover": f"Front cover taken from the release's own digital artwork source (unmodified):\n{artwork_url}" if artwork_url else "Front cover source still needs to be confirmed.",
        },
        "api_notes": [
            "MusicBrainz read API requires a meaningful User-Agent and should be throttled to no more than one request per second per application.",
            "This tool only prepares data; it does not submit edits to MusicBrainz.",
            *([] if not work_relations["query_count"] else [f"Work relationships: queried {work_relations['query_count']} recordings ({work_relations['failed']} failed, {work_relations['limited']} over budget). Read-only; manual MB editing required."]),
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
        /api/login 豁免认证本身 —— 前者是健康探针（响应里带 auth 标志供前端探测），
        后者是登录入口，凭据在 handle_login 内自行校验。
        注意 /api/login 只豁免「凭据校验」这一层，**限流照常生效**：它是唯一用
        凭据换凭据的入口，若一起放开，就等于给口令枚举留了条无限速的通道。
        401 不再携带 WWW-Authenticate 头：那会触发浏览器原生 Basic 弹窗，
        自定义登录页依赖的是普通 401 响应。
        限流（见下）覆盖所有 /api/*，包括 /api/login。
        """
        path = urlparse(self.path).path
        if path == "/api/health":
            return True
        # /api/login 不能在这里一起 return True：它只需要跳过下面的 Authorization
        # 校验（凭据由 handle_login 自己核对），限流必须继续走。
        if AUTH_HEADER and path.startswith("/api/") and path != "/api/login":
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
            self.send_json({"ok": True, "auth": True, "auth_ttl": AUTH_TTL})
            return
        username = first(str(body.get("username", ""))).strip()
        password = str(body.get("password", ""))
        candidate = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        if hmac.compare_digest(candidate.encode("utf-8"), AUTH_HEADER.encode("utf-8")):
            self.send_json({"ok": True, "auth": True, "auth_ttl": AUTH_TTL})
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
            self.send_json({"ok": True, "service": "Sleeve", "version": VERSION, "auth": bool(AUTH_HEADER), "auth_ttl": AUTH_TTL})
            return
        route = urlparse(self.path).path

        # ISRC 补查数据源用量（Sonovault 配置状态 / Soundcharts 配额实时查询）。
        # 跟随 /api/* 鉴权与限流（不豁免），避免暴露「配了哪些上游」给未认证访客。
        if route == "/api/usage":
            try:
                self.send_json(collect_usage_status())
            except Exception as exc:
                self.send_internal_error("用量查询", exc)
            return

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
        print("  taskkill /F /PID <PID>")
        raise SystemExit(1) from exc
