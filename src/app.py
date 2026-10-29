from __future__ import annotations

import base64
import hmac
import json
import os
import sys
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SRC_DIR = Path(__file__).resolve().parent
ROOT = SRC_DIR.parent / "public"
# 门面：config 模块已移至 config.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 config.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 config.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from config import (  # noqa: E402,F401
    ALLOW_OPEN_NO_AUTH,
    AUTH_HEADER,
    AUTH_RAW,
    AUTH_TTL,
    AUTH_TTL_DEFAULT,
    DETAIL_IN_ERRORS,
    EXPOSED_BIND,
    HOST,
    PORT,
    RATE_HITS,
    RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW,
    RATE_LOCK,
    bind_is_loopback,
    parse_auth_ttl,
    parse_rate_limit,
    rate_limit_allow,
)

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
# 门面：已移至 version.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 version.py。
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
# 门面：已移至 musicbrainz.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 musicbrainz.py。
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
    choose_mb_candidate,
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
# 门面：已移至 net.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 net.py。
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

if AUTH_RAW and ":" not in AUTH_RAW:
    # 宁可起不来，也不要静默地以「无鉴权」状态对外服务 —— 那正是最危险的失败方式
    raise SystemExit("SLEEVE_AUTH 格式应为 user:password，当前值里没有冒号，拒绝启动。")
if not AUTH_HEADER and not ALLOW_OPEN_NO_AUTH and not bind_is_loopback(EXPOSED_BIND):
    raise SystemExit(
        f"监听地址 {EXPOSED_BIND} 对外且未设置 SLEEVE_AUTH，拒绝启动。\n"
        "  · 要对外开放：设 SLEEVE_AUTH=user:password（并套一层 HTTPS 反向代理）；\n"
        "  · 只给本机用：把监听 / 发布地址改回 127.0.0.1（SLEEVE_HOST / SLEEVE_BIND）；\n"
        "  · 确要在可信网络里无鉴权开放：显式设 SLEEVE_AUTH_ALLOW_OPEN=1。\n"
        "无鉴权的 /api/lookup 等于一个开放代理：任何人都能借你的 IP 扇出 30~50 个出网请求，\n"
        "并把 MusicBrainz「每秒 1 次」的配额打光。"
    )


# 门面：values 模块已移至 values.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 values.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 values.py。
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
# 门面：已移至 itunes.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 itunes.py。
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
# 门面：已移至 spotify.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 spotify.py。
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
# 门面：已移至 deezer.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 deezer.py。
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

# 门面：report 模块已移至 report.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 report.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 report.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from report import (  # noqa: E402,F401
    JAPANESE_TEXT_RE,
    LYRIC_SITE_INTERNATIONAL,
    LYRIC_SITE_JAPANESE,
    MAX_LYRICS_CANDIDATE_TRACKS,
    PLATFORM_SEARCH_URLS,
    SOURCE_URL_SPLIT_RE,
    add_derived_external_links,
    build_external_links,
    build_report,
    build_song_report,
    build_work_relations,
    comparable_sources,
    detect_song_url,
    discover_platform_links,
    fill_missing_isrc,
    imprint_from_copyright,
    likely_compilation,
    looks_japanese,
    lyrics_candidates_for_tracks,
    lyrics_search_candidates,
    merge_tracks,
    platform_search_links,
    platform_search_notes,
    search_candidates,
    search_query_text,
    song_recording_edit_note,
    song_report_markdown,
    split_source_urls,
    track_slot,
    work_relations_markdown,
)

# 门面：soundcharts 模块已移至 soundcharts.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 soundcharts.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 soundcharts.py。
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
# 门面：已移至 parsers.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 parsers.py。
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

# 门面：sites 模块已移至 sites.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 sites.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
# 门面：已移至 sites.py。
# 列出该模块的**全部**公开顶层名字 —— 门面的承诺就是 app.X 与拆分前一致，
# 测试和调用方不该被迫改 import。（下划线开头的是模块私有，不在此列。）
from sites import (  # noqa: E402,F401
    PUBLIC_SUFFIX_TAIL_RE,
    URL_SITE_RULES,
    host_matches_site_rule,
    site_info,
)


# ---------------------------------------------------------------------------
# Work relationships：只查询、只展示；建库（建 Work / 挂关系）由人工在 MusicBrainz 完成
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Lyrics URL relationship 候选：MB 的 lyrics relationship 只允许白名单站点
# ---------------------------------------------------------------------------

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
