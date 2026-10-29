"""Soundcharts 与 Sonovault 客户端（都可选，未配置凭据时整体静默降级）。

两个都是「按需补查」的付费/受限 API，只在用户填了自己的凭据时才启用 ——
没配就直接返回空结果，查询照常进行，不报错也不提示。这是刻意的：
它们提供的是**锦上添花**的字段（ISRC / ISWC / 平台播放量），
缺失不该让整次查询失败。

Soundcharts 需要 OAuth 取 token：客户端凭据在 token URL 上换 access_token，
结果按过期时间缓存在 SOUNDCHARTS_TOKEN_CACHE 里。token 请求走 GUARDED_OPENER
并显式 check_outbound —— 这两个 URL 可以被环境变量改掉，等于用户可控的
出网目标，必须过 SSRF 闸门。

注意 SOUNDCHARTS_TOKEN_CACHE 等模块级可变状态：测试要用 patch_seam 打补丁，
而不是给函数传参，因为生产路径上它们是全局单例。
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request

# 上游模块（拆分前这些是 app.py 里的同级定义）
from net import FetchError, GUARDED_OPENER, check_outbound, fetch_json
from version import USER_AGENT
from values import clean_value, first, title_is_related


SONOVAULT_BASE = "https://api.sonovault.now"
SONOVAULT_API_KEY = os.environ.get("SONOVAULT_API_KEY", "").strip()


def sonovault_track_search(title: str, artist: str) -> dict[str, Any]:
    """Sonovault 免费 API：按艺人+标题补查 ISRC / ISWC（93M 录音目录）。

    只对曲库收录的歌有效：英文/主流歌命中率高；CJK 原文标题不索引（罗马字
    标题可命中）。未配置 SONOVAULT_API_KEY 或查询无匹配时返回 {}。
    免费档限速 20 req/min；单曲报告只查一次，不会触发。
    """
    if not SONOVAULT_API_KEY or not title or not artist:
        return {}
    params = {"artist": artist, "title": title, "limit": "5"}
    query_string = "&".join(f"{quote(key)}={quote(value)}" for key, value in params.items())
    data = fetch_json(f"{SONOVAULT_BASE}/v1/tracks/search?{query_string}", headers={"x-api-key": SONOVAULT_API_KEY})
    items = data.get("results") if isinstance(data, dict) else None
    for item in items or []:
        if not isinstance(item, dict):
            continue
        found_title = first(item.get("title"))
        if not found_title:
            continue
        # 剥掉尾部括号变体（(loop) / (remix) / (instrumental) / (feat. …)）再匹配，
        # 避免把别的版本的 ISRC 误补到这首歌上
        base_title = re.sub(r"\s*\([^)]*\)\s*$", "", found_title).strip()
        if not base_title or not title_is_related(base_title, title):
            continue
        # 标题匹配上了但这条没有任何标识码（loop / 无元数据变体）就继续看下一条
        if not item.get("isrc") and not item.get("iswc"):
            continue
        return {
            "isrc": clean_value(item.get("isrc")),
            "iswc": clean_value(item.get("iswc")),
            "title": found_title,
            "artists": [first(a.get("name")) for a in item.get("artists") or [] if isinstance(a, dict) and first(a.get("name"))],
            "duration": item.get("duration"),
            "source_url": f"https://sonovault.now/track/{item.get('id')}" if item.get("id") else "",
        }
    return {}


# ---- Soundcharts 可选集成（ISRC / ISWC 补查的第二数据源）----
#    认证二选一：OAuth client_credentials（推荐：SOUNDCHARTS_CLIENT_ID / SECRET，
#    Soundcharts 控制台创建 API Client 后可得）或 legacy x-app-id / x-api-key
#    （含公开沙箱 soundcharts / soundcharts）。凭据只从环境变量读取，绝不落盘、
#    不入库、不写日志；两种认证都不配置时整个 Soundcharts 补查静默跳过，零侵入。
#    查询走「按平台曲目 ID 直查」端点（/api/v2.25/song/by-platform/{platform}/{id}），
#    不依赖其标了 internal-use-only 的 search 端点，适合对外的 Sleeve。
SOUNDCHARTS_BASE = "https://customer.api.soundcharts.com"
SOUNDCHARTS_TOKEN_URL = "https://account.soundcharts.com/oauth/token"
SOUNDCHARTS_CLIENT_ID = os.environ.get("SOUNDCHARTS_CLIENT_ID", "").strip()
SOUNDCHARTS_CLIENT_SECRET = os.environ.get("SOUNDCHARTS_CLIENT_SECRET", "").strip()
SOUNDCHARTS_APP_ID = os.environ.get("SOUNDCHARTS_APP_ID", "").strip()
SOUNDCHARTS_API_KEY = os.environ.get("SOUNDCHARTS_API_KEY", "").strip()
SOUNDCHARTS_PLATFORMS = {"apple": "itunes", "spotify": "spotify", "deezer": "deezer"}
SOUNDCHARTS_TOKEN_CACHE: dict[str, Any] = {}


def soundcharts_configured() -> bool:
    """两种认证方式任配其一即启用；全空则 Soundcharts 补查完全跳过。"""
    return bool(
        (SOUNDCHARTS_CLIENT_ID and SOUNDCHARTS_CLIENT_SECRET)
        or (SOUNDCHARTS_APP_ID and SOUNDCHARTS_API_KEY)
    )


def _soundcharts_oauth_token() -> str:
    """client_credentials 换 bearer token（默认 3600s 有效），进程内缓存、失败静默。"""
    cached = SOUNDCHARTS_TOKEN_CACHE.get("token") or ""
    if cached and SOUNDCHARTS_TOKEN_CACHE.get("expires_at", 0) > time.time() + 60:
        return cached
    if not (SOUNDCHARTS_CLIENT_ID and SOUNDCHARTS_CLIENT_SECRET):
        return ""
    basic = "Basic " + base64.b64encode(
        f"{SOUNDCHARTS_CLIENT_ID}:{SOUNDCHARTS_CLIENT_SECRET}".encode()
    ).decode("ascii")
    try:
        req = Request(
            SOUNDCHARTS_TOKEN_URL,
            data=b"grant_type=client_credentials",
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": basic,
            },
            method="POST",
        )
        with GUARDED_OPENER.open(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        token = payload.get("access_token") if isinstance(payload, dict) else ""
        expires_in = int(payload.get("expires_in") or 3600) if isinstance(payload, dict) else 3600
        if token:
            SOUNDCHARTS_TOKEN_CACHE.update(token=token, expires_at=time.time() + expires_in)
        return token
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError):
        return ""


def soundcharts_auth_headers() -> dict[str, str]:
    """优先 OAuth bearer；无 OAuth 凭据或换 token 失败时退回 legacy headers。"""
    token = _soundcharts_oauth_token()
    if token:
        return {"Authorization": f"Bearer {token}"}
    headers: dict[str, str] = {}
    if SOUNDCHARTS_APP_ID:
        headers["x-app-id"] = SOUNDCHARTS_APP_ID
    if SOUNDCHARTS_API_KEY:
        headers["x-api-key"] = SOUNDCHARTS_API_KEY
    return headers


def soundcharts_song_by_platform_id(source: str, track_id: str) -> dict[str, Any]:
    """Soundcharts API：按平台曲目 ID 直查歌曲元数据（ISRC / ISWC / 溯源链接）。

    不配置凭据、来源不在 apple/spotify/deezer、曲目未收录（404）或查询无匹配时
    返回 {}；凭据 / 计划 / 网络等错误向上抛 FetchError，由调用方决定提示还是静默。
    平台代码映射：apple→itunes（Apple Music 歌单才是 apple-music，歌曲用 itunes）、
    spotify、deezer；响应兼容 single-object envelope（{object: …}）与裸对象两种形态。
    """
    if not soundcharts_configured() or not track_id:
        return {}
    platform = SOUNDCHARTS_PLATFORMS.get(source or "")
    if not platform:
        return {}
    headers = soundcharts_auth_headers()
    if not headers:
        return {}
    try:
        data = fetch_json(
            f"{SOUNDCHARTS_BASE}/api/v2.25/song/by-platform/{quote(platform)}/{quote(track_id)}",
            headers=headers,
        )
    except FetchError as exc:
        # 404 = 曲库未收录，是正常结果，静默降级；其余错误（401/403/网络）继续抛
        if "404" in str(exc):
            return {}
        raise
    obj = data.get("object") if isinstance(data, dict) and "object" in data else data
    if not isinstance(obj, dict) or not obj.get("uuid"):
        return {}
    isrc = obj.get("isrc") if isinstance(obj.get("isrc"), dict) else {}
    iswcs = obj.get("iswcs") or []
    return {
        "isrc": clean_value(isrc.get("value")),
        "iswc": " / ".join(clean_value(code) for code in iswcs if clean_value(code)),
        "title": first(obj.get("name")),
        "artists": [
            first(a.get("name"))
            for a in (obj.get("mainArtists") or obj.get("artists") or [])
            if isinstance(a, dict) and first(a.get("name"))
        ],
        "duration": obj.get("duration"),
        "source_url": first(obj.get("appUrl")) or f"https://soundcharts.com/app/song/{obj.get('uuid')}",
    }


def soundcharts_team_usage() -> dict[str, Any]:
    """GET /api/v2/team/usage：Soundcharts 配额与实时限速。

    不配置凭据返回 {}；网络 / 4xx 等错误抛 FetchError。刻意不走 fetch_json，
    避免出网缓存把用量卡在旧值（用量要实时）。仍过 check_outbound 出网闸。
    """
    if not soundcharts_configured():
        return {}
    headers = soundcharts_auth_headers()
    if not headers:
        return {}
    url = f"{SOUNDCHARTS_BASE}/api/v2/team/usage"
    check_outbound(url)
    req = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            **headers,
        },
    )
    try:
        with GUARDED_OPENER.open(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        raise FetchError(str(exc)) from exc
    obj = payload.get("object") if isinstance(payload, dict) and "object" in payload else payload
    if not isinstance(obj, dict):
        return {}
    quota = obj.get("quota") if isinstance(obj.get("quota"), dict) else {}
    rate = obj.get("rateLimit") if isinstance(obj.get("rateLimit"), dict) else {}
    return {
        "quota": {
            "limit": quota.get("limit"),
            "used": quota.get("used"),
            "remaining": quota.get("remaining"),
            "period": quota.get("period"),
            "end_period_date": quota.get("endPeriodDate"),
        },
        "rate_limit": {
            "limit_per_minute": rate.get("limitPerMinute"),
            "used": rate.get("used"),
            "remaining": rate.get("remaining"),
            "reset_in_seconds": rate.get("resetInSeconds"),
        },
    }


def collect_usage_status() -> dict[str, Any]:
    """/api/usage 用：汇总两个 ISRC 补查数据源的配置与用量状态。"""
    sources: dict[str, Any] = {}
    # Sonovault：没有用量查询 API，只报配置状态与限速策略（实时余量在响应头里）
    sources["sonovault"] = {
        "configured": bool(SONOVAULT_API_KEY),
        "usage_api": False,
        "note": "无用量查询接口；免费档限速 20 req/min，实时剩余次数见响应头 ratelimit-remaining",
    }
    # Soundcharts：有 /team/usage 配额端点，实时查询
    sc: dict[str, Any] = {
        "configured": bool(soundcharts_configured()),
        "usage_api": True,
    }
    if sc["configured"]:
        sc["auth"] = "oauth" if (SOUNDCHARTS_CLIENT_ID and SOUNDCHARTS_CLIENT_SECRET) else "legacy"
        try:
            sc["usage"] = soundcharts_team_usage()
        except FetchError as exc:
            sc["error"] = str(exc)
    sources["soundcharts"] = sc
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": sources,
    }


