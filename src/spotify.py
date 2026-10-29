"""Spotify 客户端：官方 Web API 优先，未配凭据时回落到免凭据反代。

两条路都保留是刻意的：官方接口需要用户自己申请 Client ID / Secret，
而 groover.co 反代即开即用。但反代是第三方**未公开**接口 —— 改版、加防爬盾、
换路径都会让它静默下线，所以配置了官方凭据就优先走官方，没有才回落。
回落是静默的：用户不该因为别人家的接口挂了而看到报错。

官方接口也带来一个字段上的差异：反代的响应里有 `label`，而 Web API 的
album 对象没有 —— 由 spotify_normalize_album 统一成同一种形状，
上层不必知道自己拿到的是哪条路。

SPOTIFY_PROXY_HEADERS 里那个 X-CSRFToken 是反代自己的固定值，不是凭据，
写死即可（它公开在那个站点的前端 JS 里，没有任何保密性）。
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
from net import FetchError, GUARDED_OPENER, fetch_json, post_json
from version import USER_AGENT
from values import clean_value, first, format_duration, iso_date, title_is_related


def extract_spotify_id(url: str) -> str:
    match = re.search(r"open\.spotify\.com/(?:intl-[a-z-]+/)?album/([A-Za-z0-9]{22})", url or "", re.I)
    return match.group(1) if match else ""


def extract_spotify_track_id(url: str) -> str:
    match = re.search(r"open\.spotify\.com/(?:intl-[a-z-]+/)?track/([A-Za-z0-9]{22})", url or "", re.I)
    return match.group(1) if match else ""


SPOTIFY_PROXY_BASE = "https://groover.co/core"
SPOTIFY_PROXY_HEADERS = {
    "Origin": "https://groover.co",
    "Referer": "https://groover.co/",
    "X-CSRFToken": "/za/warudo/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
}


# ---- Spotify 官方 Web API（可选，配置了凭据就用它）----
#
# 默认走 groover.co 的免凭据反代：即开即用，但那是第三方未公开的接口 ——
# 改版、加防爬盾、换路径都可能让它静默下线。配了官方凭据就走官方接口，
# 没配就继续用反代，两条路都能出数据。
SPOTIFY_API_BASE = "https://api.spotify.com/v1"
SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
SPOTIFY_CLIENT_ID = os.environ.get("SPOTIFY_CLIENT_ID", "").strip()
SPOTIFY_CLIENT_SECRET = os.environ.get("SPOTIFY_CLIENT_SECRET", "").strip()
SPOTIFY_TOKEN_CACHE: dict[str, Any] = {}


def spotify_configured() -> bool:
    """是否配置了 Spotify 官方凭据（全空则官方通道完全跳过）。"""
    return bool(SPOTIFY_CLIENT_ID and SPOTIFY_CLIENT_SECRET)


def _spotify_oauth_token() -> str:
    """client_credentials 换 bearer token（默认 3600s 有效），进程内缓存、失败静默。

    与 Soundcharts 的实现同构：凭据只从环境变量读，绝不写进代码 / 仓库 / 日志。
    """
    cached = SPOTIFY_TOKEN_CACHE.get("token") or ""
    if cached and SPOTIFY_TOKEN_CACHE.get("expires_at", 0) > time.time() + 60:
        return cached
    if not spotify_configured():
        return ""
    basic = "Basic " + base64.b64encode(
        f"{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}".encode()
    ).decode("ascii")
    try:
        req = Request(
            SPOTIFY_TOKEN_URL,
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
            SPOTIFY_TOKEN_CACHE.update(token=token, expires_at=time.time() + expires_in)
        return token
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return ""


def spotify_auth_headers() -> dict[str, str]:
    """官方 API 的 Authorization 头；换不到 token 时返回空 dict（调用方自行降级）。"""
    token = _spotify_oauth_token()
    return {"Authorization": "Bearer " + token} if token else {}


def spotify_api_get(path: str, params: dict[str, str] | None = None) -> Any:
    """官方 Spotify Web API 的 GET；失败抛 FetchError，由调用方降级到反代。"""
    headers = spotify_auth_headers()
    if not headers:
        raise FetchError("未配置 Spotify 官方凭据")
    query = "&".join(f"{quote(key)}={quote(value)}" for key, value in (params or {}).items())
    url = f"{SPOTIFY_API_BASE}/{path.lstrip('/')}" + (f"?{query}" if query else "")
    return fetch_json(url, headers=headers)


def spotify_normalize_album(data: Any) -> dict[str, Any]:
    """把官方 API 的专辑响应规整成内部统一结构。

    **这一步不能省**：官方 API 与 groover 反代的响应形状并不相同，
    直接把官方响应当成反代响应用，会静默丢字段：

      | 内部字段        | groover 反代 | 官方 API                     |
      |-----------------|-------------|------------------------------|
      | external_ids.upc| ✓           | ✓                            |
      | total_tracks    | ✓           | ✓                            |
      | tracks.items    | ✓           | ✓（在 items 数组里）          |
      | copyrights[].text| ✓         | ✓                            |
      | **label（厂牌）**| ✓          | **✗ 官方响应没有这个字段**    |
      | artist_name     | ✓（单曲用） | ✗ 官方是 artists[].name       |

    厂牌是从版权行推出来的（官方只有 copyrights），推不出就留空 —— 但不能
    假装有值。调用方据此知道「官方通道拿不到厂牌」。
    """
    if not isinstance(data, dict) or not data.get("id"):
        return {}
    raw_tracks = data.get("tracks")
    items = raw_tracks.get("items") if isinstance(raw_tracks, dict) else raw_tracks
    tracks: list[dict[str, Any]] = []
    for index, item in enumerate(items or [], 1):
        if not isinstance(item, dict):
            continue
        artists = [first(artist.get("name")) for artist in item.get("artists") or [] if isinstance(artist, dict)]
        tracks.append({
            "number": str(item.get("track_number") or index),
            "disc": str(item.get("disc_number") or ""),
            "title": first(item.get("name")),
            "artist": " / ".join(name for name in artists if name),
            "length": format_duration(item.get("duration_ms")),
            "isrc": item_isrc(item),
            "recording_mbid": "",
            "source": "Spotify",
        })
    images = data.get("images") or []
    copyrights = [first(item.get("text")) for item in data.get("copyrights") or [] if isinstance(item, dict)]
    external_ids = data.get("external_ids") or {}
    upc = first(external_ids.get("upc")) if isinstance(external_ids, dict) else ""
    # 官方没有 label 字段；厂牌只能从版权行里猜（「℗ 2021 X」/「(P) 2021 X」）
    label = ""
    for text in copyrights:
        candidate = re.sub(r"^\s*[℗©(]\s*\d{4}\s*", "", text).strip(" -")
        if candidate and not re.fullmatch(r"\d{4}", candidate):
            label = candidate
            break
    return {
        "url": first((data.get("external_urls") or {}).get("spotify")),
        "status": "ok",
        "title": first(data.get("name")),
        "artist": " / ".join(first(artist.get("name")) for artist in data.get("artists") or [] if isinstance(artist, dict) and first(artist.get("name"))),
        "date": iso_date(data.get("release_date")),
        "label": clean_value(label),
        "barcode": upc,
        "upc": upc,
        "copyrights": copyrights,
        "track_count": data.get("total_tracks") or len(tracks),
        "tracks": tracks,
        "image": first((images[0] or {}).get("url")) if images and isinstance(images[0], dict) else "",
        "source": "Spotify",
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
    # 注意：proxy 对 track 返回的是简化结构（album_name / thumbnail），
    # 不含 album id / album url / isrc —— 专辑跳转交给用户用专辑链接再查
    return {
        "id": first(data.get("id")),
        "title": first(data.get("name")),
        "artist": first(data.get("artist_name")),
        "album": first(data.get("album_name")),
        "album_id": "",
        "album_url": "",
        "isrc": "",
        "date": iso_date(data.get("release_date")),
        "length": format_duration(data.get("duration_ms")),
        "url": first(data.get("external_url")) or f"https://open.spotify.com/track/{track_id}",
        "image": first(data.get("thumbnail")),
        "source": "Spotify 曲目",
    }


def spotify_album(album_id: str) -> dict[str, Any]:
    """取 Spotify 专辑数据。

    两条通道：
      1. 配了官方凭据（SPOTIFY_CLIENT_ID / SPOTIFY_CLIENT_SECRET）→ 走官方 Web API；
      2. 官方通道失败（无凭据 / 401 / 网络）→ 回落到 groover 免凭据反代。

    官方通道优先是因为反代是第三方未公开接口，随时可能下线；官方通道的响应
    形状与反代不同，先经 spotify_normalize_album 规整再返回，两条通道对外
    暴露的结构完全一致，调用方无需区分。
    """
    if spotify_configured():
        try:
            normalized = spotify_normalize_album(spotify_api_get(f"albums/{album_id}"))
            if normalized:
                return normalized
        except FetchError:
            # 官方通道失败不报错：静默回落到反代，保证「配不配凭据都能用」
            pass
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


def item_isrc(item: dict[str, Any]) -> str:
    external = item.get("external_ids")
    return first(external.get("isrc")) if isinstance(external, dict) else ""


