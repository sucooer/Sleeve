"""Deezer 公开 API 客户端（免凭据）。

这个模块里最值得注意的是 **Deezer 的错误约定**：失败时返回的是
HTTP 200 + `{"error": {...}}`，而不是 4xx / 429。实测（2026-09-26）：

    /album/999999999999        -> 200 {"error":{"type":"DataException","code":800}}
    连续快速请求 60 次         -> 全部 200，没有一次 429

所以**任何只靠异常判断成败的地方都会静默拿到空数据** —— 表现为「这张专辑
查得到但字段全空」，而不是报错。deezer_error 就是为此存在的，每个调用点
都必须显式过一遍它，不能只 try/except。

UPC 查询（deezer_album_by_upc）另有一层校验：Deezer 对不存在的 UPC 会返回
**某个无关专辑**而不是空结果，所以 barcode_is_plausible 与 deezer_album_matches
要一起用，光看「有没有返回」会把错误专辑当命中。
"""
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import quote

# 上游模块（拆分前这些是 app.py 里的同级定义）
from net import FetchError, fetch_json
from values import clean_value, first, format_duration, iso_date, title_is_related, title_match_key


def extract_deezer_track_id(url: str) -> str:
    match = re.search(r"deezer\.com/(?:[a-z-]{2,5}/)?track/(\d+)", url or "", re.I)
    return match.group(1) if match else ""


def deezer_track(track_id: str) -> dict[str, Any]:
    """Deezer 公开 API 的 /track/<id>：单曲的 isrc / 所属专辑 / 时长 / 发行日期一次拿齐。"""
    data = fetch_json(f"{DEEZER_BASE}/track/{quote(track_id)}")
    if not isinstance(data, dict) or deezer_error(data) or not data.get("id"):
        return {}
    album = data.get("album") if isinstance(data.get("album"), dict) else {}
    artist = data.get("artist") if isinstance(data.get("artist"), dict) else {}
    duration = data.get("duration")
    return {
        "id": str(data.get("id") or ""),
        "title": first(data.get("title")) or first(data.get("title_short")),
        "artist": first(artist.get("name")),
        "album": first(album.get("title")),
        "album_id": str(album.get("id") or ""),
        "album_url": f"https://www.deezer.com/album/{album.get('id')}" if album.get("id") else "",
        "isrc": clean_value(data.get("isrc")),
        "date": iso_date(data.get("release_date")),
        "length": format_duration(int(duration) * 1000) if isinstance(duration, (int, float)) else "",
        "url": first(data.get("link")) or f"https://www.deezer.com/track/{quote(track_id)}",
        "image": deezer_cover_large(first(data.get("cover_xl")) or first(data.get("cover_big"))),
        "source": "Deezer 曲目",
    }


DEEZER_BASE = "https://api.deezer.com"
DEEZER_TYPE_MAP = {"album": "Album", "single": "Single", "ep": "EP", "compile": "Album", "bundle": "Album"}


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


