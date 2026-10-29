"""来源页面解析：把「用户贴进来的那个链接」变成结构化字段。

这一层是**离线**的 —— 只吃 HTML 字符串和 URL，不自己发请求（唯一例外是
source_page_summary，它负责取页面再分发）。因此 tests/fixtures/ 里的
真实页面存档能直接喂进来跑，不用联网也不用打桩，这正是它值得独立成模块的原因：
36 个解析测试全部落在这一层，而它们和 HTTP 服务器之间毫无关系。

各站点的解析器按「可靠性从高到低」退化：
  Apple  Music 页 —— 有 JSON-LD，优先走它
  mora          —— JSON-LD + og: 标签
  OTOTOY        —— 没有结构化数据，只能正则扒表格
  Bandcamp      —— 只有 og: 标签
  其它          —— 退到 og: / description 兜底
兜底路径必须存在：用户贴的可能是任何站点，宁可只拿到标题也不要整个查询失败。
"""
from __future__ import annotations

import json
import re
from html import unescape
from typing import Any
from urllib.parse import urlparse

# 上游模块（拆分前这些是 app.py 里的同级定义）
from net import FetchError, fetch_text
from values import first, iso_date, named_text


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


def extract_date_text(value: str) -> str:
    match = re.search(r"\d{4}-\d{2}-\d{2}", value or "")
    return match.group(0) if match else ""


def parse_ototoy_html(html: str, url: str) -> dict[str, Any]:
    title_match = re.search(r'<h1[^>]+class=["\'][^"\']*album-title[^"\']*["\'][^>]*>(.*?)</h1>', html, re.I | re.S)
    artist_match = re.search(r'<p[^>]+class=["\'][^"\']*album-artist[^"\']*["\'][^>]*>(.*?)</p>', html, re.I | re.S)
    date_match = re.search(r'<p[^>]+class=["\'][^"\']*release-day[^"\']*["\'][^>]*>(.*?)</p>', html, re.I | re.S)
    label_match = re.search(r'<p[^>]+class=["\'][^"\']*label-name[^"\']*["\'][^>]*>(.*?)</p>', html, re.I | re.S)
    catalog_match = re.search(r'<p[^>]+class=["\'][^"\']*catalog-id[^"\']*["\'][^>]*>(.*?)</p>', html, re.I | re.S)
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


def extract_deezer_id(url: str) -> str:
    match = re.search(r"deezer\.com/(?:[a-z-]{2,5}/)?album/(upc:)?(\d+)", url or "", re.I)
    if not match:
        return ""
    return f"upc:{match.group(2)}" if match.group(1) else match.group(2)


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


