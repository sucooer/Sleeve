"""MusicBrainz 只读 API 客户端：查询、限速、实体归一化。

**这个模块唯一真正微妙的地方是 mb_request 的限速**（注释写在函数上，
包含完整的来龙去脉）：MB 要求每秒最多 1 个请求，而一次专辑查询会打出
十来个 MB 调用。两件事必须同时对：

  - 限速只约束**真正打到 MB 的请求** —— 命中本地缓存时既不睡也不更新
    时间戳，否则重复查询会被一串无谓的 sleep 拖慢十几秒。
  - 锁只保护「取号」，绝不覆盖网络 IO。早先的写法把 fetch_json 塞在锁里，
    单个用户查 40 首曲目的 work 关系就能让**所有**用户的 MB 通道停摆一分多钟。
    现在是「预约制」：持锁算出出发时刻并预写时间戳，随即放锁，
    sleep 与 HTTP 都在锁外。

MB_BASE / MB_LAST_REQUEST / MB_LOCK 是模块级可变状态，测试用 patch_seam 补丁，
不给函数加参数 —— 生产路径上它们就是全局单例，改动签名反而会掩盖这一点。

这一层只读：工具只**准备**数据供人工提交，从不写回 MusicBrainz。
"""
from __future__ import annotations

import re
import threading
import time
from typing import Any
from urllib.parse import quote, urlparse

# 上游模块（拆分前这些是 app.py 里的同级定义）
from net import CACHE_STATS, FetchError, ascii_url, cache_key, cache_load, fetch_json
from sites import site_info
from values import TITLE_SUFFIX_RE, clean_value, first, format_duration, iso_date, normalize_mb_url, title_is_related

MB_BASE = "https://musicbrainz.org/ws/2"
MB_LAST_REQUEST = 0.0
# 限速时间戳必须与「打请求」这个动作原子地绑在一起，否则并发下形同虚设（见 mb_request）
MB_LOCK = threading.Lock()


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


def mb_request(path: str, params: dict[str, str]) -> Any:
    """MusicBrainz 要求每秒最多 1 个请求（每个应用、每个 IP）。

    限速只约束**真正打到 MusicBrainz 的请求**：命中本地缓存时直接返回，既不睡、
    也不更新 MB_LAST_REQUEST。否则重复查询会被一串无谓的 sleep 拖慢十几秒 ——
    一次查询有十来个 MB 调用，纯等待就超过 10 秒。

    限速必须严格（全局时间戳 + 锁），否则两个并发查询会同时读到旧值、
    都判定「离上次请求已经超过 1 秒」、于是一起打过去 —— 净结果是违反 MB
    每秒 1 次的约束，然后被 503 打回来并记进 source_errors（见 api_notes）。

    **锁只保护「取号」，不覆盖网络 IO**（早先的写法把 fetch_json 也塞在锁里）：
    一次 MB 请求可能耗时 20 秒以上还带重试，锁被占住的这段时间里，
    **所有**其他用户的 MB 查询全部排队干等 —— 单个用户查 40 首曲目的 work
    关系就能让整台服务的 MB 通道停摆一分多钟。

    改成「预约制」：持锁时按 MB_LAST_REQUEST 算出本请求的出发时刻并**预写**进
    MB_LAST_REQUEST，随即放锁，sleep 与真正的 HTTP 请求都在锁外完成。
    于是：
      - 任意两个 MB 请求的实际出发间隔仍 ≥ 1.05 秒（限速约束不变）；
      - 一个慢请求不再占着锁，别人的下一个请求可以立刻预约到后面的号；
      - 预约时刻若已过期（前面那次慢了），下一位会等更久 —— 只会更保守，不会超速。

    限速闸挂在**每一次真正发出去的请求**上（before_attempt），包括 fetch_json
    内部的失败重试 —— 重试同样是一次真实的出网请求，漏掉它就会绕过限速。
    """
    global MB_LAST_REQUEST
    query = "&".join(f"{quote(key)}={quote(value)}" for key, value in params.items())
    url = f"{MB_BASE}/{path}?{query}"
    key = cache_key("GET", ascii_url(url))
    cached = cache_load(key)
    if cached is not None:
        CACHE_STATS.hit += 1
        return cached
    # 预约之前再查一次：等锁期间别的线程可能已经拿到并写好了，别再白等 1 秒
    cached = cache_load(key)
    if cached is not None:
        CACHE_STATS.hit += 1
        return cached

    def reserve() -> None:
        """预约一个出发时刻；到点才真正发请求。"""
        global MB_LAST_REQUEST
        with MB_LOCK:
            now = time.monotonic()
            earliest = MB_LAST_REQUEST + 1.05
            wait = max(0.0, earliest - now)
            MB_LAST_REQUEST = max(now, earliest)
        if wait > 0:
            time.sleep(wait)

    return fetch_json(url, headers={"Accept": "application/json"}, before_attempt=reserve)


def _credit_artist_name(credit: dict[str, Any]) -> str:
    """从一条 artist-credit 里取艺人名。

    刻意加下划线前缀、不对外导出的原因：本文件（以及 app.py）里几十个函数的
    形参就叫 artist_name（用户查询的艺人名），模块级再挂一个同名函数会让
    `artist_name` 在函数体内歧义 —— ruff 的 F811 会直接报「重定义」，
    而真正的原因是两个完全不同的概念撞了名字。
    """
    artist = credit.get("artist") or {}
    return first(credit.get("name")) or first(artist.get("name"))


def mb_artist_credit(credits: list[dict[str, Any]] | None) -> str:
    if not credits:
        return ""
    result = ""
    for credit in credits:
        result += _credit_artist_name(credit)
        result += first(credit.get("joinphrase"))
    return result


def is_valid_ean(code: str) -> bool:
    if not code.isdigit() or len(code) not in (8, 12, 13):
        return False
    digits = [int(char) for char in code]
    body, check = digits[:-1], digits[-1]
    # EAN-13 and EAN-8 start with weight 1; UPC-A starts with weight 3.
    weights = [1, 3] * 6 if len(code) == 13 else ([3, 1] * 6 if len(code) == 12 else [3, 1, 3, 1, 3, 1, 3])
    total = sum(digit * weight for digit, weight in zip(body, weights, strict=False))
    return (10 - total % 10) % 10 == check


def barcode_from_artwork(url: str) -> str:
    segments = [segment for segment in urlparse(url or "").path.split("/") if segment]
    for segment in reversed(segments):
        candidate = re.sub(r"\.(jpe?g|png|gif|webp)$", "", segment, flags=re.I).split(".")[0]
        if is_valid_ean(candidate):
            return candidate
    return ""


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


MAX_WORK_RELS_TRACKS = 40   # 单次报告最多查询这么多首曲的 recording（每首 1 次 + 其 work 各 1 次）
MAX_WORK_RELS_WORKS = 6     # 单曲最多展开这么多个 work 的 artist 关系，多的提示人工


def mb_work_relation_artist(rel: dict[str, Any]) -> dict[str, Any]:
    """把一条 artist 型关系压成前端好渲染的扁平结构。"""
    artist = rel.get("artist") or {}
    return {
        "type": first(rel.get("type")),
        "artist": first(artist.get("name")),
        "artist_mbid": first(artist.get("id")),
        "attributes": [first(a.get("name")) for a in rel.get("attributes") or [] if isinstance(a, dict)] or [],
    }


def mb_work_rels_for_recording(recording_mbid: str) -> dict[str, Any]:
    """查一个 recording 关联的 work 与关系。

    MB 数据模型：recording 通过 performance 关系指向 work；作词 / 作曲 / 编曲等
    大多挂在 work 的 artist-rels 上（少数也直接挂在 recording 上）。这里两步：
      1. recording?inc=artist-rels+work-rels       拿 work 列表 + recording 直接关系；
      2. 对每个 work 再查 work/{id}?inc=artist-rels 拿 work 级 composer/lyricist 等。

    每次调用会打 1 + len(works) 个请求，受 mb_request 的 1 req/s 限速约束。
    """
    data = mb_request(f"recording/{recording_mbid}", {"inc": "artist-rels+work-rels", "fmt": "json"})
    works: list[dict[str, Any]] = []
    recording_relations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rel in data.get("relations") or []:
        if rel.get("direction") not in (None, "forward"):
            continue
        if rel.get("target-type") == "work":
            work = rel.get("work") or {}
            work_id = first(work.get("id"))
            if not work_id or work_id in seen:
                continue
            seen.add(work_id)
            works.append({
                "title": first(work.get("title")),
                "mbid": work_id,
                "type": first(work.get("type")),
                "iswc": clean_value(work.get("iswc")),
                "url": f"https://musicbrainz.org/work/{work_id}",
                "relations": [],
            })
        elif rel.get("target-type") == "artist":
            recording_relations.append(mb_work_relation_artist(rel))
    for work in works[:MAX_WORK_RELS_WORKS]:
        try:
            work_data = mb_request(f"work/{work['mbid']}", {"inc": "artist-rels", "fmt": "json"})
        except FetchError:
            continue
        relations: list[dict[str, Any]] = []
        for rel in work_data.get("relations") or []:
            if rel.get("direction") in (None, "forward") and rel.get("target-type") == "artist":
                relations.append(mb_work_relation_artist(rel))
        work["relations"] = relations
    return {"works": works, "recording_relations": recording_relations}


def mb_search_recording(title: str, artist: str, limit: int = 5) -> list[dict[str, Any]]:
    """MusicBrainz 按「歌名 + 艺人」搜录音，拿 recording 的 MBID / ISRC / 所在发行。

    给单曲查询用：专辑模式下 recording 从匹配上的 release 曲目表里取，不用搜。
    返回按 score 排序的候选列表；评分仅供参考，命中与否最终看标题/艺人/时长人工核对。
    """
    query_parts: list[str] = []
    if title:
        query_parts.append(f'recording:"{mb_query_escape(title)}"')
    if artist:
        query_parts.append(f'artist:"{mb_query_escape(artist)}"')
    if not query_parts:
        return []
    found = mb_request("recording", {"query": " AND ".join(query_parts), "limit": str(limit), "fmt": "json"})
    rows: list[dict[str, Any]] = []
    for item in found.get("recordings") or []:
        mbid = first(item.get("id"))
        if not mbid:
            continue
        rows.append({
            "mbid": mbid,
            "title": clean_value(item.get("title")),
            "artist": mb_artist_credit(item.get("artist-credit")),
            "isrc": next(iter(item.get("isrcs") or []), ""),
            "length_ms": item.get("length") or "",
            "length": format_duration(item.get("length")),
            "score": item.get("score") or 0,
            "releases": [clean_value(rel.get("title")) for rel in (item.get("releases") or []) if clean_value(rel.get("title"))][:4],
            "url": f"https://musicbrainz.org/recording/{mbid}",
        })
    return rows


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


