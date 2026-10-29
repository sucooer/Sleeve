"""iTunes / Apple Music 客户端（Search + Lookup API，免凭据）。

这一层最反直觉的一点写在缓存块的注释里：iTunes Search API 超限时**静默返回
resultCount: 0**，不是 429。限流会直接伪装成「这张专辑查不到」——
所以「查不到」这个结论永远不可靠，缓存与按条码补查都不是优化而是正确性手段。

另一个坑是 storefront（国家/地区）：同一条专辑在不同 storefront 的
collectionId 不同，而链接里带的地区码未必有货。apple_storefront_chain 按
「链接里的地区 → 用户可能的目标地区」顺序逐个试，任一命中即返回。
WAF_FLAKY_SITES 记录的是会随机返回 WAF 拦截页的站点 —— 那些失败是环境噪音，
重试有意义，不该直接记成 source_error 让用户以为链接坏了。

normalize_itunes 把 Search/Lookup 两种响应形状统一成报告层认识的字段；
itunes_artist_albums 则利用 Apple「按艺人列全部专辑」很全这一点做补查。
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, quote, urljoin, urlparse

# 上游模块（拆分前这些是 app.py 里的同级定义）
from net import FetchError, fetch_json, fetch_text, merge_cache_stats, run_parallel
from values import first, format_duration, iso_date, normalize_mb_url, title_match_key


def extract_apple_id(url: str) -> str:
    # 只在 Apple 域名下取 ID：Deezer / TIDAL 的 /album/<数字> 也会命中同一个模式
    if "apple.com" not in urlparse(url or "").netloc.lower():
        return ""
    match = re.search(r"/(?:album|playlist)/(?:[^/?]+/)?(\d+)(?:[/?]|$)", url or "", re.I)
    if match:
        return match.group(1)
    parsed = urlparse(url or "")
    return parse_qs(parsed.query).get("i", [""])[0]


def extract_apple_song_id(url: str) -> str:
    """单曲链接（music.apple.com/.../song/.../<数字>）里的 trackId。

    单曲 ID 是 trackId 而不是 collectionId，不能直接当专辑 ID 用；
    主流程拿到它之后先 itunes_album_from_song() 转成所属专辑再走专辑查询。
    """
    if "apple.com" not in urlparse(url or "").netloc.lower():
        return ""
    match = re.search(r"/song/(?:[^/?]+/)?(\d+)(?:[/?]|$)", url or "", re.I)
    if match:
        return match.group(1)
    parsed = urlparse(url or "")
    return parse_qs(parsed.query).get("i", [""])[0]


def itunes_album_from_song(track_id: str) -> dict[str, Any]:
    """单曲 ID → 所属专辑。lookup 返回 wrapperType=track，取 collectionId 反查专辑。

    完全查不到（链接失效 / 不是真实曲目）时返回 {}。
    """
    data = fetch_json(f"https://itunes.apple.com/lookup?id={quote(track_id)}&entity=song&limit=1")
    track = next((item for item in data.get("results") or [] if item.get("wrapperType") == "track"), {})
    collection_id = str(track.get("collectionId") or "")
    if not collection_id:
        return {}
    return {
        "collection_id": collection_id,
        "collection_name": first(track.get("collectionName")),
        "track_name": first(track.get("trackName")),
        "artist": first(track.get("artistName")),
        "url": normalize_mb_url(urljoin("https://music.apple.com", first(track.get("collectionViewUrl")))),
    }


CREDIT_SECTION_KEYS = ("performer", "composer-and-lyrics", "production-and-engineering")


def parse_apple_credits(html: str) -> list[dict[str, Any]]:
    """从 Apple Music 歌曲页面 HTML 里解析 Credits 区块。

    页面内嵌 JSON（window 数据）里有 sections：
      - performer：出演艺人（含乐器/声部 roleNames，如 声乐 / 钢琴 / 编程）
      - composer-and-lyrics：作曲和作词（词曲作者）
      - production-and-engineering：制作和工程（制作 / 混音 / 母带 / 工程师等）

    这是**版权方侧**的 credits 数据，MB 上有没有这张专辑、有没有 work 都照常可用，
    是新建 Work / Recording 时挂 relationship 的直接参考。
    角色名与区块标题随页面 locale 变化（中文：词曲作者；英文：songwriter），按原样保留。
    """
    if not html:
        return []
    match = re.search(r'"sections":(\[)', html)
    if not match:
        return []
    try:
        decoder = json.JSONDecoder()
        sections, _ = decoder.raw_decode(html[match.start() + len('"sections":'):])
    except (ValueError, json.JSONDecodeError):
        return []
    groups: list[dict[str, Any]] = []
    for section in sections or []:
        section_id = section.get("id") or ""
        if section_id not in CREDIT_SECTION_KEYS:
            continue
        items = []
        for item in section.get("items") or []:
            name = first(item.get("name"))
            if not name:
                continue
            items.append({
                "name": name,
                "roles": [first(role) for role in item.get("roleNames") or [] if first(role)] or [],
            })
        if items:
            groups.append({"id": section_id, "title": first(section.get("title")) or section_id, "items": items})
    return groups


def collect_apple_credits(url: str, track_title: str = "") -> dict[str, Any]:
    """抓取 Apple 歌曲页并解析 Credits。不是歌曲页 / 页面无 Credits 时返回 {}。

    失败不抛异常（页面暂时抓不到时由调用方记一条 source_warning）。

    注意：Apple 的专辑展开页（album/…?i=<trackId>）只渲染 tracklist 和推荐，
    不渲染 Credits 区块；词曲/制作 credits 只在歌曲页（/song/<trackId>）出现。
    所以专辑展开页进来时改抓对应歌曲页（保留 storefront 段）。
    """
    if not url or "apple.com" not in urlparse(url or "").netloc.lower():
        return {}
    parsed = urlparse(url)
    # 只处理具体曲目页：/song/ 路径，或专辑页带 ?i=<trackId> 的展开
    if "/song/" not in parsed.path and "i=" not in parsed.query:
        return {}
    # 专辑展开页 → 歌曲页：/us/album/<slug>/<albumId>?i=<trackId> → /us/song/<trackId>
    if "/song/" not in parsed.path:
        track_id = parse_qs(parsed.query).get("i", [""])[0]
        if not track_id:
            return {}
        m = re.match(r"^/([a-z]{2})/album/", parsed.path)
        storefront = m.group(1) if m else ""
        url = f"https://music.apple.com/{storefront}/song/{track_id}" if storefront else f"https://music.apple.com/song/{track_id}"
    try:
        html = fetch_text(url)
    except FetchError:
        return {}
    groups = parse_apple_credits(html)
    if not groups:
        return {}
    return {
        "track": track_title or "",
        "source_url": url,
        "groups": groups,
    }


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

    **探测顺序**：链接自带的区先查（这是最常命中的一区，命中就能省掉后面 3 次请求）；
    只有它没给出「艺人名对得上 + 带完整曲目表」的理想结果时，才把剩下的区**并行**去查。
    这样最常见的路径请求数不变（仍是一次），而「链接区缺数据」这种慢路径的等待时间
    从「各区耗时相加」降到「最慢的那一个」。

    **代价**（知情取舍）：慢路径下并行会把本来能被 break 跳过的区也发出去，
    首次查询的上游请求数最多从 2 涨到 4。iTunes lookup 是宽松的公开接口，
    且每个区的响应都进本地缓存（默认 TTL 1 小时），同一张碟重复查询不再出网，
    因此这里选择用「多发几次」换「等待时间不叠加」。结果的选择语义完全不变：
    各区仍按 chain 的顺序并入，第一个满足理想条件的区胜出。
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

    chain = apple_storefront_chain(preferred_country)

    def lookup(code: str) -> dict[str, Any]:
        suffix = f"&country={code}" if code else ""
        try:
            return normalize_itunes(fetch_json(f"https://itunes.apple.com/lookup?id={quote(apple_id)}&entity=song{suffix}"))
        except FetchError:
            return {}

    def absorb(code: str, data: dict[str, Any]) -> bool:
        """把这个区的结果并进状态；返回 True 表示「已拿到理想结果，可以停」。"""
        nonlocal primary, primary_country, primary_artist_ok, jp_data
        nonlocal matched_donor, matched_donor_country, donor_data, donor_tracks, donor_country
        nonlocal preferred_found, preferred_tracks, preferred_artist_ok
        if not first(data.get("title")):
            return False
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
        return bool(primary_artist_ok and primary.get("tracks"))

    # 第一区（链接自带区）单独同步查：它命中就是最常见的快路径，没必要多发 3 次请求
    done = absorb(chain[0], lookup(chain[0]))
    if not done and len(chain) > 1:
        rest = chain[1:]
        outcomes = run_parallel([lambda c=code: lookup(c) for code in rest])
        merge_cache_stats([(item.hit_delta, item.miss_delta) for item in outcomes])
        for index, outcome in enumerate(outcomes):
            # 仍按 chain 的顺序并入：主来源 / donor 的选取依赖「先到先得」的顺序语义
            if outcome.error is not None:
                continue
            if absorb(rest[index], outcome.value or {}):
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


def choose_itunes_candidate(candidates: list[dict[str, Any]], title_hint: str, artist_hint: str) -> dict[str, Any]:
    def score(candidate: dict[str, Any]) -> tuple[int, int]:
        title_match = int(title_match_key(candidate.get("title")) == title_match_key(title_hint)) if title_hint else 0
        artist_match = int(bool(artist_hint) and first(candidate.get("artist")).casefold().replace(" ", "") == artist_hint.casefold().replace(" ", ""))
        return artist_match, title_match
    return max(candidates, key=score, default={})


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


