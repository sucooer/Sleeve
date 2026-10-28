"""站点识别：平台 URL 规则表 + 域名边界匹配。

独立成模块的理由：这张表被**两处**用到，而它们分属不同的关注点 ——
  - 出网闸门（check_outbound）用 site_info 判断「主机是否在已知平台里」；
  - 报告组装（build_external_links）用它给出 MB 关系类型。
这两处都要改这张表时，原来得在 4000 行的同一个文件里两头跳。
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

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
