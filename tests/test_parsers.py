"""离线解析器测试：用静态 HTML 样本验证各站点解析器的抽取能力。

这些是当前**语句覆盖率最低**的一批函数（原先只在 build_report 的真实链路里
被顺带触发，测试里既没有断言、也没有 fixture，页面结构一变就无从察觉）：

    search_candidates      0.9%
    parse_ototoy_html      4.5%
    itunes_artist_albums   3.7%
    spotify_album          6.7%
    deezer_album           7.7%
    deezer_album_matches   8.3%
    deezer_album_by_upc   11.1%
    parse_bandcamp_html   14.3%
    parse_mora_html       20.0%

样本放在 tests/fixtures/ 下，刻意做成**精简但结构真实**的片段：
结构不对，测的就不是解析器了。

**全部不出网**：只读本地文件。
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

import app  # noqa: E402

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _fixture(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


# ------------------------------------------------------------------ OTOTOY

def test_parse_ototoy_html_extracts_album_fields_and_tracks():
    html = _fixture("ototoy_album.html")
    result = app.parse_ototoy_html(html, "https://ototoy.jp/_/default/p/123456")

    assert result["status"] == "ok"
    assert result["title"] == "夜に駆ける"
    assert result["artist"] == "YOASOBI"
    assert result["date"] == "2020-12-16"
    assert result["label"] == "Sony Music Labels"
    assert result["catalog_number"] == "AYCJA-1"
    assert result["track_count"] == 2
    assert "4168264" in result["image"]
    assert result["source"] == "ototoy.jp"


def test_parse_ototoy_html_reads_track_rows():
    html = _fixture("ototoy_album.html")
    result = app.parse_ototoy_html(html, "https://ototoy.jp/_/default/p/123456")

    tracks = result["tracks"]
    assert [t["number"] for t in tracks] == ["1", "2"]
    assert tracks[0]["title"] == "あの、Dream."
    assert tracks[0]["length"] == "04:22"
    # 没有艺人链接时回落到专辑艺人
    assert tracks[0]["artist"] == "YOASOBI"
    assert tracks[0]["source"] == "OTOTOY"


def test_parse_ototoy_html_tolerates_missing_optional_blocks():
    """类名 / 结构对不上时不应抛异常，缺失的字段留空即可。"""
    result = app.parse_ototoy_html("<html><body></body></html>", "https://ototoy.jp/_/default/p/1")

    assert result["status"] == "ok"
    assert result["title"] == ""
    assert result["artist"] == ""
    assert result["tracks"] == []
    assert result["track_count"] == 0


# ------------------------------------------------------------------ mora

def test_parse_mora_html_prefers_json_ld():
    html = _fixture("mora_package.html")
    result = app.parse_mora_html(html, "https://mora.jp/package/12345/MORA-12345")

    assert result["status"] == "ok"
    # JSON-LD 优先于 og:title
    assert result["title"] == "Sample mora Album"
    assert result["artist"] == "Sample Artist"
    assert result["date"] == "2021-06-30"
    assert result["label"] == "Sample Label"
    assert result["track_count"] == 3
    assert result["source"] == "mora.jp"


def test_parse_mora_html_falls_back_to_opengraph():
    """没有 JSON-LD 时退回 og:title / og:image。"""
    html = '<html><head><meta property="og:title" content="OG Title"><meta property="og:image" content="https://x/i.jpg"></head></html>'
    result = app.parse_mora_html(html, "https://mora.jp/package/1/ABC-1234")

    assert result["title"] == "OG Title"
    assert result["image"] == "https://x/i.jpg"
    assert result["artist"] == ""


# ------------------------------------------------------------------ Bandcamp

def test_parse_bandcamp_html_strips_platform_suffix():
    html = _fixture("bandcamp_track.html")
    result = app.parse_bandcamp_html(html, "https://artist.bandcamp.com/track/sample")

    assert result["status"] == "ok"
    # 标题尾部的 " | Bandcamp" 要去掉
    assert result["title"] == "Sample Track"
    assert result["image"] == "https://f4.bcbits.com/img/a1234567890_10.jpg"
    assert "Sample description" in result["description"]


# ------------------------------------------------------------------ 品番抽取

def test_catalog_from_url_reads_mora_package_path():
    """mora 的品番固定在 /package/<label_id>/<品番>/ 段。"""
    assert app.catalog_from_url("https://mora.jp/package/12345/MORA-12345") == "MORA-12345"
    # 纯数字品番（Universal 的 UPC 直接当品番用）也要认
    assert app.catalog_from_url("https://mora.jp/package/12345/456789012345") == "456789012345"


def test_catalog_from_url_reads_alnum_code_from_path():
    # 品番的形状：2~6 位字母 + 可选分隔符 + 4~8 位数字
    assert app.catalog_from_url("https://example.com/album/ABC-12345") == "ABC-12345"
    assert app.catalog_from_url("https://ototoy.jp/_/default/p/123456/ABC-12345") == "ABC-12345"


def test_catalog_from_url_returns_empty_when_nothing_matches():
    # 数字太少（不是 4~8 位）不算品番
    assert app.catalog_from_url("https://example.com/album/AYCJA-1") == ""
    assert app.catalog_from_url("https://example.com/album/some-album") == ""
    assert app.catalog_from_url("") == ""


def test_extract_catalog_prefers_parsed_value_then_url_then_body():
    html = _fixture("bandcamp_track.html")
    # 1) 显式解析出来的值最优先
    assert app.extract_catalog(html, "https://x/BC-99887", "PARSED-1") == "PARSED-1"
    # 2) 其次从 URL 取
    assert app.extract_catalog(html, "https://x/album/BC-99887") == "BC-99887"
    # 3) 最后从正文正则取
    assert app.extract_catalog(html, "https://x/album/plain") == "BC-99887"


def test_extract_catalog_reads_japanese_label():
    html = "<p>品番：JPX-2024-001</p>"
    assert app.extract_catalog(html, "https://x/album/plain") == "JPX-2024-001"


# ------------------------------------------------------------------ Deezer 匹配判定

def test_deezer_album_matches_accepts_matching_title_and_artist():
    album = {"title": "Sample Album", "artist": "Sample Artist"}
    assert app.deezer_album_matches(album, "Sample Album", "Sample Artist") is True


def test_deezer_album_matches_tolerates_transliterated_artist():
    """艺人名不一致但标题完全一致时仍然接受（跨区罗马字差异很常见）。"""
    album = {"title": "Sample Album", "artist": "Sample Artist"}
    assert app.deezer_album_matches(album, "Sample Album", "サンプルアーティスト") is True


def test_deezer_album_matches_rejects_different_title():
    album = {"title": "Sample Album", "artist": "Sample Artist"}
    # 标题完全不同（且不共享片段）时必须否掉
    assert app.deezer_album_matches(album, "完全没有关系的唱片名", "Sample Artist") is False


def test_deezer_album_matches_rejects_different_artist_and_title():
    album = {"title": "Sample Album", "artist": "Sample Artist"}
    assert app.deezer_album_matches(album, "完全不相关的标题", "完全不相关的艺人") is False

# ------------------------------------------------------------------ 其它低覆盖解析器

def test_html_meta_reads_both_attribute_orders():
    html = '<meta property="og:title" content="First"><meta content="Second" property="og:title">'
    assert app.html_meta(html, "og:title") == "First"
    assert app.html_meta(html, "missing") == ""


def test_json_ld_summary_reads_album_record():
    html = _fixture("mora_package.html")
    summary = app.json_ld_summary(html)
    assert summary["title"] == "Sample mora Album"
    assert summary["artist"] == "Sample Artist"
    assert summary["track_count"] == 3


def test_json_ld_summary_ignores_non_album_records():
    assert app.json_ld_summary('<script type="application/ld+json">{"@type":"Person","name":"X"}</script>') == {}
    assert app.json_ld_summary("no json here") == {}


def test_strip_html_removes_tags_and_normalizes_space():
    assert app.strip_html("<p>Hello   <b>World</b></p>") == "Hello World"
    assert app.strip_html("") == ""


def test_parse_iso_duration_handles_iso8601():
    assert app.parse_iso_duration("PT4M22S") == "4:22"
    # 小时会折进分钟数（输出统一是 M:SS）
    assert app.parse_iso_duration("PT1H2M3S") == "62:03"
    assert app.parse_iso_duration("garbage") == ""


def test_imprint_from_copyright_extracts_label():
    """Apple 的 ℗ 行里厂牌常写在「A <厂牌> release」里。"""
    assert app.imprint_from_copyright("A Virgin Music release; ℗ 2026 UNIVERSAL MUSIC LLC") == "Virgin Music"
    # 没有「A ... release」结构时取不到厂牌（不猜）
    assert app.imprint_from_copyright("℗ 2021 Sample Label") == ""
    assert app.imprint_from_copyright("") == ""


def test_parse_apple_html_reads_json_ld_album():
    html = """
    <script type="application/ld+json">
    {"@context":"https://schema.org","@type":"MusicAlbum","name":"Apple Album",
     "byArtist":{"@type":"MusicGroup","name":"Apple Artist"},
     "datePublished":"2020-01-02",
     "image":"https://is1-ssl.mzstatic.com/image/thumb/x/300x300bb.jpg",
     "tracks":[{"name":"T1","duration":"PT3M5S"}]}
    </script>
    """
    result = app.parse_apple_html(html, "https://music.apple.com/us/album/x/1")
    assert result["title"] == "Apple Album"
    assert result["artist"] == "Apple Artist"
    assert result["date"] == "2020-01-02"
    assert result["track_count"] == 1
    assert result["tracks"][0]["title"] == "T1"
    assert result["tracks"][0]["length"] == "3:05"
    # 封面 URL 要换成大图
    assert "4000x4000" in result["image"]


def test_extract_mbids_reads_release_and_release_group():
    release, group = app.extract_mbids("https://musicbrainz.org/release/11111111-2222-3333-4444-555555555555")
    assert release == "11111111-2222-3333-4444-555555555555"
    assert group == ""
    release, group = app.extract_mbids("https://musicbrainz.org/release-group/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    assert release == ""
    assert group == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_extract_apple_id_and_country():
    assert app.extract_apple_id("https://music.apple.com/cn/album/x/12345") == "12345"
    assert app.extract_apple_country("https://music.apple.com/cn/album/x/1") == "cn"
    assert app.extract_apple_country("https://example.com/") == ""


def test_extract_spotify_and_deezer_ids():
    assert app.extract_spotify_id("https://open.spotify.com/album/4aawyAB9vmqN3uQ7FjRGTy") == "4aawyAB9vmqN3uQ7FjRGTy"
    assert app.extract_deezer_id("https://www.deezer.com/album/123456") == "123456"
    # upc: 前缀要保留 —— Deezer 的条码反查入口靠它区分两种查法
    assert app.extract_deezer_id("https://www.deezer.com/album/upc:1234567890123") == "upc:1234567890123"


def test_barcode_from_artwork_finds_ean_in_url():
    # 封面 URL 末段去掉扩展名后，剩下的必须**本身就是**一个合法 EAN
    assert app.barcode_from_artwork("https://example.com/img/5099750442227.jpg") == "5099750442227"
    assert app.barcode_from_artwork("https://example.com/cover.jpg") == ""
    # 前后缀会破坏合法性，取不到
    assert app.barcode_from_artwork("https://f4.bcbits.com/img/a5099750442227_10.jpg") == ""


def test_deezer_error_reads_http200_error_envelope():
    """Deezer 用 HTTP 200 + {"error":...} 表达失败 —— 只看异常会静默拿到空数据。"""
    assert "no data" in app.deezer_error({"error": {"type": "DataException", "message": "no data", "code": 800}})
    assert app.deezer_error({"title": "ok"}) == ""
    assert app.deezer_error(None) == ""


def test_barcode_is_plausible_rejects_placeholder():
    assert app.barcode_is_plausible("000000000000") is False
    assert app.barcode_is_plausible("123456789012") is True


def test_merge_tracks_fills_missing_isrc_only_on_aligned_slots():
    left = [{"number": "1", "title": "T1", "isrc": ""}, {"number": "2", "title": "T2", "isrc": ""}]
    right = [{"number": "1", "title": "T1", "isrc": "JP-1"}, {"number": "2", "title": "T2", "isrc": "JP-2"}]
    merged = app.merge_tracks(left, right)
    assert [t.get("isrc") for t in merged] == ["JP-1", "JP-2"]


def test_comparable_sources_builds_field_comparison():
    comparison = app.comparable_sources(
        {"title": "Same", "artist": "X"},
        {"title": "Same", "artist": "X"},
        [],
    )
    title_row = next(row for row in comparison if row["key"] == "title")
    assert title_row["status"] == "match"
    # 两个来源都没有的字段标成 missing，并说明是「公开来源未提供」
    date_row = next(row for row in comparison if row["key"] == "date")
    assert date_row["status"] == "missing"
    assert date_row["note"] == "公开来源未提供"
