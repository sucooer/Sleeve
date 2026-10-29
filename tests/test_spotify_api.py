"""Spotify 官方 Web API 适配层测试。

默认走 groover.co 免凭据反代（第三方未公开接口）；配了 SPOTIFY_CLIENT_ID /
SPOTIFY_CLIENT_SECRET 就走官方 API。两条通道的响应形状不同，中间必须有规整层
（spotify_normalize_album）—— 官方 API **没有 label 字段**，厂牌只能从版权行推。

**全部不出网**：只 mock 网络函数。
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

import app  # noqa: E402
from testkit import patch_seam  # noqa: E402


# ------------------------------------------------------------------ Spotify 官方 API 适配层

def test_spotify_not_configured_without_credentials():
    assert app.spotify_configured() is False
    assert app.spotify_auth_headers() == {}


def test_spotify_normalize_album_maps_official_shape():
    """官方 API 的响应要规整成内部统一结构（两条通道对外一致）。"""
    official = {
        "id": "abc123",
        "name": "Album Title",
        "release_date": "2020-01-02",
        "external_urls": {"spotify": "https://open.spotify.com/album/abc123"},
        "external_ids": {"upc": "5099750442227"},
        "total_tracks": 2,
        "images": [{"url": "https://i.scdn.co/image/abc"}],
        "artists": [{"name": "Artist One"}, {"name": "Artist Two"}],
        "copyrights": [{"text": "℗ 2020 Some Label"}],
        "tracks": {"items": [
            {"name": "T1", "track_number": 1, "disc_number": 1, "duration_ms": 262000,
             "artists": [{"name": "Artist One"}], "external_ids": {"isrc": "JP-1"}},
            {"name": "T2", "track_number": 2, "disc_number": 1, "duration_ms": 180000,
             "artists": [{"name": "Artist Two"}], "external_ids": {"isrc": "JP-2"}},
        ]},
    }
    result = app.spotify_normalize_album(official)

    assert result["title"] == "Album Title"
    assert result["artist"] == "Artist One / Artist Two"
    assert result["upc"] == "5099750442227"
    assert result["barcode"] == "5099750442227"
    assert result["date"] == "2020-01-02"
    assert result["track_count"] == 2
    assert result["url"] == "https://open.spotify.com/album/abc123"
    assert result["image"] == "https://i.scdn.co/image/abc"
    # 逐轨字段
    assert [t["title"] for t in result["tracks"]] == ["T1", "T2"]
    assert result["tracks"][0]["isrc"] == "JP-1"
    assert result["tracks"][0]["length"] == "4:22"
    assert result["tracks"][0]["artist"] == "Artist One"


def test_spotify_normalize_album_derives_label_from_copyrights():
    """官方 API 没有 label 字段，只能从版权行推；推不出就留空，不伪造。"""
    official = {
        "id": "abc", "name": "T", "artists": [{"name": "A"}],
        "external_ids": {"upc": "5099750442227"},
        "copyrights": [{"text": "℗ 2020 Real Label"}],
        "tracks": {"items": []},
    }
    assert app.spotify_normalize_album(official)["label"] == "Real Label"


def test_spotify_normalize_album_returns_empty_for_bad_payload():
    assert app.spotify_normalize_album({}) == {}
    assert app.spotify_normalize_album(None) == {}
    assert app.spotify_normalize_album({"id": ""}) == {}


def test_spotify_album_falls_back_to_proxy_when_official_fails(monkeypatch):
    """官方通道失败时回落到反代，不能让 Spotify 整条线索断掉。"""
    patch_seam(monkeypatch, "spotify_configured", lambda: True)
    patch_seam(monkeypatch, "spotify_api_get", lambda path, params=None: (_ for _ in ()).throw(app.FetchError("boom")))

    def fake_post(url, payload, headers=None, timeout=25, retries=2):
        return {"id": "proxy1", "name": "Proxy Album", "external_ids": {"upc": "1111111111111"},
                "artists": [{"name": "P"}], "tracks": {"items": []}}

    patch_seam(monkeypatch, "post_json", fake_post)
    result = app.spotify_album("abc")
    assert result["title"] == "Proxy Album"
    assert result["upc"] == "1111111111111"


def test_spotify_album_prefers_official_api_when_configured(monkeypatch):
    patch_seam(monkeypatch, "spotify_configured", lambda: True)
    patch_seam(monkeypatch, "spotify_api_get", lambda path, params=None: {
        "id": "official1", "name": "Official Album", "artists": [{"name": "O"}],
        "external_ids": {"upc": "2222222222222"}, "tracks": {"items": []},
    })
    patch_seam(monkeypatch, "post_json", lambda *a, **k: (_ for _ in ()).throw(AssertionError("不应走反代")))
    result = app.spotify_album("abc")
    assert result["title"] == "Official Album"
    assert result["upc"] == "2222222222222"
