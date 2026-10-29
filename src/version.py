"""版本号与出站 User-Agent。

版本号是**纯 tag 驱动**的：CI 用 --build-arg VERSION → ENV SLEEVE_VERSION
注入，代码里永远不硬编码第二份版本号（硬编码的版本号必然与 tag 漂移）。
所以这个模块只有两件事：把环境变量读成版本号，以及由它派生出 UA。

单独成模块是因为 UA 散落在各处出网调用里（iTunes / Deezer / MusicBrainz /
Soundcharts / Spotify），而这些调用将分属不同模块 —— 谁都不该为了拼一个
header 去 import 一个四千行的 app。
"""
from __future__ import annotations

import os


def resolve_version(raw: str | None = None) -> str:
    """应用版本号。镜像里由 CI 传 --build-arg VERSION → ENV SLEEVE_VERSION 注入；
    本地直接跑没有这个环境变量时降级为 dev —— 代码里永远不硬编码第二份版本号。"""
    value = (raw if raw is not None else os.environ.get("SLEEVE_VERSION", "")).strip()
    return value or "dev"


VERSION = resolve_version()

# 上游基本都希望调用方能被识别；UA 带上版本号，排查「只有某个版本才出的问题」才有靶子
USER_AGENT = f"Sleeve/{VERSION} (local metadata preparation tool)"
