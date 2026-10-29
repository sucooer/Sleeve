"""值归一化：把上游五花八门的返回值收拾成「能直接写进报告」的字符串。

这些函数被 200 多处调用（first 一个就 280 处），是整个 app 里复用最广的一层。
抽出来是因为它们**没有任何依赖**、语义也彼此独立，属于典型的「谁都在用、
谁都不拥有」的代码 —— 留在 app.py 里只会让它继续膨胀。

MB_PLACEHOLDERS 是这一层存在的核心理由：MusicBrainz 用 "[no label]"、
"[unknown]" 这类**占位符**表示「这个字段没有值」，而它们全是合法字符串。
直接当值用会让报告里出现「厂牌：[no label]」这种伪数据，还会覆盖掉真正
查到的厂牌 —— 所以清值是数据正确性问题，不是美化。
"""
from __future__ import annotations

from typing import Any


def first(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


MB_PLACEHOLDERS = {"[no label]", "[none]", "[no catalog number]", "[unknown]", "[no barcode]", "[no title]", "[untitled]"}


def clean_value(value: Any) -> str:
    text = first(value).strip()
    return "" if text.casefold() in MB_PLACEHOLDERS else text


def named_text(value: Any) -> str:
    if isinstance(value, dict):
        return first(value.get("name"))
    if isinstance(value, list):
        return " / ".join(named_text(item) for item in value if named_text(item))
    return first(value)


def format_duration(milliseconds: Any) -> str:
    try:
        total_seconds = max(0, round(int(milliseconds) / 1000))
    except (TypeError, ValueError):
        return ""
    return f"{total_seconds // 60}:{total_seconds % 60:02d}"


def iso_date(value: Any) -> str:
    text = first(value)
    return text[:10] if text else ""


