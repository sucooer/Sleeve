"""启动配置与访问控制：环境变量解析 + 两个「拒绝启动」守卫 + 限流。

这个模块全是**导入期副作用**：读环境变量、校验、不合格就 SystemExit。
放在 app.py 里时，读它得先穿过四千行业务代码；独立出来后
「这个服务怎么配、什么情况下起不来」一眼能看全。

两条守卫都遵循同一个原则：**宁可起不来，也不要静默地以不安全状态对外服务**。

  1. `SLEEVE_AUTH` 格式必须是 user:password。只校验「格不格式」不够 ——
     照着 .env.example 抄一份得到的是「绑定 0.0.0.0 + 空口令」，
     一句 docker compose up -d 就裸奔上线了。所以还要校验它**是否生效**：
     对外监听 + 无鉴权 → 直接拒绝启动，逃生阀是 SLEEVE_AUTH_ALLOW_OPEN=1。
  2. 无鉴权的 /api/lookup 等于一个开放代理：任何人都能借你的 IP 扇出 30~50 个
     出网请求，并把 MusicBrainz「每秒 1 次」的配额打光。

限流遵循本仓库一贯的「配了才启用、没配不改变行为」风格：
    SLEEVE_AUTH=user:password     开启认证
    SLEEVE_RATE_LIMIT=30/60       每 IP 每 60 秒最多 30 次
/api/health 与 /api/login 豁免**认证**（健康探针要能无凭据探测；login 是登录页
换凭据的入口）—— 但 /api/login 绝不免**限流**，否则口令枚举可以无限打。

TTL 的默认值是 12 小时而不是「不过期」：服务端是无状态 Basic 校验，本来没有
会话概念，TTL 是下发给前端的约定。不设 = 永不过期在安全管理上是个坑。
"""
from __future__ import annotations

import base64
import ipaddress
import os
import threading
import time

HOST = os.environ.get("SLEEVE_HOST", "127.0.0.1")
PORT = int(os.environ.get("SLEEVE_PORT", "8765"))


# ------------------------------------------------------------------ 访问控制
#
# 这个服务默认没有任何鉴权，因为它最初只跑在本机 127.0.0.1 上。一旦挂到公网，
# /api/lookup 是**完全裸奔**的：一次调用会扇出十几个对外的请求，任何人拿到地址
# 都能把你的上游额度用光，并让你这台机器的 IP 被 iTunes / Deezer / MusicBrainz
# 一起限流。所以公网部署必须先开这两道闸。
#
# 沿用本仓库一贯的「配了才启用、没配不改变行为」风格：
#     SLEEVE_AUTH=user:password        开启认证（前端显示自定义登录页，替代浏览器原生 Basic 弹框）
#     SLEEVE_RATE_LIMIT=30/60          每 IP 每 60 秒最多 30 次请求
# /api/health 与 /api/login 永远豁免 —— health 供探针使用（响应里带 auth 标志），
# login 是前端登录页的凭据校验入口，凭据在其内部自行比对。
#
# 2026-09-27 补上守卫：原来只校验 SLEEVE_AUTH 的**格式**，不校验它是否**生效**。
# 照着 .env.example 抄一份 .env 得到的就是「绑定 0.0.0.0 + 空口令」，一句
# `docker compose up -d` 就裸奔上线了。现在「对外监听 + 无鉴权」直接拒绝启动，
# 逃生阀是 SLEEVE_AUTH_ALLOW_OPEN=1（见下）。
AUTH_RAW = os.environ.get("SLEEVE_AUTH", "").strip()


AUTH_HEADER = "Basic " + base64.b64encode(AUTH_RAW.encode("utf-8")).decode("ascii") if AUTH_RAW else ""


# 认证有效期（秒）：登录后超过该时长需要重新认证。默认 12 小时；0 = 永不过期。
# 服务端是无状态 Basic 校验，本身没有「会话」概念；TTL 作为约定下发给前端，
# 前端把登录时间戳与 TTL 一起保存，到点自动清除本地凭据并回到登录页。
# 未设置时沿用默认 12h（安全管理上，不设 = 永不过期是一个坑）。
AUTH_TTL_DEFAULT = 12 * 60 * 60


def parse_auth_ttl(raw: str | None) -> int:
    """解析 SLEEVE_AUTH_TTL：未设置 / 空串 / 非法值一律回落默认 12h；显式 "0" 才是永不过期。

    空串必须走默认值：`SLEEVE_AUTH_TTL=` 这种「写了但没填」的配置很常见，
    当成 0 就等于悄悄把凭据改成永不过期，正好与上一行的约定相反。
    """
    text = (raw or "").strip()
    if not text:
        return AUTH_TTL_DEFAULT
    try:
        return int(text)
    except ValueError:
        print(f"[warn] SLEEVE_AUTH_TTL 应为秒数，忽略当前值「{text}」，使用默认 {AUTH_TTL_DEFAULT}。", flush=True)
        return AUTH_TTL_DEFAULT


AUTH_TTL = parse_auth_ttl(os.environ.get("SLEEVE_AUTH_TTL"))


# 逃生阀：确要在可信网络里无鉴权开放时才显式设 1
ALLOW_OPEN_NO_AUTH = os.environ.get("SLEEVE_AUTH_ALLOW_OPEN", "").strip().lower() in {"1", "true", "yes", "on"}


def bind_is_loopback(value: str) -> bool:
    """这个监听 / 发布地址是否只有本机能访问。空值按「全网卡」（0.0.0.0）处理。"""
    host = (value or "").strip().strip("[]").lower()
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# 「对外」看的是**能被谁访问**，不是进程绑在哪个网卡上：
#   - 直接跑 app.py：就是 HOST 本身；
#   - docker compose：容器里必须绑 0.0.0.0（否则宿主机的端口映射进不来），
#     真正决定暴露面的是宿主机上的发布地址，compose 把 ${SLEEVE_BIND}
#     通过 SLEEVE_PUBLISH_BIND 传进来。
EXPOSED_BIND = os.environ.get("SLEEVE_PUBLISH_BIND", "").strip() or HOST
# 对外监听时，500 的正文只留一句「详情见服务端日志」：异常里可能带上游原文、内网主机名与路径
DETAIL_IN_ERRORS = bind_is_loopback(EXPOSED_BIND)


def parse_rate_limit(raw: str) -> tuple[int, int]:
    """把 "30/60" 解析成 (30, 60)；格式不对或未设置则返回 (0, 0) 表示不限流。"""
    raw = (raw or "").strip()
    if not raw:
        return (0, 0)
    try:
        count, window = raw.split("/", 1)
        limit, seconds = int(count), int(window)
    except ValueError:
        print(f"[warn] SLEEVE_RATE_LIMIT 格式应为 次数/秒数，忽略当前值：{raw}", flush=True)
        return (0, 0)
    return (limit, seconds) if limit > 0 and seconds > 0 else (0, 0)


RATE_LIMIT_MAX, RATE_LIMIT_WINDOW = parse_rate_limit(os.environ.get("SLEEVE_RATE_LIMIT", ""))
RATE_LOCK = threading.Lock()
RATE_HITS: dict[str, list[float]] = {}


def rate_limit_allow(client_ip: str) -> bool:
    """滑动窗口限流。只保证「同一个 IP 不会把上游打爆」，不是精确的配额系统。"""
    if not RATE_LIMIT_MAX:
        return True
    now = time.time()
    with RATE_LOCK:
        hits = [stamp for stamp in RATE_HITS.get(client_ip, []) if now - stamp < RATE_LIMIT_WINDOW]
        if len(hits) >= RATE_LIMIT_MAX:
            RATE_HITS[client_ip] = hits
            return False
        hits.append(now)
        RATE_HITS[client_ip] = hits
        # 顺手回收沉寂条目，否则这个 dict 会随来访 IP 数无限增长
        if len(RATE_HITS) > 4096:
            for key in [k for k, v in RATE_HITS.items() if not v or now - v[-1] > RATE_LIMIT_WINDOW]:
                RATE_HITS.pop(key, None)
    return True


