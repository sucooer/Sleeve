# Sleeve · 数字合辑建库助手

MusicBrainz 建库资料准备工具：粘贴专辑链接即可自动倒查品番、条码、厂牌和逐轨 ISRC。
**只准备与校对资料，不自动提交编辑** —— 冲突、条码、Artist Credit 与封面仍需人工确认。

## 功能

- 支持 Apple Music / Spotify / Deezer / Qobuz / OTOTOY / mora / TIDAL / Bandcamp 等 35+ 平台链接
- 反查 MusicBrainz，拿回品番、条码、厂牌与逐轨 ISRC，并横向比对标出一致 / 缺失 / 冲突
- 单曲报告自动补 ISRC / ISWC：Sonovault（免费）与 Soundcharts（可选商业）两个数据源
  交叉引用，查不到时静默降级，平台已给的值绝不覆盖
- 生成 Add release 用的 External links（含关系类型）、Track Parser、Annotation 草稿，
  附带查重、发行地区、艺人 MBID 与发行组候选
- 导出 Markdown / JSON / XML 工作单

## 快速开始

```bash
python src/app.py
```

打开 http://localhost:8765

## 目录结构

```
sleeve/
├── src/                 # 代码：app.py（后端）+ app.js / styles.css（前端）
├── public/              # 纯静态资源，原样对外（index.html、图标、manifest）
├── tests/               # 纯函数回归测试（pytest，无网络依赖）
├── docker-compose.yml   # 部署编排
├── .env.example         # 部署配置示例
```

## 环境变量

本机运行无需设置

| 变量 | 默认 | 说明 |
|---|---|---|
| `SLEEVE_AUTH` | 空 | `user:password` 则开启 HTTP Basic；**留空且监听地址对外时会拒绝启动** |
| `SLEEVE_AUTH_ALLOW_OPEN` | 空 | 逃生阀：确要在可信网络里无鉴权开放才设 `1`（不推荐） |
| `SLEEVE_RATE_LIMIT` | 空 | `次数/秒数`，按 IP 限流，只覆盖 `/api/*` |
| `SLEEVE_HOST` / `SLEEVE_PORT` | `127.0.0.1` / `8765` | 监听地址与端口；容器内必须是 `0.0.0.0` |
| `SLEEVE_PUBLISH_BIND` | 同 `SLEEVE_HOST` | 判断「是否对外」用的发布地址；compose 用 `SLEEVE_BIND` 自动填 |
| `SLEEVE_CACHE_DIR` | 系统临时目录 | 缓存落点，**部署时务必指到持久化路径** |
| `SLEEVE_CACHE` / `SLEEVE_CACHE_TTL` | `1` / `3600` | 出网缓存的开关与有效期（秒） |
| `SLEEVE_IPV4_FIRST` | `1` | IPv4 优先；仅当本机 IPv6 **确实可用**时设 `0` |
| `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` | 空 | 出网代理，由 `SLEEVE_OUTBOUND_PROXY` 注入 |
| `SONOVAULT_API_KEY` | 空 | Sonovault 免费 API 密钥：平台没给 ISRC 时按「艺人 + 标题」交叉引用补 ISRC / ISWC（93M 录音目录） |
| `SOUNDCHARTS_CLIENT_ID` / `SOUNDCHARTS_CLIENT_SECRET` | 空 | Soundcharts OAuth 凭据（推荐）：Sonovault 未命中时按平台曲目 ID 直查 ISRC / ISWC / 溯源 |
| `SOUNDCHARTS_APP_ID` / `SOUNDCHARTS_API_KEY` | 空 | Soundcharts legacy 凭据（官方已标弃用但仍可用），与 OAuth 二选一 |

### ISRC / ISWC 补查（可选数据源）

单曲报告在平台没给 ISRC（主要是 Spotify 代理）时自动补查，**两级降级**：

1. **Sonovault**（免费，申请即有 API key）：按「艺人 + 标题」搜索 93M 录音目录。
   CJK 原文标题不索引，日文歌可试罗马字（如 `夜に駆ける` → `Yoru ni Kakeru`）。
2. **Soundcharts**（商业 API，控制台创建 API Client 申请凭据）：Sonovault 未命中时
   按平台曲目 ID 直查（不依赖被限制的搜索端点），覆盖更广、返回 ISWC 与 Work 关联。
   免费试用 1000 次，之后按档位计费（约 $50/月起）。

两个源**都不配置则完全跳过**（零侵入）；平台已给的 ISRC 绝不覆盖；查不到就静默，
不制造噪音。凭据只从环境变量读取，绝不写入代码、仓库或日志。

**用量监控**：`GET /api/usage` 返回两个数据源的配置状态与 Soundcharts 实时配额
（免费试用 1000 次，`quota.remaining` 可见余量）；Sonovault 无用量接口，只有响应头
`ratelimit-remaining`（免费档 20 req/min）。未配置的源不会触发任何请求。

对外监听（`0.0.0.0` 或局域网地址）必须同时设 `SLEEVE_AUTH`，否则服务拒绝启动：
无鉴权的 `/api/lookup` 等于一个开放代理，任何人拿到地址都能借你的 IP 扇出 30~50 个出网请求。

`/api/health` 永远豁免鉴权与限流，方便接探针。

## 部署

```bash
cp .env.example .env
docker compose up -d --build
```

默认只发布到 `127.0.0.1:8765` —— 只有宿主机自己能访问（容器里的 `SLEEVE_HOST=0.0.0.0`
是端口映射所必需，不代表对外）。要对外发布：把 `.env` 里的 `SLEEVE_BIND` 改成
`0.0.0.0`（或某个内网地址），**并先设好 `SLEEVE_AUTH`** —— 对外发布且无鉴权时，
容器会带着明确提示拒绝启动。

### 出网边界（防 SSRF）

`/api/lookup` 会**拿服务端身份去抓你贴的那个链接**，所以对用户链接加了三道限制：
只允许 `http`/`https`；拒绝解析到回环 / 私有 / 链路本地 / 保留 / CGNAT 的地址；
主机必须在已知平台表里（复用 `URL_SITE_RULES` 的平台表，不另维护一份清单）。
**重定向逐跳复检**：301/302/307/308 的跳转目标会重新过一遍这三道闸。

贴了表外的冷门站点会看到「不在已知平台列表里，已拒绝抓取」——
这时设 `SLEEVE_ALLOW_ANY_USER_HOST=1` 可以放开，前两道闸仍然生效。

## 测试

```bash
python -m pytest -q
```

`tests/` 里是纯函数回归测试：出网三道闸与白名单边界、危险协议过滤、条码校验、
标题匹配、语言 / 文字判定、MB 查询串转义、缓存工具；另有一个本地起服务的集成用例
（只打 127.0.0.1，不发出任何出网请求）。