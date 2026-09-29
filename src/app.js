let currentReport = null;
// 手工品番已从 UI 移除（不再提供手动输入框），但分享链接和「品番候选」按钮仍能
// 携带/采用品番：此变量承接 URL 参数与候选按钮写入的值，随请求发给后端。
let manualCatalogValue = "";

// ---------------------------------------------------------------
// 认证（feat/custom-login）：自定义登录页替代浏览器原生 Basic 弹窗。
// 服务端开启 SLEEVE_AUTH 后，/api/* 对未认证请求返回 401（不带
// WWW-Authenticate 头，不会触发系统弹窗）；前端收集凭据、存本地，
// 后续业务请求自动携带 Authorization: Basic。服务端未启用认证时
// /api/health 返回 auth:false，登录层会自动隐藏。
// ---------------------------------------------------------------
const AUTH_STORAGE_KEY = "sleeve_auth_v1";
const AUTH_AT_KEY = "sleeve_auth_at_v1";
// 后端没下发 TTL（旧版服务端）时使用的兜底有效期：12 小时，与后端默认一致
const AUTH_TTL_FALLBACK = 12 * 60 * 60;

const getStoredAuth = () => {
  try { return localStorage.getItem(AUTH_STORAGE_KEY) || ""; } catch { return ""; }
};
const setStoredAuth = (value) => {
  try { localStorage.setItem(AUTH_STORAGE_KEY, value); } catch { /* 隐私模式等场景忽略 */ }
};
const clearStoredAuth = () => {
  try { localStorage.removeItem(AUTH_STORAGE_KEY); } catch { /* ignore */ }
};
const basicAuthHeader = () => (getStoredAuth() ? `Basic ${getStoredAuth()}` : "");

// 认证有效期（秒）。initAuth 从 /api/health 的 auth_ttl 读取；0 = 永不过期。
let authTtl = 0;

// 距离登录是否已超过 TTL：是则清凭据并弹回登录层。
// at=0（旧版本地数据没有时间戳）时不强制过期，等下一次登录写入时间戳。
function checkAuthExpiry() {
  if (!authTtl) return; // 永不过期 / 尚未拿到 TTL
  let at = 0;
  try { at = Number(localStorage.getItem(AUTH_AT_KEY) || 0); } catch { /* ignore */ }
  if (!at) return;
  if (Date.now() - at > authTtl * 1000) expireAuthNow();
}

const expireAuthNow = () => {
  clearStoredAuth();
  try { localStorage.removeItem(AUTH_AT_KEY); } catch { /* ignore */ }
  showLogin("登录已过期，请重新认证");
};

// 统一业务请求入口：自动带上已保存的凭据；收到 401 时清凭据并回到登录层。
async function apiFetch(path, options = {}) {
  checkAuthExpiry();
  const headers = new Headers(options.headers || {});
  const auth = basicAuthHeader();
  if (auth) headers.set("Authorization", auth);
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) {
    clearStoredAuth();
    showLogin();
    throw new Error("需要登录");
  }
  return response;
}

const showLogin = (message) => {
  const overlay = $("#login-overlay");
  if (overlay) overlay.classList.remove("hidden");
  if (message) {
    const errorEl = $("#login-error");
    if (errorEl) { errorEl.textContent = message; errorEl.hidden = false; }
  }
};
const hideLogin = () => {
  const overlay = $("#login-overlay");
  if (overlay) overlay.classList.add("hidden");
  const errorEl = $("#login-error");
  if (errorEl) errorEl.hidden = true;
};

function setupLoginForm() {
  const form = $("#login-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = $("#login-username").value.trim();
    const password = $("#login-password").value;
    if (!username || !password) { showLogin("请输入用户名和密码"); return; }
    const submitBtn = $("#login-submit");
    if (submitBtn) submitBtn.disabled = true;
    const credentials = btoa(unescape(encodeURIComponent(`${username}:${password}`)));
    try {
      const response = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Basic ${credentials}` },
        body: JSON.stringify({ username, password }),
      });
      if (response.ok) {
        setStoredAuth(credentials);
        try { localStorage.setItem(AUTH_AT_KEY, String(Date.now())); } catch { /* ignore */ }
        // 登录响应里也带有效期，health 没取到（如已过期的旧登录）时补上
        const data = await response.json().catch(() => ({}));
        if (typeof data.auth_ttl === "number") authTtl = data.auth_ttl;
        hideLogin();
        if ($("#login-password")) $("#login-password").value = "";
      } else {
        showLogin("用户名或密码错误");
      }
    } catch (error) {
      showLogin("无法连接服务器，请稍后重试");
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });
}

// 启动认证检查：读 /api/health 的 auth 标志，决定登录层去留。
// 服务不可达时保持登录层可见（页面本来就是遮罩，不会闪出内容）。
async function initAuth() {
  setupLoginForm();
  // 本地已有凭据：立刻收起登录层，避免每次刷新都「闪」一下认证窗口
  // （不用等 /api/health 网络往返）。凭据若已失效，后面的 checkAuthExpiry
  // 或业务请求 401（apiFetch）会自动清凭据并弹回登录层，安全不回退。
  if (getStoredAuth()) hideLogin();
  let authEnabled = true;
  try {
    const response = await fetch("/api/health", { cache: "no-store" });
    const data = await response.json().catch(() => ({}));
    authEnabled = data.auth !== false;
    // 后端下发有效期；旧版服务端没有该字段时用兜底 12h
    if (typeof data.auth_ttl === "number") authTtl = data.auth_ttl;
    else if (data.auth) authTtl = AUTH_TTL_FALLBACK;
  } catch (error) { /* 保持默认：视为需要认证 */ }
  if (!authEnabled) { hideLogin(); return; }
  // 已有凭据但本地没时间戳（旧数据）：记为「刚登录」，从这一刻开始计时
  if (getStoredAuth()) {
    let at = 0;
    try { at = Number(localStorage.getItem(AUTH_AT_KEY) || 0); } catch { /* ignore */ }
    if (!at) {
      try { localStorage.setItem(AUTH_AT_KEY, String(Date.now())); } catch { /* ignore */ }
    }
  }
  checkAuthExpiry();
  // 到点后即使没有业务请求，也要自动弹回登录层
  setInterval(checkAuthExpiry, 60000);
  if (!authEnabled || getStoredAuth()) hideLogin();
  else showLogin();
}

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[char]));
const display = (value) => value === undefined || value === null || value === "" ? "未确认" : value;

// href 白名单：escapeHtml 只处理字符，不处理协议头 —— href="javascript:..." 里的
// 脚本照样会执行。后端 split_source_urls 已经只放行 http/https，这里再兜一层
// （分享链接、旧报告、上游返回的 URL 都可能带别的东西进来）。
const safeHref = (value) => {
  const text = String(value ?? "").trim();
  return /^https?:\/\//i.test(text) ? text : "#";
};

// 切分粘贴进来的一串链接：换行 / 分号，以及「逗号后面紧跟一个新链接」。
// 原来按 [\n,;]+ 切会把查询参数里带逗号的链接（?ids=1,2）截断；
// 后端 split_source_urls 用的是同一套规则，两边必须一致。
const URL_SPLIT_RE = /[\n;]+|,\s*(?=https?:\/\/)/i;
const splitUrls = (values) => (Array.isArray(values) ? values : [values])
  .flatMap((value) => String(value ?? "").split(URL_SPLIT_RE))
  .map((url) => url.trim())
  .filter(Boolean);

function renderReport(report) {
  // 单曲链接的报告结构与专辑报告几乎不重叠，走独立渲染
  if (report.report_type === "song") {
    currentReport = report;
    renderSongReport(report);
    return;
  }
  currentReport = report;
  $("#results").classList.remove("hidden");
  $("#report-title").textContent = report.release.title || "建库资料";
  $("#report-subtitle").textContent = `${report.release.artist || "未知艺人"} · ${report.release.date || "日期待确认"} · ${report.confidence.overall} confidence`;

  const fields = [
    ["Title", report.release.title], ["Artist", report.release.artist], ["Release group", report.release.release_group],
    ["Primary type", report.release.primary_type], ["Secondary types", (report.release.secondary_types || []).join(", ")],
    ["Status", report.release.status], ["Language", report.release.language], ["Script", report.release.script],
    ["Date", report.release.date], ["Country", report.release.country], ["Label / imprint", report.release.label],
    ["Catalog number", report.release.catalog_number], ["Barcode", report.release.barcode || report.release.barcode_status],
    ["Packaging", report.release.packaging], ["Format", report.release.format], ["Release MBID", report.release.musicbrainz_release_mbid]
  ];
  const missing = report.missing_fields || [];
  $("#missing-fields").innerHTML = missing.length ? `<div class="missing-banner"><strong>还需人工补齐 ${missing.length} 项</strong>${missing.map((item) => `<div class="missing-item"><span class="missing-name">${escapeHtml(item.field)}</span><span>${escapeHtml(item.hint)}</span></div>`).join("")}</div>` : "";

  const warnFields = new Set();
  if (!report.release.barcode) warnFields.add("Barcode");
  if (!report.release.catalog_number) warnFields.add("Catalog number");
  $("#release-fields").innerHTML = fields.map(([key, value]) => `<div class="field ${warnFields.has(key) ? "warn" : ""}"><div class="key">${escapeHtml(key)}</div><div class="value">${escapeHtml(display(value))}</div></div>`).join("");

  const cover = report.release.cover_art_url;
  $("#cover-panel").innerHTML = `${cover ? `<img src="${escapeHtml(safeHref(cover))}" alt="${escapeHtml(report.release.title)} cover" />` : `<div class="cover-placeholder">未找到可靠封面<br/>请从发行平台取原图</div>`}<div class="cover-meta"><strong>推荐封面来源</strong><p>${cover ? `<a href="${escapeHtml(safeHref(cover))}" target="_blank" rel="noreferrer">打开原图</a>` : "待人工补充"}</p><p class="muted">保持原图，不裁剪、不 AI 放大、不加水印。</p></div>`;
  $("#sources").innerHTML = report.sources.length ? report.sources.map((source) => `<div class="source"><div class="source-name">${escapeHtml(source.name)} <span class="muted">${escapeHtml(source.status || "")}</span></div><a href="${escapeHtml(safeHref(source.url))}" target="_blank" rel="noreferrer">${escapeHtml(source.url || "无链接")}</a></div>`).join("") : `<div class="empty">没有成功的来源。</div>`;

  const coverSources = report.release.cover_sources || [];
  $("#cover-sources").innerHTML = coverSources.length ? `<div class="lookup-hint">各平台原图（提交前取最大的一张，不要裁剪或放大）：</div><div class="lookup-actions">${coverSources.map((item) => `<a class="lookup-link" href="${escapeHtml(safeHref(item.url))}" target="_blank" rel="noreferrer" title="${escapeHtml(item.url)}">${escapeHtml(item.site)} 原图</a>`).join("")}${report.release.cover_upload_url ? `<a class="lookup-link" href="${escapeHtml(safeHref(report.release.cover_upload_url))}" target="_blank" rel="noreferrer" title="${escapeHtml(report.release.cover_upload_url)}">给已存在的 Release 补图 →</a>` : ""}</div><p class="muted">${coverSources.map((item) => `${escapeHtml(item.site)}：${escapeHtml(item.note)}`).join(" · ")}</p>` : "";

  $("#source-comparison").innerHTML = (report.source_comparison || []).map((row) => `<div class="comparison-row ${escapeHtml(row.status)}"><div class="comparison-field">${escapeHtml(row.field)}</div><div class="comparison-status ${escapeHtml(row.status)}">${row.status === "match" ? "一致" : row.status === "conflict" ? "冲突" : "缺失"}</div><div class="comparison-values">${row.values.length ? row.values.map((item) => `<div><span>${escapeHtml(item.source)}：</span><strong>${escapeHtml(display(item.value))}</strong></div>`).join("") : `<span>${escapeHtml(row.note)}</span>`}</div></div>`).join("") || `<div class="empty">没有足够的来源用于对比。</div>`;

  const externalLinks = report.external_links || [];
  $("#external-count").textContent = `${externalLinks.length} 条`;
  const platformSearch = report.external_platform_search || [];
  $("#external-links").innerHTML = (externalLinks.length ? `<table class="external-table"><thead><tr><th>站点</th><th>MusicBrainz 关系类型</th><th>链接</th><th>来源</th></tr></thead><tbody>${externalLinks.map((item) => `<tr><td>${escapeHtml(item.site)}</td><td><code>${escapeHtml(item.relationship)}</code></td><td><a href="${escapeHtml(safeHref(item.url))}" target="_blank" rel="noreferrer">${escapeHtml(item.url)}</a></td><td class="muted">${escapeHtml(item.source)}</td></tr>`).join("")}</tbody></table><p class="muted">关系类型照抄；「自动发现」的链接添加前请核对。</p>` : `<div class="empty">还没有可用的外部链接。</div>`) + (platformSearch.length ? `<div class="lookup-hint">下面这些平台还没拿到链接，点开搜索页找到后把 URL 贴回输入框即可自动归类。${report.external_platform_search_note ? escapeHtml(report.external_platform_search_note) : ""}</div><div class="lookup-actions">${platformSearch.map((item) => `<a class="lookup-link" href="${escapeHtml(safeHref(item.url))}" target="_blank" rel="noreferrer">${escapeHtml(item.name)} 搜索</a>`).join("")}</div>` : "");

  const candidates = report.catalog_candidates || [];
  $("#catalog-candidates").innerHTML = candidates.length ? `<div class="lookup-hint">品番候选（点击采用为手工品番）：</div><div class="lookup-actions">${candidates.map((item) => `<button class="lookup-link use-catalog" data-value="${escapeHtml(item.value)}">${escapeHtml(item.value)}（${escapeHtml(item.source)}）</button>`).join("")}</div><div class="lookup-hint">${escapeHtml(candidates[0].note)}</div>` : "";

  const links = report.lookup_links || [];
  $("#lookup-links").innerHTML = links.length ? `<div class="lookup-hint">没找到品番时，用下面的入口核对：站内搜索最直接；若商店返回 403（OTOTOY 的搜索页会拦脚本流量），改用 Google 站内搜索。找到专辑后把商店链接贴回上方即可自动取品番。</div><div class="lookup-actions">${links.map((item) => `<a class="lookup-link" href="${escapeHtml(safeHref(item.url))}" target="_blank" rel="noreferrer" title="${escapeHtml(item.url)}">${escapeHtml(item.name)}</a>`).join("")}</div>` : "";

  // 查重：MusicBrainz 里已经存在同条码的发行吗？
  const duplicates = report.duplicates || [];
  $("#duplicates-card").classList.toggle("hidden", !duplicates.length);
  $("#duplicates").innerHTML = duplicates.length ? duplicates.map((item) => `<div class="duplicate"><div class="duplicate-head"><a href="${escapeHtml(safeHref(item.url))}" target="_blank" rel="noreferrer"><strong>${escapeHtml(display(item.title))}</strong></a><span class="muted">${escapeHtml(display(item.artist))} · ${escapeHtml(display(item.date))} · ${escapeHtml(item.country || "地区未确认")} · ${escapeHtml(item.track_count || "?")} 轨</span></div><div class="duplicate-body"><div><span class="muted">那张已挂：</span>${(item.linked_sites || []).length ? escapeHtml(item.linked_sites.join("、")) : "没有任何平台链接"}</div><div><span class="muted">本张还缺：</span>${(item.missing_sites || []).length ? escapeHtml(item.missing_sites.join("、")) : "无，链接已齐"}</div></div></div>`).join("") : "";
  if (duplicates.length) $("#duplicates").insertAdjacentHTML("beforeend", `<p class="muted">同一张发行不要重复建：如果是同一张，请去上面那条 Release 上补冲突/缺失的链接与信息；只有确认是不同的发行（不同地区、不同厂牌、不同母带）才新建。</p>`);

  // 发行地区：给出 [None] / [Worldwide] / 全部国家 三种可复制形态
  const events = report.release_events || {};
  const eventCountries = events.countries || [];
  const eventCodes = eventCountries.map((item) => item.code).filter(Boolean);
  $("#event-count").textContent = eventCodes.length ? `${eventCodes.length} 个地区` : "未确认";
  $("#release-events").innerHTML = `<div class="event-head"><span class="pill">${escapeHtml(events.mode || "unknown")}</span><span class="muted">日期 ${escapeHtml(display(events.date))} · 来源 ${escapeHtml(events.source || "未确认")}</span></div><p class="muted">${escapeHtml(events.note || "")}</p>` + (eventCodes.length ? `<div class="event-codes">${eventCountries.map((item) => `<span class="event-code" title="${escapeHtml(item.date || "")}">${escapeHtml(item.code)}${item.name ? ` <span class="muted">${escapeHtml(item.name)}</span>` : ""}</span>`).join("")}</div><div class="lookup-actions"><span class="muted">也可以整个留空（[None]）：</span><button class="secondary copy-events${events.mode === "countries" ? "" : " btn-sm"}" data-events="${escapeHtml(events.mode === "countries" ? eventCodes.join(", ") : "XW")}" type="button">复制 ${events.mode === "countries" ? "全部国家" : "[Worldwide]"}</button>${events.mode === "countries" ? `<button class="secondary copy-events btn-sm" data-events="XW" type="button">复制 [Worldwide]</button>` : ""}</div>` : `<div class="empty">没有查到发行地区，请人工补齐。</div>`);

  // Annotation 草稿：版权行 + 可用地区
  const annotation = report.annotation || {};
  $("#annotation").innerHTML = annotation.combined ? `<div class="note-block"><div class="note-head"><span>Copyright notice</span></div><pre>${escapeHtml(annotation.copyright || "（没有查到版权行）")}</pre></div><div class="note-block"><div class="note-head"><span>Countries where available</span></div><pre>${escapeHtml(annotation.available || "（没有查到可用地区）")}</pre></div><p class="muted">复制你确认过的版权行与地区。</p>` : `<div class="empty">没有拿到可用的版权行或地区信息，没有生成 Annotation 草稿。</div>`;

  // 艺人解析：别建重名艺人
  const artistCredits = report.artist_credits || [];
  const rgCandidates = report.release_group_candidates || [];
  const rgNote = report.release.musicbrainz_release_group_mbid ? `<div class="rg-hit"><span class="rg-hit-mark">✅</span><span>MusicBrainz 已经匹配到发行组 <a href="https://musicbrainz.org/release-group/${escapeHtml(report.release.musicbrainz_release_group_mbid)}" target="_blank" rel="noreferrer"><code>${escapeHtml(report.release.musicbrainz_release_group_mbid)}</code></a>，直接用它，<strong>不要新建</strong>。</span></div>` : "";
  $("#artist-credits").innerHTML = `<div class="table-wrap"><table><thead><tr><th>名称</th><th>MusicBrainz 艺人 MBID</th><th>范围</th><th>来源</th></tr></thead><tbody>${artistCredits.map((item) => `<tr><td><strong>${escapeHtml(item.name)}</strong></td><td>${item.mbid ? `<a href="https://musicbrainz.org/artist/${escapeHtml(item.mbid)}" target="_blank" rel="noreferrer"><code>${escapeHtml(item.mbid)}</code></a>` : `<span class="empty">未确认，先在 MusicBrainz 搜同名艺人</span>`}</td><td>${item.scope === "release" ? "发行" : `曲目 ${escapeHtml(item.track || "")}`}</td><td class="muted">${escapeHtml(item.source || "")}${(item.candidates || []).length > 1 ? `（另有 ${item.candidates.length - 1} 个同名候选，打开 MBID 页核对消歧义注释）` : ""}</td></tr>`).join("")}</tbody></table></div><p class="muted">Add release 时把上面的 MBID 填进 Artist Credit，避免新建一个重名艺人；多艺人 / feat. 也要逐条确认。</p>`;
  $("#release-groups").innerHTML = rgNote + (rgCandidates.length ? `<div class="lookup-hint">MusicBrainz 里已有的相近发行组（点按钮复制 MBID，填进 Add release 的 Release group）：</div><div class="lookup-actions">${rgCandidates.map((item) => `<button class="lookup-link copy-mbid" data-mbid="${escapeHtml(item.mbid)}" data-label="${escapeHtml(item.title)}（${escapeHtml(item.primary_type || "类型未确认")}，${escapeHtml(item.artist || "")}，${escapeHtml(item.release_count)} 个发行）">${escapeHtml(item.title)} · ${escapeHtml(item.primary_type || "?")} · ${escapeHtml(item.artist || "")} · ${escapeHtml(item.release_count)} 发行</button><a class="lookup-link" href="${escapeHtml(safeHref(item.url))}" target="_blank" rel="noreferrer" title="${escapeHtml(item.url)}">↗</a>`).join("")}</div><p class="muted">如果其中一条就是这张专辑的发行组，复用它而不是新建；都不匹配才新建，并顺手补上类型与消歧义注释。</p>` : (rgNote ? "" : `<div class="empty">没有找到相近的已有发行组，这一张大概率需要新建 Release group（注意类型选对，合辑勾 Compilation）。</div>`));

  const tracks = report.tracks || [];
  const multiDisc = hasMultipleDiscs(tracks);
  const isrcCount = tracks.filter((track) => track.isrc).length;
  $("#track-count").textContent = tracks.length ? `${tracks.length} tracks · ISRC ${isrcCount}/${tracks.length}` : "0 tracks";
  $("#tracklist-parser").textContent = trackParserText(report);
  $("#tracks").innerHTML = tracks.length ? tracks.map((track, index) => `<tr><td>${escapeHtml(trackNumberLabel(track, index, multiDisc))}</td><td><strong>${escapeHtml(track.title)}</strong></td><td>${escapeHtml(track.artist || "跟随发行艺人")}</td><td>${escapeHtml(track.length || "未确认")}</td><td>${track.isrc ? `<code>${escapeHtml(track.isrc)}</code>` : `<span class="empty">未确认</span>`}</td><td>${track.recording_mbid ? `<a href="https://musicbrainz.org/recording/${escapeHtml(track.recording_mbid)}" target="_blank" rel="noreferrer">${escapeHtml(track.recording_mbid.slice(0, 8))}…</a>` : `<span class="empty">新建 / 待确认</span>`}</td></tr>`).join("") : `<tr><td colspan="6" class="empty">没有找到曲目表，请提供更具体的发行链接。</td></tr>`;

  $("#checklist").innerHTML = report.manual_review.map((item, index) => `<label class="check"><input type="checkbox" data-check="${index}" /><span><span class="check-title">${escapeHtml(item.label)}</span><br/><span class="check-reason">${escapeHtml(item.reason)}</span></span></label>`).join("");
  $("#edit-notes").innerHTML = Object.entries(report.edit_notes).map(([name, note]) => `<div class="note-block"><div class="note-head"><span>${escapeHtml(name)}</span><button class="copy-note" data-note="${escapeHtml(note)}">复制</button></div><pre>${escapeHtml(note)}</pre></div>`).join("");
  const workRels = report.work_relations || { status: "skipped", notice: "", items: [], work_count: 0, relation_count: 0 };
  const wrCount = $("#work-relations-count");
  if (wrCount) {
    const creditsN = (workRels.apple_credits || []).length;
    wrCount.textContent = creditsN ? `Apple Credits ${creditsN} 曲` : (workRels.status === "skipped" ? "未查询" : `${workRels.work_count || 0} work / ${workRels.relation_count || 0} 关系`);
  }
  $("#work-relations").innerHTML = renderWorkRelations(workRels);
  const lyricsCandidates = report.lyrics_candidates || [];
  $("#lyrics-candidates").innerHTML = lyricsCandidates.length ? renderLyricsCandidates(lyricsCandidates) : "";
  $("#diagnostics").innerHTML = [...report.confidence.notes.map((note) => `<div class="diagnostic">${escapeHtml(note)}</div>`), ...(report.source_warnings || []).map((item) => `<div class="diagnostic warning">${escapeHtml(item.source)}：${escapeHtml(item.warning)}</div>`), ...report.source_errors.map((item) => `<div class="diagnostic error">${escapeHtml(item.source)}：${escapeHtml(item.error)}</div>`), ...report.api_notes.map((note) => `<div class="diagnostic ok">${escapeHtml(note)}</div>`)].join("");
  const reviewCount = $("#review-count");
  if (reviewCount) reviewCount.textContent = report.manual_review.length ? `${report.manual_review.length} 项待勾` : "已核对完";
  // 完成度分母由**实际渲染的字段**推导（发行字段 + 来源对比字段），不再写死 21：
  // 后端加字段时写死的分母会静默失真，进度条永远是错的
  renderRail(report, fields.length + (report.source_comparison || []).length);
  // 工具栏高度会随标题换行 / 按钮换行变化，左导航与锚点的让位量要跟着实测值走
  syncBarOffset();
  window.scrollTo({ top: $("#results").offsetTop - 20, behavior: "smooth" });
}

function renderSongReport(report) {
  const s = report.song || {};
  $("#results").classList.add("hidden");
  const box = $("#song-results");
  box.classList.remove("hidden");
  $("#song-report-title").textContent = s.title || "单曲资料";
  const albumPart = s.album ? `《${s.album}》` : "所属专辑未确认";
  $("#song-report-subtitle").textContent = `${s.artist || "未知艺人"} · ${albumPart}${s.release_date ? ` · ${s.release_date}` : ""}`;

  // S1 歌曲信息
  const cover = s.artwork_url;
  $("#song-cover").innerHTML = cover
    ? `<img src="${escapeHtml(safeHref(cover))}" alt="${escapeHtml(s.title || "cover")}" />`
    : `<div class="cover-placeholder">未找到该单曲封面</div>`;
  const fields = [
    ["Artist", s.artist],
    ["时长", s.length || "未确认"],
    ["ISRC", s.isrc || "未确认"],
    ["ISWC", s.iswc || "未确认"],
    ["发行日期", s.release_date || "未确认"],
    ["类型", s.genre || "未确认"],
  ];
  $("#song-fields").innerHTML = fields.map(([key, value]) => `<div class="field"><div class="key">${escapeHtml(key)}</div><div class="value">${escapeHtml(value)}</div></div>`).join("");

  // S2 所属专辑：给线索 + 一键切专辑报告
  const albumUrl = s.album_url || "";
  $("#song-album-card").innerHTML = `<div class="song-album">
    <div>
      <strong>${escapeHtml(s.album || "未确认")}</strong>
      <p class="muted">${escapeHtml(s.album_source || "平台")} ID ${escapeHtml(s.album_platform_id || "—")}${s.track_url ? `<br/><a href="${escapeHtml(safeHref(s.track_url))}" target="_blank" rel="noreferrer">打开 ${escapeHtml(s.album_source || "平台")} 单曲页</a>` : ""}</p>
    </div>
    <div class="lookup-actions">
      ${albumUrl ? `<button class="lookup-link song-to-album" data-url="${escapeHtml(albumUrl)}" type="button">用专辑方式查询</button><a class="lookup-link" href="${escapeHtml(safeHref(albumUrl))}" target="_blank" rel="noreferrer">打开专辑页</a>` : ""}
    </div>
  </div>
  ${albumUrl ? `<p class="hint">单曲报告聚焦 recording / work / credits / 歌词页；要建整张专辑（条码、品番、发行地区、全部曲目）时用「用专辑方式查询」。</p>` : `<p class="hint">${escapeHtml(s.album_source || "该平台")} 未返回所属专辑的 ID / 链接；需要专辑资料时请粘贴专辑链接再查询。</p>`}`;

  // S3 Apple Credits
  $("#song-credits").innerHTML = renderSongCredits(report.apple_credits || []);

  // S4 Work 关系（复用 album 版的渲染，结构相同）
  const wr = report.work_relations || { status: "skipped", notice: "" };
  const wrCount = $("#song-work-count");
  if (wrCount) {
    wrCount.textContent = (wr.apple_credits || []).length ? `Apple Credits ${wr.apple_credits.length} 曲`
      : (wr.status === "skipped" ? "未查询" : `${wr.work_count || 0} work / ${wr.relation_count || 0} 关系`);
  }
  $("#song-work-relations").innerHTML = renderWorkRelations(wr);

  // S5 歌词候选
  const lc = report.lyrics_candidates || [];
  $("#song-lyrics-candidates").innerHTML = lc.length ? renderLyricsCandidates(lc) : `<div class="empty">没有生成歌词候选（缺少曲目标题）。</div>`;

  // S6 外部链接（track 级）
  const ext = report.external_links || [];
  const extCount = $("#song-external-count");
  if (extCount) extCount.textContent = `${ext.length} 条`;
  $("#song-external-links").innerHTML = ext.length ? `<table class="external-table"><thead><tr><th>站点</th><th>MusicBrainz 关系类型</th><th>链接</th><th>来源</th></tr></thead><tbody>${ext.map((item) => `<tr><td>${escapeHtml(item.site)}</td><td><code>${escapeHtml(item.relationship)}</code></td><td><a href="${escapeHtml(safeHref(item.url))}" target="_blank" rel="noreferrer">${escapeHtml(item.url)}</a></td><td class="muted">${escapeHtml(item.source)}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">还没有可用的外部链接。</div>`;

  // S7 核对清单
  const items = report.manual_review || [];
  $("#song-checklist").innerHTML = items.map((item, index) => `<label class="check"><input type="checkbox" data-check="${index}" /><span><span class="check-title">${escapeHtml(item.label)}</span><br/><span class="check-reason">${escapeHtml(item.reason)}</span></span></label>`).join("") || `<div class="empty">没有核对项。</div>`;
  const reviewCount = $("#song-review-count");
  if (reviewCount) reviewCount.textContent = items.length ? `${items.length} 项待勾` : "已核对完";

  // S8 Edit note 草稿
  const notes = report.edit_notes || {};
  $("#song-edit-notes").innerHTML = Object.entries(notes).map(([name, note]) => `<div class="note-block"><div class="note-head"><span>${escapeHtml(name)}</span><button class="copy-note" data-note="${escapeHtml(note)}">复制</button></div><pre>${escapeHtml(note)}</pre></div>`).join("");

  // S9 诊断
  const diagnostics = [
    ...(report.source_warnings || []).map((item) => `<div class="diagnostic warning">${escapeHtml(item.source)}：${escapeHtml(item.warning)}</div>`),
    ...(report.source_errors || []).map((item) => `<div class="diagnostic error">${escapeHtml(item.source)}：${escapeHtml(item.error)}</div>`),
    ...(report.api_notes || []).map((note) => `<div class="diagnostic ok">${escapeHtml(note)}</div>`),
  ];
  $("#song-diagnostics").innerHTML = diagnostics.join("") || `<div class="empty">没有诊断信息。</div>`;

  syncBarOffset();
  window.scrollTo({ top: box.offsetTop - 20, behavior: "smooth" });
}

function renderSongCredits(credits) {
  if (!credits.length) {
    return `<div class="diagnostic">Apple 歌曲页面没有抓到 Credits 区块（可能被 WAF 挡或页面结构变化）。词曲作者 / 制作信息请从发行页面或官方渠道人工补齐。</div>`;
  }
  const groupsHtml = (creditGroup) => {
    const itemsHtml = (creditGroup.items || []).map((it) => {
      const roles = (it.roles || []).length ? `（${escapeHtml(it.roles.join("、"))}）` : "";
      return `<div class="wr-rel"><span class="wr-rel-type">${escapeHtml(creditGroup.title || creditGroup.id || "Credits")}</span><span>${escapeHtml(it.name)}</span>${roles ? `<span class="muted">${roles}</span>` : ""}</div>`;
    }).join("");
    return `<div class="wr-credit-group"><div class="wr-credit-head">${escapeHtml(creditGroup.title || creditGroup.id)}</div><div class="wr-rels">${itemsHtml}</div></div>`;
  };
  return credits.map((credit) => `<div class="wr-track">
    <div class="wr-track-head"><strong>${escapeHtml(credit.track || "歌曲")}</strong><a href="${safeHref(credit.source_url || "")}" target="_blank" rel="noreferrer"><code>Apple Music Credits</code></a></div>
    <div class="wr-credit-groups">${(credit.groups || []).map(groupsHtml).join("")}</div>
  </div>`).join("") + `<p class="muted">版权方侧数据；在 MusicBrainz 挂 composer / lyricist / producer 关系时逐条核对。角色名随页面语言变化，按原样保留。</p>`;
}

function renderWorkRelations(wr) {
  const creditsHtml = ((wr && wr.apple_credits) || []).map((credit) => {
    const groupsHtml = (credit.groups || []).map((g) => {
      const itemsHtml = (g.items || []).map((it) => {
        const roles = (it.roles || []).length ? `（${escapeHtml(it.roles.join("、"))}）` : "";
        return `<div class="wr-rel"><span class="wr-rel-type">${escapeHtml(g.title || g.id || "Credits")}</span><span>${escapeHtml(it.name)}</span>${roles ? `<span class="muted">${roles}</span>` : ""}</div>`;
      }).join("");
      return `<div class="wr-credit-group"><div class="wr-credit-head">${escapeHtml(g.title || g.id)}</div><div class="wr-rels">${itemsHtml}</div></div>`;
    }).join("");
    return `<div class="wr-track">
      <div class="wr-track-head">
        <strong>${escapeHtml(credit.track || "歌曲")}</strong>
        <a href="${safeHref(credit.source_url || "")}" target="_blank" rel="noreferrer"><code>Apple Music Credits</code></a>
      </div>
      <div class="wr-credit-groups">${groupsHtml}</div>
    </div>`;
  }).join("");

  if (!wr || (wr.status === "skipped" && !creditsHtml)) {
    return `<div class="diagnostic">${escapeHtml((wr && wr.notice) || "没有可查询的 work 关系。")}</div>`;
  }
  const relLine = (rel, extra = "") => {
    const attr = (rel.attributes || []).length ? ` <span class="muted">（${escapeHtml(rel.attributes.join(", "))}）</span>` : "";
    const mbid = rel.artist_mbid ? ` <a href="https://musicbrainz.org/artist/${escapeHtml(rel.artist_mbid)}" target="_blank" rel="noreferrer"><code>${escapeHtml(rel.artist_mbid.slice(0, 8))}…</code></a>` : "";
    return `<div class="wr-rel"><span class="wr-rel-type">${escapeHtml(rel.type || "?")}</span><span>${escapeHtml(rel.artist || "")}</span>${mbid}${attr}${extra}</div>`;
  };
  const itemsHtml = wr.items.map((item) => {
    const worksHtml = (item.works || []).length ? `<div class="wr-works">${(item.works || []).map((w) => {
      const relsHtml = (w.relations || []).map((rel) => relLine(rel)).join("");
      return `<div class="wr-work">
        <div class="wr-work-head">
          <a href="${safeHref(w.url || "")}" target="_blank" rel="noreferrer"><strong>${escapeHtml(w.title || "(无标题 work)")}</strong></a>
          <span class="pill">${escapeHtml(w.type || "Work")}</span>
          <span class="wr-iswc">${w.iswc ? `<code>${escapeHtml(w.iswc)}</code>` : `<span class="empty">无 ISWC</span>`}</span>
        </div>
        ${relsHtml ? `<div class="wr-rels">${relsHtml}</div>` : `<div class="empty">work 上没有查到 artist 关系</div>`}
      </div>`;
    }).join("")}</div>` : `<div class="empty">没有关联 work（新建 Recording 时可顺便建 Work，注意别与已有同名词条重复）</div>`;
    const recHtml = (item.recording_relations || []).map((rel) => relLine(rel, `<span class="muted">（recording 直接关系）</span>`)).join("");
    const errorHtml = item.error ? `<div class="diagnostic error">查询失败：${escapeHtml(item.error)}</div>` : "";
    return `<div class="wr-track">
      <div class="wr-track-head">
        <strong>${escapeHtml(item.track || "(无标题)")}</strong>
        <a href="${safeHref(item.recording_url || "")}" target="_blank" rel="noreferrer"><code>${escapeHtml(item.recording_mbid || "")}</code></a>
        ${errorHtml}
      </div>
      ${recHtml ? `<div class="wr-rels">${recHtml}</div>` : ""}
      ${worksHtml}
    </div>`;
  }).join("");
  const copyHtml = wr.markdown ? `<div class="lookup-actions"><button class="copy-note" data-note="${escapeHtml(wr.markdown)}">复制 Work 关系 Markdown</button></div>` : "";
  const noticeHtml = wr.notice ? `<div class="diagnostic ok">${escapeHtml(wr.notice)}</div>` : "";
  const creditsSection = creditsHtml ? `<div class="wr-credits"><div class="wr-credits-title">Apple Music Credits（版权方侧数据，MB 有没有都不影响）</div>${creditsHtml}</div>` : "";
  const mbSection = itemsHtml ? `<div class="wr-mb">${itemsHtml}</div>` : "";
  return `${noticeHtml}${creditsSection}${mbSection}${copyHtml}<p class="muted">只查询不建库：MusicBrainz 的编辑需要登录账号；Apple Credits 是版权方页面数据，请在 Add work / 编辑页人工核对后挂载。</p>`;
}

function renderLyricsCandidates(items) {
  const rows = items.map((item) => {
    const links = (item.links || []).map((l) => `<a class="lyric-link" href="${safeHref(l.url)}" target="_blank" rel="noreferrer">${escapeHtml(l.site)}</a>`).join("");
    return `<div class="lyr-track"><strong>${escapeHtml(item.track)}</strong>${item.artist ? `<span class="muted">— ${escapeHtml(item.artist)}</span>` : ""}<span class="lyr-links">${links}</span></div>`;
  }).join("");
  return `<div class="lyr-block"><div class="lyr-title">Lyrics URL relationship 候选（MB 白名单站点，先建好 Work/Recording 再挂）</div>${rows}<p class="muted">MB 的 lyrics relationship 只允许白名单站点（Genius / Musixmatch / LyricsTranslate 及日文歌词站等）；点击进入各站搜索页，确认歌词页后把最终 URL 挂到 Work / Recording 的 lyrics 关系上。</p></div>`;
}

// 左导航：完成度与待确认项汇总
function renderRail(report, baseFields = 0) {
  const missing = (report.missing_fields || []).length;
  const conflicts = (report.source_comparison || []).filter((row) => row.status === "conflict").length;
  const errors = (report.source_errors || []).length;
  const reviews = (report.manual_review || []).length;
  // 基数 = 实际渲染的发行字段 + 对比字段（调用方传入），每一项人工核对再算 1 项。
  // 原来写死 21（注释说 15 + 6），与 fields 的实际条数已经对不上 —— 进度条一开始就是错的
  const total = baseFields + reviews;
  const open = missing + conflicts + errors + reviews;
  const percent = total > 0 ? Math.round(Math.max(0, Math.min(1, (total - open) / total)) * 100) : 0;

  const value = $("#rail-progress-value");
  const bar = $("#rail-progress-bar");
  if (value) value.textContent = `${percent}%`;
  if (bar) bar.style.width = `${percent}%`;

  const risks = [
    conflicts ? `${conflicts} 个字段来源冲突` : "",
    missing ? `${missing} 项发行字段待补` : "",
    reviews ? `${reviews} 项需人工核对` : "",
    errors ? `${errors} 个来源查询失败` : ""
  ].filter(Boolean);

  const box = $("#rail-risk");
  if (!box) return;
  box.classList.toggle("hidden", !risks.length);
  const title = $("#rail-risk-title");
  const list = $("#rail-risk-list");
  if (title) title.textContent = `${risks.length} 类待确认`;
  if (list) list.innerHTML = risks.map((item) => `<div>· ${escapeHtml(item)}</div>`).join("");
}

/*
 * 把吸顶工具栏的实测高度写回 CSS 变量 --bar-h。
 *
 * 左导航的 sticky top 与锚点 scroll-margin-top 都必须退到工具栏下方，但工具栏高度
 * 不是常数：桌面单行按钮 111px，1000px 档按钮换两行 143px，标题长了还会再高。
 * 之前这两处在 CSS 里写死 104px（按「约 80px 的工具栏」估的），于是左导航顶部
 * 有 19~51px 被压进工具栏底下、「REPORT INDEX / 建库完成度」被吃掉，
 * 锚点落点的卡片顶边也会钻进条下。统一改成脚本实测，别再写死数字。
 */
function syncBarOffset() {
  // 专辑 / 单曲两种报告各有一个 .reportbar，同一时间只有一个可见。
  // 取「可见」的那个的实测高度，避免隐藏栏（高度 0）把变量清掉。
  const bars = document.querySelectorAll(".reportbar");
  let height = 0;
  bars.forEach((bar) => {
    if (bar.offsetParent === null) return;
    height = Math.max(height, Math.round(bar.getBoundingClientRect().height));
  });
  if (!height) return;
  document.documentElement.style.setProperty("--bar-h", `${height}px`);
}

(function watchBarOffset() {
  const bars = document.querySelectorAll(".reportbar");
  if (!bars.length) return;
  syncBarOffset();
  // 标题改写、按钮换行、字体加载完成都会改变工具栏高度，用 ResizeObserver 盯住
  if ("ResizeObserver" in window) bars.forEach((bar) => new ResizeObserver(syncBarOffset).observe(bar));
  window.addEventListener("resize", syncBarOffset);
})();

function hasMultipleDiscs(tracks) {
  return new Set((tracks || []).map((track) => track.disc).filter(Boolean)).size > 1;
}

function trackNumberLabel(track, index, multiDisc) {
  const number = track.number || String(index + 1);
  // 多碟时写成「碟-轨」；MusicBrainz 的 Track Parser 仍按每碟单独粘贴
  return multiDisc && track.disc ? `${track.disc}-${number}` : number;
}

function reportMarkdown(report) {
  const r = report.release;
  const multiDisc = hasMultipleDiscs(report.tracks);
  const lines = [
    `# ${r.title || "MusicBrainz 建库资料"}`, "", `- Artist: ${r.artist || ""}`, `- Release group: ${r.release_group || ""}`,
    `- Primary type: ${r.primary_type || ""}`, `- Secondary types: ${(r.secondary_types || []).join(", ")}`, `- Status: ${r.status || ""}`,
    `- Language / Script: ${r.language || ""} / ${r.script || ""}`, `- Date: ${r.date || ""}`, `- Country: ${r.country || ""}`,
    `- Label / imprint: ${r.label || ""}`, `- Catalog number: ${r.catalog_number || ""}`, `- Barcode: ${r.barcode || r.barcode_status || ""}`,
    `- Packaging: ${r.packaging || ""}`, `- Format: ${r.format || ""}`, `- Cover: ${r.cover_art_url || "待确认"}`, "",
    "## Tracklist", "", "| # | Title | Artist Credit | Length | ISRC | Recording |", "|---:|---|---|---:|---|---|",
    ...(report.tracks || []).map((t, index) => `| ${trackNumberLabel(t, index, multiDisc)} | ${t.title || ""} | ${t.artist || "跟随发行艺人"} | ${t.length || ""} | ${t.isrc || ""} | ${t.recording_mbid || "新建/待确认"} |`), "",
    "### Track Parser（可直接粘进 MusicBrainz）", "", "```text", trackParserText(report), "```", "",
    "### Track Parser（带艺人，VA/合辑用）", "", "```text", trackParserText(report, true), "```", "",
    "## Manual review checklist", "", ...(report.manual_review || []).map((item) => `- [ ] ${item.label}：${item.reason}`), "",
    "## External links (Add release)", "", "| Site | MusicBrainz relationship | URL | Source |", "|---|---|---|---|",
    ...(report.external_links || []).map((item) => `| ${item.site} | \`${item.relationship}\` | ${item.url} | ${item.source} |`),
    ...((report.external_platform_search || []).length ? ["", "### 待补平台（搜索入口）", "", ...(report.external_platform_search || []).map((item) => `- ${item.name} 搜索: ${item.url}`), ...(report.external_platform_search_note ? ["", `> ${report.external_platform_search_note}`] : [])] : []), "",
    ...((report.duplicates || []).length ? ["## MusicBrainz 已有同条码的发行（不要重复建）", "", ...report.duplicates.map((item) => `- ${item.url} — ${item.title}（${item.artist || ""}，${item.date || ""}，${item.track_count || "?"} 轨）｜已挂：${(item.linked_sites || []).join("、") || "无"}｜本张还缺：${(item.missing_sites || []).join("、") || "无"}`), ""] : []),
    "## Release events", "", `- mode: ${report.release_events.mode}`, `- date: ${report.release_events.date}`, `- source: ${report.release_events.source}`, ...(report.release_events.countries || []).map((item) => `- ${item.code}${item.name ? ` ${item.name}` : ""}${item.date ? ` (${item.date})` : ""}`), "",
    ...(report.annotation && report.annotation.combined ? ["## Annotation", "", "```text", report.annotation.combined, "```", ""] : []),
    ...((report.artist_credits || []).length ? ["## Artist credits", "", "| 名称 | MBID | 范围 | 来源 |", "|---|---|---|---|", ...report.artist_credits.map((item) => `| ${item.name} | ${item.mbid || "未确认"} | ${item.scope}${item.track ? ` ${item.track}` : ""} | ${item.source || ""} |`), ""] : []),
    ...((report.release_group_candidates || []).length ? ["## Release group 候选", "", ...report.release_group_candidates.map((item) => `- ${item.url} — ${item.title}（${item.primary_type || "?"}，${item.artist || ""}，${item.release_count} 个发行）`), ""] : []),
    "## Sources", "", ...(report.sources || []).map((source) => `- ${source.name}: ${source.url || ""}`), "",
    "## Edit notes", "", ...Object.entries(report.edit_notes || {}).flatMap(([name, note]) => [`### ${name}`, "", "```text", note, "```", ""]),
    "## Limitations", "", ...(report.confidence.notes || []).map((note) => `- ${note}`), ...(report.source_warnings || []).map((item) => `- ${item.source}: ${item.warning}`), ...(report.source_errors || []).map((item) => `- ${item.source}: ${item.error}`)
  ];
  return lines.join("\n");
}

function trackParserText(report, withArtists = false) {
  return (report.tracks || []).map((track, index) => {
    const number = track.number || String(index + 1);
    const title = track.title || "";
    const length = track.length ? ` (${track.length})` : "";
    // 单艺人专辑用纯「序号. 标题 (时长)」；带艺人时用「序号. 标题 - 艺人 (时长)」
    const artist = withArtists && track.artist ? ` - ${track.artist}` : "";
    return `${number}. ${title}${artist}${length}`;
  }).join("\n");
}

function xmlEscape(value) {
  return String(value ?? "").replace(/[&<>\"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&apos;"}[char]));
}

function reportXml(report) {
  const r = report.release;
  const sources = (report.sources || []).map((source) => `    <source name="${xmlEscape(source.name)}" status="${xmlEscape(source.status)}">${xmlEscape(source.url)}</source>`).join("\n");
  const tracks = (report.tracks || []).map((track) => `    <track number="${xmlEscape(track.number)}" disc="${xmlEscape(track.disc)}" length="${xmlEscape(track.length)}" isrc="${xmlEscape(track.isrc)}" recording-mbid="${xmlEscape(track.recording_mbid)}"><title>${xmlEscape(track.title)}</title><artist-credit>${xmlEscape(track.artist || "跟随发行艺人")}</artist-credit></track>`).join("\n");
  const checks = (report.manual_review || []).map((item) => `    <check key="${xmlEscape(item.key)}" label="${xmlEscape(item.label)}" reason="${xmlEscape(item.reason)}" />`).join("\n");
  const duplicateXml = (report.duplicates || []).map((item) => `    <release mbid="${xmlEscape(item.release_mbid)}" linked-sites="${xmlEscape((item.linked_sites || []).join(", "))}" missing-sites="${xmlEscape((item.missing_sites || []).join(", "))}" track-count="${xmlEscape(item.track_count)}"><title>${xmlEscape(item.title)}</title><artist>${xmlEscape(item.artist)}</artist></release>`).join("\n");
  const eventXml = ((report.release_events || {}).countries || []).map((item) => `    <event code="${xmlEscape(item.code)}" name="${xmlEscape(item.name)}" date="${xmlEscape(item.date)}" />`).join("\n");
  const creditXml = (report.artist_credits || []).map((item) => `    <artist name="${xmlEscape(item.name)}" mbid="${xmlEscape(item.mbid)}" scope="${xmlEscape(item.scope)}" track="${xmlEscape(item.track)}" source="${xmlEscape(item.source)}" />`).join("\n");
  const annotationXml = xmlEscape((report.annotation || {}).combined).replace(/^/gm, "    ");
  const externals = (report.external_links || []).map((item) => `    <link site="${xmlEscape(item.site)}" relationship="${xmlEscape(item.relationship)}" source="${xmlEscape(item.source)}">${xmlEscape(item.url)}</link>`).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!-- Sleeve building worksheet. This is not a direct MusicBrainz submission payload. -->\n<sleeve-workbook generated-at="${xmlEscape(report.generated_at)}">\n  <release>\n    <title>${xmlEscape(r.title)}</title>\n    <artist>${xmlEscape(r.artist)}</artist>\n    <release-group>${xmlEscape(r.release_group)}</release-group>\n    <primary-type>${xmlEscape(r.primary_type)}</primary-type>\n    <secondary-types>${xmlEscape((r.secondary_types || []).join(", "))}</secondary-types>\n    <status>${xmlEscape(r.status)}</status>\n    <language>${xmlEscape(r.language)}</language>\n    <script>${xmlEscape(r.script)}</script>\n    <date>${xmlEscape(r.date)}</date>\n    <country>${xmlEscape(r.country)}</country>\n    <label>${xmlEscape(r.label)}</label>\n    <catalog-number>${xmlEscape(r.catalog_number)}</catalog-number>\n    <barcode>${xmlEscape(r.barcode)}</barcode>\n    <packaging>${xmlEscape(r.packaging)}</packaging>\n    <format>${xmlEscape(r.format)}</format>\n    <cover-art-url>${xmlEscape(r.cover_art_url)}</cover-art-url>\n    <musicbrainz-release-mbid>${xmlEscape(r.musicbrainz_release_mbid)}</musicbrainz-release-mbid>\n    <musicbrainz-release-group-mbid>${xmlEscape(r.musicbrainz_release_group_mbid)}</musicbrainz-release-group-mbid>\n  </release>\n  <tracklist>\n${tracks}\n  </tracklist>\n  <sources>\n${sources}\n  </sources>\n  <external-links>\n${externals}\n  </external-links>\n  <duplicates>\n${duplicateXml}\n  </duplicates>\n  <release-events mode="${xmlEscape((report.release_events || {}).mode)}" date="${xmlEscape((report.release_events || {}).date)}" source="${xmlEscape((report.release_events || {}).source)}">\n${eventXml}\n  </release-events>\n  <artist-credits>\n${creditXml}\n  </artist-credits>\n  <annotation mode="manual-review-only">\n${annotationXml}\n  </annotation>\n  <manual-review>\n${checks}\n  </manual-review>\n</sleeve-workbook>\n`;
}

function checklistMarkdown(report) {
  return [`# ${report.release.title || "MusicBrainz 建库核对清单"}`, "", `> 这是一份人工核对清单，生成时间：${report.generated_at}`, "", ...(report.manual_review || []).map((item) => `- [ ] ${item.label}\n  - ${item.reason}`), "", "## 来源冲突", ...(report.source_comparison || []).filter((row) => row.status !== "match").map((row) => `- ${row.field}：${row.note}${row.values.length ? `（${row.values.map((item) => `${item.source}=${item.value}`).join("；")}）` : ""}`), "",     "## 提交前提醒", ...(report.confidence.notes || []).map((note) => `- ${note}`), ...(report.source_warnings || []).map((item) => `- ${item.source}：${item.warning}`)].join("\n");
}

function download(filename, content, type) {
  const blob = new Blob([content], { type });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

function collectUrls() {
  return splitUrls($("#source-urls").value || "");
}

const lookupButton = $("#lookup-form button.primary");

async function runLookup() {
  const manualCatalog = manualCatalogValue;
  const urls = collectUrls();
  const status = $("#status");
  if (!urls.length) {
    status.className = "status error";
    status.textContent = "请粘贴至少一个来源链接";
    return;
  }
  status.className = "status";
  // 查询要走好几家外部服务，慢的时候十几秒。把已等待时间显出来，别让人以为卡死了。
  const startedAt = Date.now();
  const workingText = "正在查询输入链接、Apple/iTunes、Spotify 和 MusicBrainz…";
  const tickStatus = () => {
    status.textContent = `${workingText}（已等待 ${Math.round((Date.now() - startedAt) / 1000)} 秒）`;
  };
  tickStatus();
  const statusTimer = setInterval(tickStatus, 1000);
  if (lookupButton) lookupButton.disabled = true;
  try {
    const response = await apiFetch("/api/lookup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ urls, catalog: manualCatalog }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "查询失败");
    if (data.needs_selection) {
      status.className = "status error";
      status.textContent = data.reason || "无法解析该链接，请换一个站点链接再试";
      return;
    }
    renderReport(data);
    // 把查询条件写回地址栏：万一报告页被导航走（例如点开外部链接），按返回键还能自动重跑
    try {
      const params = new URLSearchParams();
      // 每个链接单独一个 urls 参数：join(",") 会把查询参数里带逗号的链接截断
      urls.forEach((url) => params.append("urls", url));
      if (manualCatalog) params.set("catalog", manualCatalog);
      history.replaceState(null, "", `${location.pathname}?${params.toString()}`);
    } catch (error) { /* file:// 等环境不允许改地址栏时忽略 */ }
    status.className = "status ok";
    status.textContent = "资料已生成，请逐项核对";
  } catch (error) {
    status.className = "status error";
    status.textContent = error.message;
  } finally {
    clearInterval(statusTimer);
    if (lookupButton) lookupButton.disabled = false;
  }
}

$("#lookup-form").addEventListener("submit", (event) => {
  event.preventDefault();
  runLookup();
});
if (lookupButton) lookupButton.addEventListener("click", () => runLookup());

document.addEventListener("click", (event) => {
  const useCatalog = event.target.closest(".use-catalog");
  if (useCatalog) {
    manualCatalogValue = useCatalog.dataset.value || "";
    runLookup();
  }
});

let noticeTimer = 0;

function showNotice(text) {
  let box = document.getElementById("link-notice");
  if (!box) {
    box = document.createElement("div");
    box.id = "link-notice";
    box.className = "link-notice";
    document.body.appendChild(box);
  }
  box.textContent = text;
  box.classList.add("show");
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => box.classList.remove("show"), 8000);
}

// 复制到剪贴板，三级降级：Clipboard API → execCommand 旧通道 → 选中文本兜底。
// 注：http + 非 localhost 的环境里 navigator.clipboard 是 undefined（非 secure context），
// 早期实现会把整段内容塞进 notice，长文本（如 Markdown）会铺满页面；现在一律先走旧通道。
function legacyCopy(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.left = "-9999px";
  ta.style.top = "0";
  document.body.appendChild(ta);
  ta.select();
  ta.setSelectionRange(0, ta.value.length);
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch (error) {
    ok = false;
  }
  if (ok) {
    document.body.removeChild(ta);
  } else {
    // execCommand 也失败：保留选中状态并提示手动复制，别把内容摊进页面。
    showNotice("剪贴板被浏览器拒绝，内容已选中：请按 Ctrl+C（Mac 上 ⌘+C）复制。");
    ta.focus({ preventScroll: true });
    setTimeout(() => {
      if (ta.parentNode) ta.parentNode.removeChild(ta);
    }, 60000);
  }
  return ok;
}

async function copyText(text, button, original) {
  let ok = false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      // clipboard 权限提示被忽略时 writeText 可能永不返回（挂起），加超时降级
      await Promise.race([
        navigator.clipboard.writeText(text),
        new Promise((_, reject) => setTimeout(() => reject(new Error("clipboard timeout")), 1500)),
      ]);
      ok = true;
    }
  } catch (error) {
    ok = false;
  }
  if (!ok) ok = legacyCopy(text);
  if (ok) {
    if (!button) return;
    button.textContent = "已复制";
    setTimeout(() => button.textContent = original, 1300);
    return;
  }
  if (button) button.textContent = original;
}

$("#copy-tracklist").addEventListener("click", async (event) => {
  if (!currentReport) return;
  await copyText(trackParserText(currentReport), event.target, "复制 Track Parser 格式");
});

$("#copy-tracklist-artist").addEventListener("click", async (event) => {
  if (!currentReport) return;
  await copyText(trackParserText(currentReport, true), event.target, "复制（带艺人）");
});

$("#download-tracklist").addEventListener("click", () => {
  if (!currentReport) return;
  download(`${currentReport.release.title || "tracklist"}-track-parser.txt`, trackParserText(currentReport), "text/plain;charset=utf-8");
});

$("#copy-external").addEventListener("click", async () => {
  if (!currentReport) return;
  const text = (currentReport.external_links || []).map((item) => `${item.relationship}\t${item.url}`).join("\n");
  await copyText(text, $("#copy-external"), "复制全部链接");
});

function songMarkdown(report) {
  if (report && report.markdown) return report.markdown;
  // 后端没生成时兜底：极简结构
  const s = (report || {}).song || {};
  const lines = [`# ${s.title || "单曲资料"}`, "", `- Artist: ${s.artist || ""}`, `- 所属专辑: ${s.album || ""}`];
  (report.external_links || []).forEach((item) => lines.push(`- ${item.site}: ${item.url}`));
  return lines.join("\n") + "\n";
}

function songFileName(report) {
  const title = ((report || {}).song || {}).title || "musicbrainz-song";
  return title.replace(/[^\w\u4e00-\u9fa5-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "musicbrainz-song";
}

$("#copy-song-markdown").addEventListener("click", async () => {
  if (!currentReport) return;
  await copyText(songMarkdown(currentReport), $("#copy-song-markdown"), "复制 Markdown");
});
$("#download-song-markdown").addEventListener("click", () => currentReport && download(`${songFileName(currentReport)}.md`, songMarkdown(currentReport), "text/markdown;charset=utf-8"));
$("#download-song-json").addEventListener("click", () => currentReport && download(`${songFileName(currentReport)}.json`, JSON.stringify(currentReport, null, 2), "application/json;charset=utf-8"));

$("#copy-markdown").addEventListener("click", async () => {
  if (!currentReport) return;
  await copyText(reportMarkdown(currentReport), $("#copy-markdown"), "复制 Markdown");
});
$("#download-markdown").addEventListener("click", () => currentReport && download(`${currentReport.release.title || "musicbrainz-report"}.md`, reportMarkdown(currentReport), "text/markdown;charset=utf-8"));
$("#download-checklist").addEventListener("click", () => currentReport && download(`${currentReport.release.title || "musicbrainz-checklist"}-checklist.md`, checklistMarkdown(currentReport), "text/markdown;charset=utf-8"));
$("#download-xml").addEventListener("click", () => currentReport && download(`${currentReport.release.title || "musicbrainz-workbook"}.xml`, reportXml(currentReport), "application/xml;charset=utf-8"));
$("#download-json").addEventListener("click", () => currentReport && download(`${currentReport.release.title || "musicbrainz-report"}.json`, JSON.stringify(currentReport, null, 2), "application/json;charset=utf-8"));

$("#copy-share").addEventListener("click", async (event) => {
  const urls = collectUrls();
  if (!urls.length) return;
  const params = new URLSearchParams();
  urls.forEach((url) => params.append("urls", url));
  const catalog = manualCatalogValue;
  if (catalog) params.set("catalog", catalog);
  await copyText(`${location.origin}${location.pathname}?${params.toString()}`, event.target, "复制分享链接");
});

$("#copy-events").addEventListener("click", async (event) => {
  const codes = ((currentReport || {}).release_events || {}).countries || [];
  await copyText(codes.map((item) => item.code).join(", "), event.target, "复制国家列表");
});

$("#copy-annotation").addEventListener("click", async (event) => {
  await copyText(((currentReport || {}).annotation || {}).combined || "", event.target, "复制 Annotation");
});

document.addEventListener("click", async (event) => {
  const toAlbum = event.target.closest(".song-to-album");
  if (toAlbum) {
    const url = (toAlbum.dataset.url || "").trim();
    if (url) {
      const input = $("#source-urls");
      if (input) input.value = url;
      runLookup();
    }
    return;
  }
  const events = event.target.closest(".copy-events");
  if (events) {
    await copyText(events.dataset.events || "", events, events.textContent);
    return;
  }
  const rg = event.target.closest(".copy-mbid");
  if (rg) {
    await copyText(rg.dataset.mbid || "", rg, rg.dataset.label || rg.textContent);
    rg.dataset.label = rg.dataset.label || "";
    return;
  }
});

// 分享链接：?urls=...&catalog=... 打开后自动重跑同样的查询
(function restoreSharedQuery() {
  const params = new URLSearchParams(location.search);
  // 新格式是多个 urls 参数，旧格式是一个逗号拼接的字符串，两种都收
  const urls = splitUrls(params.getAll("urls"));
  if (!urls.length) return;
  $("#source-urls").value = urls.join("\n");
  const catalog = params.get("catalog");
  if (catalog) manualCatalogValue = catalog;
  runLookup();
})();
document.addEventListener("click", async (event) => {
  const button = event.target.closest(".copy-note");
  if (!button) return;
  await copyText(button.dataset.note || "", button, "复制");
});

// 顶部栏显示当前访问地址
(function showHost() {
  const host = $("#run-host");
  if (host && location.host) host.textContent = `本地运行 · ${location.host}`;
})();

// 手动点击锚点后短暂压制滚动观察器，避免刚高亮就被观察器改回去
let railHighlightUntil = 0;

// 左导航锚点：自己用 scrollIntoView 落位，不依赖浏览器的原生锚点滚动。
// 原生锚点在 body 曾是滚动容器时只会滚到一半；scrollIntoView 会尊重 CSS 的
// scroll-margin-top，落点稳定停在吸顶工具栏下方，并且高亮立刻跟上。
(function railAnchors() {
  const list = document.querySelector("#rail-list");
  if (!list) return;
  list.addEventListener("click", (event) => {
    const link = event.target.closest('a[href^="#"]');
    if (!link) return;
    const target = document.querySelector(link.getAttribute("href"));
    if (!target) return;
    event.preventDefault();
    // 更新地址栏但不触发浏览器的锚点滚动
    history.replaceState(null, "", link.getAttribute("href"));
    railHighlightUntil = Date.now() + 900;
    target.scrollIntoView({ block: "start", behavior: "smooth" });
    list.querySelectorAll("a").forEach((item) => item.classList.toggle("active", item === link));
  });
})();

// 左导航：滚动时高亮当前模块
(function watchCurrentModule() {
  const list = $("#rail-list");
  if (!list || !("IntersectionObserver" in window)) return;
  const links = Array.from(list.querySelectorAll('a[href^="#"]'));
  const targets = links.map((link) => document.querySelector(link.getAttribute("href"))).filter(Boolean);
  if (!targets.length) return;
  const setActive = (id) => links.forEach((link) => link.classList.toggle("active", link.getAttribute("href") === `#${id}`));
  const visible = new Set();
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) visible.add(entry.target.id);
      else visible.delete(entry.target.id);
    }
    if (!visible.size || Date.now() < railHighlightUntil) return;
    // 并排两卡（如 04 / 05）在同一高度会同时进入判定区；固定取最靠上的那张，
    // 否则高亮会在两张卡之间随机跳
    const topmost = targets
      .filter((target) => visible.has(target.id))
      .reduce((a, b) => (a.getBoundingClientRect().top <= b.getBoundingClientRect().top ? a : b));
    setActive(topmost.id);
  }, { rootMargin: "-8% 0px -70% 0px" });
  targets.forEach((target) => observer.observe(target));
})();

// 内嵌浏览器（预览面板 / IDE webview）会把 target=_blank / window.open 的弹窗「收编」成当前标签页，
// 结果就是点一下链接，辛苦查出来的报告页直接被顶掉。
// 只在那种环境里接管：不弹新窗口、也不跳转，改成复制链接 + 提示，报告页一定保得住；
// 普通浏览器里不动，还是照旧新标签页打开。想直接跳转可用 Ctrl/⌘+点击，或把链接粘到地址栏。
const EMBEDDED_BROWSER = /Electron|Freebuff|Code\/|Electron\//i.test(navigator.userAgent) || "__freebuffSelectors" in window;

document.addEventListener("click", async (event) => {
  if (!EMBEDDED_BROWSER) return;
  const link = event.target.closest("a[href^='http']");
  if (!link || event.defaultPrevented) return;
  // 保留中键 / 修饰键的原生行为，交给浏览器自己处理
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  let copied = true;
  try {
    await navigator.clipboard.writeText(link.href);
  } catch (error) {
    copied = false;
  }
  showNotice(`${copied ? "链接已复制到剪贴板" : "链接如下（剪贴板不可用）"}，请粘到浏览器地址栏打开：\n${link.href}\n（这个预览面板会把新窗口换成当前页，直接点会丢失本次报告；确实要跳转请用 Ctrl/⌘ + 点击。）`);
});

// 返回顶部：滚动超过一屏才出现；点击平滑回到顶部（尊重系统「减少动态效果」）。
(function setupToTop() {
  const btn = $("#to-top");
  if (!btn) return;
  const onScroll = () => btn.classList.toggle("show", window.scrollY > 600);
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  btn.addEventListener("click", () => window.scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" }));
})();

// 左上角品牌徽标（Sleeve 图标）：点击返回首页 —— 收起报告区、清掉分享链接参数、回到首屏。
$(".brand").addEventListener("click", () => {
  $("#results").classList.add("hidden");
  currentReport = null;
  try { history.replaceState(null, "", location.pathname); } catch (error) { /* file:// 等环境不允许改地址栏时忽略 */ }
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  window.scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" });
});

// 数据源用量小徽标（右下角）：Soundcharts 配额余量。
// 只在配了 Soundcharts 且用量可查时显示；未配置、查询失败或用量格式异常都静默隐藏。
// 跟随 apiFetch 的鉴权：开了 SLEEVE_AUTH 时凭据失效会自动弹回登录层。
async function loadUsageBadge() {
  const badge = $("#usage-badge");
  if (!badge) return;
  try {
    const response = await apiFetch("/api/usage", { cache: "no-store" });
    if (!response.ok) return;
    const data = await response.json().catch(() => ({}));
    const sc = data.sources && data.sources.soundcharts;
    if (!sc || !sc.configured || !sc.usage || !sc.usage.quota) return;
    const { remaining, limit } = sc.usage.quota;
    if (typeof remaining !== "number" || typeof limit !== "number") return;
    badge.textContent = `Soundcharts 配额 ${remaining}/${limit}`;
    badge.classList.toggle("usage-low", limit > 0 && remaining / limit < 0.2);
    badge.classList.remove("hidden");
  } catch (error) { /* 用量显示失败不打扰主流程 */ }
}

// 启动认证检查（放在文件末尾：$ 与 DOM 都已就绪）。
// 用量徽标在认证流程走完后一并加载（未登录时 401 会由 apiFetch 弹回登录层）。
initAuth().finally(loadUsageBadge);
