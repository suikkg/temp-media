const COOKIE_NAME = "kkinto_session";
const PART_SIZE_BYTES = 8 * 1024 * 1024;
const SHORT_CODE_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const SHORT_CODE_LENGTH = 7;

function jsonResponse(data, init = {}) {
  const headers = new Headers(init.headers || {});
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(data), { ...init, headers });
}

function textResponse(text, init = {}) {
  const headers = new Headers(init.headers || {});
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "text/plain; charset=utf-8");
  }
  return new Response(text, { ...init, headers });
}

function htmlResponse(html, init = {}) {
  const headers = new Headers(init.headers || {});
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(html, { ...init, headers });
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function sanitizeHeaderValue(value) {
  return String(value || "").replace(/[\r\n"]/g, "_");
}

function buildBaseUrl(request) {
  return new URL("/", request.url).toString().replace(/\/$/, "");
}

function randomShortCode() {
  let code = "";
  for (let i = 0; i < SHORT_CODE_LENGTH; i++) {
    const index = Math.floor(Math.random() * SHORT_CODE_ALPHABET.length);
    code += SHORT_CODE_ALPHABET[index];
  }
  return code;
}

function parseJson(raw) {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (error) {
    return null;
  }
}

function metaKey(key) {
  return `meta:${key}`;
}

function shortKey(code) {
  return `short:${code}`;
}

async function readMeta(env, key) {
  const raw = await env.APP_KV.get(metaKey(key));
  const meta = parseJson(raw);
  return meta && typeof meta === "object" ? meta : null;
}

async function saveMeta(env, key, meta) {
  await env.APP_KV.put(metaKey(key), JSON.stringify(meta));
}

async function deleteMeta(env, key) {
  await env.APP_KV.delete(metaKey(key));
}

function buildMetaFromHead(key, head) {
  const custom = head.customMetadata || {};
  return {
    key,
    originalName: custom.originalName || key.split("/").pop(),
    size: head.size,
    uploadedAt: custom.uploadedAt || (head.uploaded ? head.uploaded.toISOString() : null),
    expiresAt: custom.expiresAt || null,
    groupId: custom.groupId || null,
    shortCode: custom.shortCode || null,
  };
}

async function getMetaForKey(env, key, head) {
  const meta = await readMeta(env, key);
  if (meta) return meta;
  if (head) return buildMetaFromHead(key, head);
  const fresh = await env.MEDIA_BUCKET.head(key);
  if (!fresh) return null;
  return buildMetaFromHead(key, fresh);
}

function extractExpiresAt(meta, head) {
  return meta?.expiresAt || head?.customMetadata?.expiresAt || null;
}

async function ensureShortCode(env, key, meta) {
  if (meta?.shortCode) return meta.shortCode;
  for (let attempt = 0; attempt < 6; attempt++) {
    const code = randomShortCode();
    const existing = await env.APP_KV.get(shortKey(code));
    if (existing) continue;
    await env.APP_KV.put(shortKey(code), key);
    const nextMeta = { ...(meta || {}), shortCode: code };
    await saveMeta(env, key, nextMeta);
    return code;
  }
  return null;
}

async function resolveShortCode(env, code) {
  return env.APP_KV.get(shortKey(code));
}

async function deleteShortCode(env, meta) {
  if (meta?.shortCode) {
    await env.APP_KV.delete(shortKey(meta.shortCode));
  }
}

function formatRemainingSeconds(seconds) {
  if (!Number.isFinite(seconds)) return "未知";
  if (seconds <= 0) return "已过期";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}天${hours}小时`;
  if (hours > 0) return `${hours}小时${minutes}分钟`;
  return `${minutes}分钟`;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "未知";
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const value = Math.round((bytes / Math.pow(k, i)) * 100) / 100;
  return `${value} ${sizes[i]}`;
}

function buildTokenUrls(request, key, token) {
  const baseUrl = buildBaseUrl(request);
  const mediaUrl = `${baseUrl}/media/${encodeURIComponent(key)}?token=${encodeURIComponent(token)}`;
  const viewUrl = `${baseUrl}/view/${encodeURIComponent(key)}?token=${encodeURIComponent(token)}`;
  const downloadUrl = `${mediaUrl}&download=1`;
  return { mediaUrl, viewUrl, downloadUrl };
}

async function deleteObjectAndMeta(env, key, head, meta) {
  await env.MEDIA_BUCKET.delete(key);
  if (head?.size) {
    await usageRequest(env, "/adjust", { delta: -head.size });
  }
  await deleteShortCode(env, meta);
  await deleteMeta(env, key);
}

function usageStub(env) {
  return env.USAGE.get(env.USAGE.idFromName("usage"));
}

async function usageRequest(env, path, body) {
  const res = await usageStub(env).fetch("https://usage" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return res;
}

async function usageGet(env, path) {
  const res = await usageStub(env).fetch("https://usage" + path, {
    method: "GET",
  });
  return res;
}

function corsHeaders() {
  const headers = new Headers();
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Range,Content-Type");
  return headers;
}

function getEnvNumber(env, key, fallback) {
  const raw = env[key];
  const value = raw === undefined ? fallback : Number(raw);
  return Number.isFinite(value) ? value : fallback;
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  const parts = header.split(";");
  for (const part of parts) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return null;
}

function setCookie(headers, name, value, options = {}) {
  const bits = [`${name}=${value}`];
  if (options.maxAge) bits.push(`Max-Age=${options.maxAge}`);
  if (options.httpOnly) bits.push("HttpOnly");
  if (options.secure) bits.push("Secure");
  if (options.sameSite) bits.push(`SameSite=${options.sameSite}`);
  if (options.path) bits.push(`Path=${options.path}`);
  headers.append("Set-Cookie", bits.join("; "));
}

function randomId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function sanitizeFilename(name) {
  const base = name.split("/").pop() || "file";
  return base.replace(/[^A-Za-z0-9._-]/g, "_");
}

function guessContentType(name) {
  const lower = name.toLowerCase();
  if (lower.endsWith(".m3u8")) return "application/vnd.apple.mpegurl";
  if (lower.endsWith(".ts")) return "video/mp2t";
  if (lower.endsWith(".mp4")) return "video/mp4";
  if (lower.endsWith(".webm")) return "video/webm";
  if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
  if (lower.endsWith(".png")) return "image/png";
  if (lower.endsWith(".webp")) return "image/webp";
  if (lower.endsWith(".gif")) return "image/gif";
  return "application/octet-stream";
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecodeToBytes(input) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "===".slice((normalized.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return base64UrlEncode(new Uint8Array(sig));
}

async function createToken(secret, key, expiresAtSeconds) {
  const payload = JSON.stringify({ k: key, exp: expiresAtSeconds });
  const payloadBytes = new TextEncoder().encode(payload);
  const payloadB64 = base64UrlEncode(payloadBytes);
  const signature = await hmacSign(secret, payload);
  return `${payloadB64}.${signature}`;
}

async function verifyToken(secret, token, key) {
  try {
    const [payloadB64, signature] = token.split(".");
    if (!payloadB64 || !signature) return null;
    const payloadBytes = base64UrlDecodeToBytes(payloadB64);
    const payload = new TextDecoder().decode(payloadBytes);
    const expectedSignature = await hmacSign(secret, payload);
    if (!timingSafeEqual(signature, expectedSignature)) return null;
    const data = JSON.parse(payload);
    if (!data || data.k !== key) return null;
    if (typeof data.exp !== "number" || Date.now() / 1000 > data.exp) return null;
    return data;
  } catch (error) {
    return null;
  }
}

async function requireAdmin(request, env) {
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return null;
  const session = await env.APP_KV.get(`session:${token}`);
  return session ? token : null;
}

function loginPage(message = "") {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Admin Login</title>
  <style>
    body { font-family: sans-serif; margin: 32px; background: #f7f8fb; }
    .box { max-width: 360px; margin: 0 auto; background: #fff; padding: 16px; border-radius: 12px; border: 1px solid #e6e8ef; }
    label { display: block; margin-top: 12px; }
    input { width: 100%; padding: 8px; }
    button { margin-top: 16px; padding: 8px 12px; width: 100%; }
    .error { color: #b00020; margin-top: 12px; }
    @media (max-width: 600px) {
      body { margin: 16px; }
    }
  </style>
</head>
<body>
  <div class="box">
    <h1>Admin Login</h1>
    <form method="post" action="/login">
      <label>Username</label>
      <input name="username" autocomplete="username" required />
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" required />
      <button type="submit">Sign in</button>
    </form>
    ${message ? `<div class="error">${message}</div>` : ""}
  </div>
</body>
</html>`;
}

function publicHomePage() {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Temp Media</title>
  <style>
    body { font-family: sans-serif; margin: 32px; }
    a { color: #0057ff; text-decoration: none; }
    @media (max-width: 600px) {
      body { margin: 16px; }
    }
  </style>
</head>
<body>
  <h1>临时文件服务</h1>
  <p><a href="/login">管理员登录</a></p>
</body>
</html>`;
}

function adminStyles() {
  return `
    :root {
      --bg: #f7f8fb;
      --card: #ffffff;
      --border: #e6e8ef;
      --text: #1f2937;
      --muted: #6b7280;
      --primary: #2563eb;
      --primary-dark: #1e4ed8;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    a { color: var(--primary); text-decoration: none; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 24px;
      background: var(--card);
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 10;
      gap: 16px;
    }
    .brand { font-weight: 600; }
    .nav { display: flex; gap: 16px; align-items: center; }
    .nav a { color: var(--muted); font-weight: 500; padding-bottom: 4px; border-bottom: 2px solid transparent; }
    .nav a.active { color: var(--text); border-bottom-color: var(--primary); }
    .container { max-width: 1200px; margin: 24px auto; padding: 0 24px 48px; }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 16px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    }
    .card-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 12px; }
    .card-header h1, .card-header h2 { margin: 0; }
    .muted { color: var(--muted); font-size: 13px; }
    .status-grid, .stats-grid, .form-grid {
      display: grid;
      gap: 16px;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    }
    .stat { display: flex; flex-direction: column; gap: 4px; }
    .stat-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; }
    .stat-value { font-size: 20px; font-weight: 600; }
    .stat-sub { font-size: 12px; color: var(--muted); }
    .progress { background: #eef0f5; border-radius: 999px; height: 8px; margin-top: 12px; overflow: hidden; }
    .progress-bar { background: var(--primary); height: 100%; width: 0%; transition: width 0.2s ease; }
    .actions-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .btn {
      background: var(--primary);
      color: #fff;
      border: 0;
      border-radius: 8px;
      padding: 8px 12px;
      cursor: pointer;
      font-size: 13px;
    }
    .btn:hover { background: var(--primary-dark); }
    .btn-secondary { background: #f3f4f6; color: #111827; }
    .btn-secondary:hover { background: #e5e7eb; }
    .btn-outline { background: #fff; border: 1px solid var(--border); color: #111827; }
    .btn-danger { background: var(--danger); color: #fff; }
    .btn-danger:hover { background: #dc2626; }
    .btn-xs { padding: 6px 10px; font-size: 12px; }
    input[type="file"], input[type="text"], input[type="search"], input {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--border);
      border-radius: 8px;
    }
    label { font-size: 13px; color: var(--muted); display: block; margin-bottom: 6px; }
    .log {
      white-space: pre-wrap;
      background: #f4f4f5;
      padding: 12px;
      border-radius: 8px;
      min-height: 64px;
      font-size: 12px;
    }
    .links { display: grid; gap: 8px; margin-top: 12px; }
    .link-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 8px 10px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #fafafa;
    }
    .link-item a { font-size: 13px; word-break: break-all; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px 12px; border-bottom: 1px solid var(--border); text-align: left; font-size: 13px; }
    th { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }
    tbody tr:hover { background: #f9fafb; }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 6px;
      border-radius: 999px;
      background: #eef2ff;
      color: #3730a3;
      font-size: 11px;
    }
    .badge.expired { background: #fee2e2; color: #b91c1c; }
    .file-name { font-weight: 600; }
    .file-sub { font-size: 12px; color: var(--muted); margin-top: 4px; }
    .files-actions { display: flex; flex-wrap: wrap; gap: 6px; }
    @media (max-width: 720px) {
      .topbar { flex-direction: column; align-items: flex-start; }
      .card-header { flex-direction: column; align-items: flex-start; }
      .nav { flex-wrap: wrap; }
      .container { padding: 0 12px 32px; }
      .topbar { padding: 12px; }
      .card { padding: 12px; }
      table, thead, tbody, th, td, tr { display: block; width: 100%; }
      thead { display: none; }
      tr { border: 1px solid var(--border); border-radius: 10px; padding: 8px; margin-bottom: 10px; background: #fff; }
      td { border: none; padding: 6px 0; }
      td::before {
        content: attr(data-label);
        display: block;
        font-size: 11px;
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 2px;
      }
      .files-actions { gap: 4px; }
      .actions-row { gap: 6px; }
    }
  `;
}

function adminShell({ title, active, body }) {
  const navItems = [
    { href: "/admin", label: "文件", key: "files" },
    { href: "/admin/stats", label: "统计", key: "stats" },
  ];
  const navHtml = navItems
    .map((item) => `<a href="${item.href}" class="${active === item.key ? "active" : ""}">${item.label}</a>`)
    .join("");
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>${adminStyles()}</style>
</head>
<body>
  <header class="topbar">
    <div class="brand">临时文件服务</div>
    <nav class="nav">${navHtml}</nav>
    <form id="logout" method="post" action="/logout">
      <button type="submit" class="btn btn-secondary btn-xs">退出登录</button>
    </form>
  </header>
  <main class="container">
    ${body}
  </main>
</body>
</html>`;
}

function adminPage() {
  const body = `
  <section class="card">
    <div class="card-header">
      <div>
        <h1>管理员控制台</h1>
        <div class="muted">单文件 1GB，上限 5GB，默认 1 天后自动删除。</div>
      </div>
      <div class="actions-row">
        <button class="btn btn-secondary btn-xs" id="refreshStatus">刷新状态</button>
      </div>
    </div>
    <div class="status-grid">
      <div class="stat">
        <div class="stat-label">已占用</div>
        <div class="stat-value" id="statusTotal">-</div>
        <div class="stat-sub" id="statusBreakdown">-</div>
      </div>
      <div class="stat">
        <div class="stat-label">空间上限</div>
        <div class="stat-value" id="statusLimit">-</div>
        <div class="stat-sub" id="statusPercent">-</div>
      </div>
      <div class="stat">
        <div class="stat-label">单文件上限</div>
        <div class="stat-value" id="statusMaxFile">-</div>
        <div class="stat-sub" id="statusTtl">-</div>
      </div>
    </div>
    <div class="progress">
      <div class="progress-bar" id="usageBar"></div>
    </div>
    <div class="muted" id="statusNote"></div>
  </section>

  <section class="card" id="uploadSection">
    <div class="card-header">
      <div>
        <h2>上传文件</h2>
        <div class="muted">同一组 HLS 文件请填写相同的 Group ID。</div>
      </div>
    </div>
    <div class="form-grid">
      <div>
        <label for="groupId">Group ID（可选）</label>
        <input id="groupId" placeholder="留空自动生成" />
      </div>
      <div>
        <label for="files">选择文件</label>
        <input id="files" type="file" multiple />
      </div>
    </div>
    <div class="actions-row" style="margin-top: 12px;">
      <button class="btn" id="upload">开始上传</button>
    </div>
    <div class="log" id="log" style="margin-top: 12px;"></div>
    <div class="links" id="links"></div>
  </section>

  <section class="card">
    <div class="card-header">
      <div>
        <h2>文件列表</h2>
        <div class="muted" id="filesSummary">加载中...</div>
      </div>
      <div class="actions-row">
        <button class="btn btn-secondary btn-xs" id="refreshFiles">刷新列表</button>
        <button class="btn btn-secondary btn-xs" id="loadMoreFiles">加载更多</button>
      </div>
    </div>
    <div class="table-wrap">
      <table class="files-table">
        <thead>
          <tr>
            <th>文件</th>
            <th>大小</th>
            <th>上传时间</th>
            <th>到期时间</th>
            <th>剩余</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="filesBody"></tbody>
      </table>
    </div>
  </section>

  <script>
    const statusTotalEl = document.getElementById('statusTotal');
    const statusBreakdownEl = document.getElementById('statusBreakdown');
    const statusLimitEl = document.getElementById('statusLimit');
    const statusPercentEl = document.getElementById('statusPercent');
    const statusMaxFileEl = document.getElementById('statusMaxFile');
    const statusTtlEl = document.getElementById('statusTtl');
    const statusNoteEl = document.getElementById('statusNote');
    const usageBarEl = document.getElementById('usageBar');
    const refreshStatusBtn = document.getElementById('refreshStatus');
    const logEl = document.getElementById('log');
    const linksEl = document.getElementById('links');
    const groupInput = document.getElementById('groupId');
    const filesBody = document.getElementById('filesBody');
    const filesSummaryEl = document.getElementById('filesSummary');
    const refreshFilesBtn = document.getElementById('refreshFiles');
    const loadMoreFilesBtn = document.getElementById('loadMoreFiles');
    let filesCursor = null;
    let filesLoading = false;
    let loadedCount = 0;

    function log(message) {
      logEl.textContent += message + "\\n";
    }

    function formatBytes(bytes) {
      if (!Number.isFinite(bytes)) return '-';
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      const value = Math.round(bytes / Math.pow(k, i) * 100) / 100;
      return value + ' ' + sizes[i];
    }

    function formatRemaining(seconds) {
      if (!Number.isFinite(seconds)) return '未知';
      if (seconds <= 0) return '已过期';
      const days = Math.floor(seconds / 86400);
      const hours = Math.floor((seconds % 86400) / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      if (days > 0) return days + '天' + hours + '小时';
      if (hours > 0) return hours + '小时' + minutes + '分钟';
      return minutes + '分钟';
    }

    function formatDuration(seconds) {
      if (!Number.isFinite(seconds)) return '-';
      if (seconds >= 86400) {
        const days = Math.round(seconds / 86400);
        return days + ' 天';
      }
      const hours = Math.round(seconds / 3600);
      return hours + ' 小时';
    }

    function formatDate(value) {
      if (!value) return '-';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return '-';
      return date.toLocaleString('zh-CN');
    }

    function copyText(text) {
      if (!text) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text);
      } else {
        window.prompt('复制链接', text);
      }
    }

    function clearFiles() {
      filesBody.textContent = '';
      filesCursor = null;
      loadedCount = 0;
    }

    function renderEmptyRow() {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.dataset.label = '提示';
      td.textContent = '暂无文件';
      tr.appendChild(td);
      filesBody.appendChild(tr);
    }

    function renderFileRow(item) {
      const tr = document.createElement('tr');
      const nameTd = document.createElement('td');
      nameTd.dataset.label = '文件';
      const nameWrap = document.createElement('div');
      nameWrap.className = 'file-name';
      if (item.viewUrl) {
        const link = document.createElement('a');
        link.href = item.viewUrl;
        link.target = '_blank';
        link.textContent = item.filename;
        nameWrap.appendChild(link);
      } else {
        nameWrap.textContent = item.filename;
      }
      const sub = document.createElement('div');
      sub.className = 'file-sub';
      sub.textContent = item.key;
      nameTd.appendChild(nameWrap);
      nameTd.appendChild(sub);

      const sizeTd = document.createElement('td');
      sizeTd.dataset.label = '大小';
      sizeTd.textContent = formatBytes(item.size);

      const uploadedTd = document.createElement('td');
      uploadedTd.dataset.label = '上传时间';
      uploadedTd.textContent = formatDate(item.uploadedAt);

      const expTd = document.createElement('td');
      expTd.dataset.label = '到期时间';
      expTd.textContent = item.expiresAt ? new Date(item.expiresAt).toLocaleString('zh-CN') : '-';
      if (item.expired) {
        const badge = document.createElement('span');
        badge.className = 'badge expired';
        badge.textContent = '已过期';
        expTd.appendChild(document.createElement('br'));
        expTd.appendChild(badge);
      }

      const remainingTd = document.createElement('td');
      remainingTd.dataset.label = '剩余';
      remainingTd.textContent = formatRemaining(item.remainingSeconds);

      const actionsTd = document.createElement('td');
      actionsTd.className = 'files-actions';
      actionsTd.dataset.label = '操作';

      const viewBtn = document.createElement('button');
      viewBtn.textContent = '预览';
      viewBtn.className = 'btn btn-secondary btn-xs';
      viewBtn.dataset.action = 'view';
      viewBtn.dataset.url = item.viewUrl || '';
      viewBtn.disabled = !item.viewUrl;

      const downloadBtn = document.createElement('button');
      downloadBtn.textContent = '下载';
      downloadBtn.className = 'btn btn-secondary btn-xs';
      downloadBtn.dataset.action = 'download';
      downloadBtn.dataset.url = item.downloadUrl || '';
      downloadBtn.disabled = !item.downloadUrl;

      const copyShareBtn = document.createElement('button');
      copyShareBtn.textContent = item.shortUrl ? '复制短链' : '生成短链';
      copyShareBtn.className = 'btn btn-outline btn-xs';
      copyShareBtn.dataset.action = item.shortUrl ? 'copyShare' : 'shorten';
      copyShareBtn.dataset.key = encodeURIComponent(item.key);
      copyShareBtn.dataset.url = item.shortUrl || '';

      const sharePageBtn = document.createElement('button');
      sharePageBtn.textContent = '分享页';
      sharePageBtn.className = 'btn btn-outline btn-xs';
      sharePageBtn.dataset.action = 'sharePage';
      sharePageBtn.dataset.url = item.sharePageUrl || '';
      sharePageBtn.disabled = !item.sharePageUrl;

      const copyDirectBtn = document.createElement('button');
      copyDirectBtn.textContent = '复制直链';
      copyDirectBtn.className = 'btn btn-outline btn-xs';
      copyDirectBtn.dataset.action = 'copyDirect';
      copyDirectBtn.dataset.url = item.directUrl || '';
      copyDirectBtn.disabled = !item.directUrl;

      const extend1 = document.createElement('button');
      extend1.textContent = '+1天';
      extend1.className = 'btn btn-outline btn-xs';
      extend1.dataset.action = 'extend';
      extend1.dataset.key = encodeURIComponent(item.key);
      extend1.dataset.days = '1';

      const extend3 = document.createElement('button');
      extend3.textContent = '+3天';
      extend3.className = 'btn btn-outline btn-xs';
      extend3.dataset.action = 'extend';
      extend3.dataset.key = encodeURIComponent(item.key);
      extend3.dataset.days = '3';

      const extend5 = document.createElement('button');
      extend5.textContent = '+5天';
      extend5.className = 'btn btn-outline btn-xs';
      extend5.dataset.action = 'extend';
      extend5.dataset.key = encodeURIComponent(item.key);
      extend5.dataset.days = '5';

      const deleteBtn = document.createElement('button');
      deleteBtn.textContent = '删除';
      deleteBtn.className = 'btn btn-danger btn-xs';
      deleteBtn.dataset.action = 'delete';
      deleteBtn.dataset.key = encodeURIComponent(item.key);

      actionsTd.appendChild(viewBtn);
      actionsTd.appendChild(downloadBtn);
      actionsTd.appendChild(copyShareBtn);
      actionsTd.appendChild(copyDirectBtn);
      actionsTd.appendChild(sharePageBtn);
      actionsTd.appendChild(extend1);
      actionsTd.appendChild(extend3);
      actionsTd.appendChild(extend5);
      actionsTd.appendChild(deleteBtn);

      tr.appendChild(nameTd);
      tr.appendChild(sizeTd);
      tr.appendChild(uploadedTd);
      tr.appendChild(expTd);
      tr.appendChild(remainingTd);
      tr.appendChild(actionsTd);
      filesBody.appendChild(tr);
    }

    async function loadFiles(reset) {
      if (filesLoading) return;
      filesLoading = true;
      if (reset) clearFiles();
      const url = filesCursor ? '/api/files?cursor=' + encodeURIComponent(filesCursor) : '/api/files';
      const res = await fetch(url);
      if (!res.ok) {
        filesLoading = false;
        return;
      }
      const data = await res.json();
      if (!data.items.length && loadedCount === 0) {
        renderEmptyRow();
      } else {
        data.items.forEach(renderFileRow);
        loadedCount += data.items.length;
      }
      filesCursor = data.cursor || null;
      loadMoreFilesBtn.disabled = !data.hasMore;
      loadMoreFilesBtn.style.display = data.hasMore ? 'inline-flex' : 'none';
      filesSummaryEl.textContent = loadedCount ? ('已加载 ' + loadedCount + ' 个文件') : '暂无文件';
      filesLoading = false;
    }

    filesBody.addEventListener('click', async (event) => {
      const btn = event.target.closest('button');
      if (!btn) return;
      const action = btn.dataset.action;
      if (action === 'view' || action === 'download') {
        const url = btn.dataset.url;
        if (url) window.open(url, '_blank');
        return;
      }
      if (action === 'copyShare' || action === 'copyDirect') {
        copyText(btn.dataset.url || '');
        return;
      }
      if (action === 'sharePage') {
        const url = btn.dataset.url;
        if (url) window.open(url, '_blank');
        return;
      }
      if (action === 'shorten') {
        const key = decodeURIComponent(btn.dataset.key || '');
        const res = await fetch('/api/files/shorten', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key })
        });
        if (res.ok) {
          await loadFiles(true);
        }
        return;
      }
      if (action === 'extend') {
        const key = decodeURIComponent(btn.dataset.key || '');
        const days = Number(btn.dataset.days || 0);
        const res = await fetch('/api/files/extend', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key, days })
        });
        if (res.ok) {
          await loadFiles(true);
        }
        return;
      }
      if (action === 'delete') {
        const key = decodeURIComponent(btn.dataset.key || '');
        if (!window.confirm('确定要删除这个文件吗？')) return;
        const res = await fetch('/api/files/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key })
        });
        if (res.ok) {
          await loadFiles(true);
          await refreshStatus();
        }
      }
    });

    function addLinkItem(label, url) {
      if (!url) return;
      const row = document.createElement('div');
      row.className = 'link-item';
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.target = '_blank';
      anchor.textContent = label;
      const copyBtn = document.createElement('button');
      copyBtn.className = 'btn btn-outline btn-xs';
      copyBtn.textContent = '复制';
      copyBtn.addEventListener('click', () => copyText(url));
      row.appendChild(anchor);
      row.appendChild(copyBtn);
      linksEl.appendChild(row);
    }

    async function refreshStatus() {
      const res = await fetch('/api/status');
      if (!res.ok) {
        statusNoteEl.textContent = '状态加载失败';
        return;
      }
      const data = await res.json();
      const used = data.totalBytes;
      const reserved = data.reservedBytes || 0;
      const total = used + reserved;
      const maxTotal = data.maxTotalBytes || 0;
      const percent = maxTotal ? Math.min(100, Math.round(total / maxTotal * 100)) : 0;
      statusTotalEl.textContent = formatBytes(total);
      statusBreakdownEl.textContent = '已用 ' + formatBytes(used) + ' · 预留 ' + formatBytes(reserved);
      statusLimitEl.textContent = formatBytes(maxTotal);
      statusPercentEl.textContent = percent + '%';
      statusMaxFileEl.textContent = formatBytes(data.maxFileBytes || 0);
      statusTtlEl.textContent = '保留 ' + formatDuration(data.mediaTtlSeconds);
      usageBarEl.style.width = percent + '%';
      statusNoteEl.textContent = '最大文件 ' + formatBytes(data.maxFileBytes || 0) + '，超过将拒绝上传。';
    }

    async function startUpload(file, groupId) {
      const res = await fetch('/api/uploads/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: file.name,
          size: file.size,
          contentType: file.type,
          groupId
        })
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      return res.json();
    }

    async function uploadPart(uploadToken, partNumber, chunk) {
      const res = await fetch('/api/uploads/part?uploadToken=' + encodeURIComponent(uploadToken) + '&partNumber=' + partNumber, {
        method: 'POST',
        body: chunk
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      return res.json();
    }

    async function completeUpload(uploadToken) {
      const res = await fetch('/api/uploads/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uploadToken })
      });
      if (!res.ok) {
        throw new Error(await res.text());
      }
      return res.json();
    }

    async function uploadFile(file, groupId) {
      const start = await startUpload(file, groupId);
      const partSize = start.partSize;
      const totalParts = Math.ceil(file.size / partSize);
      let offset = 0;
      for (let partNumber = 1; partNumber <= totalParts; partNumber++) {
        const chunk = file.slice(offset, offset + partSize);
        await uploadPart(start.uploadToken, partNumber, chunk);
        offset += partSize;
        log('上传分片 ' + partNumber + '/' + totalParts + ' : ' + file.name);
      }
      const complete = await completeUpload(start.uploadToken);
      return { ...complete, groupId: start.groupId };
    }

    document.getElementById('upload').addEventListener('click', async (event) => {
      event.preventDefault();
      linksEl.textContent = '';
      logEl.textContent = '';
      const files = Array.from(document.getElementById('files').files);
      if (!files.length) {
        log('请选择文件。');
        return;
      }
      let groupId = groupInput.value.trim();
      for (const file of files) {
        log('开始上传：' + file.name);
        const result = await uploadFile(file, groupId || undefined);
        if (!groupId) {
          groupId = result.groupId;
          groupInput.value = groupId;
        }
        log('上传完成：' + file.name);
        addLinkItem(file.name + ' - 预览链接', result.viewUrl);
        addLinkItem(file.name + ' - 下载链接', result.downloadUrl || result.mediaUrl);
        addLinkItem(file.name + ' - 短链接', result.shortUrl);
        addLinkItem(file.name + ' - 分享页', result.sharePageUrl);
      }
      await refreshStatus();
      await loadFiles(true);
    });

    refreshStatus();
    loadFiles(true);
    refreshFilesBtn.addEventListener('click', () => loadFiles(true));
    loadMoreFilesBtn.addEventListener('click', () => loadFiles(false));
    refreshStatusBtn.addEventListener('click', refreshStatus);
  </script>`;

  return adminShell({ title: "Temp Media Admin", active: "files", body });
}

function statsPage() {
  const body = `
  <section class="card">
    <div class="card-header">
      <div>
        <h1>存储统计</h1>
        <div class="muted">统计数据来源于 R2 列表与当前使用量记录。</div>
      </div>
      <div class="actions-row">
        <button class="btn btn-secondary btn-xs" id="refreshStats">刷新</button>
      </div>
    </div>
    <div class="stats-grid">
      <div class="stat">
        <div class="stat-label">文件总数</div>
        <div class="stat-value" id="statFileCount">-</div>
        <div class="stat-sub" id="statLatestUpload">-</div>
      </div>
      <div class="stat">
        <div class="stat-label">已占用空间</div>
        <div class="stat-value" id="statTotalBytes">-</div>
        <div class="stat-sub" id="statTotalBreakdown">-</div>
      </div>
      <div class="stat">
        <div class="stat-label">空间上限</div>
        <div class="stat-value" id="statMaxBytes">-</div>
        <div class="stat-sub" id="statUsagePercent">-</div>
      </div>
    </div>
    <div class="progress">
      <div class="progress-bar" id="statsUsageBar"></div>
    </div>
  </section>

  <section class="card">
    <div class="card-header">
      <div>
        <h2>到期统计</h2>
        <div class="muted">统计包含未来 1/3/7 天内的到期文件。</div>
      </div>
    </div>
    <div class="stats-grid">
      <div class="stat">
        <div class="stat-label">已过期</div>
        <div class="stat-value" id="statExpired">-</div>
      </div>
      <div class="stat">
        <div class="stat-label">1 天内</div>
        <div class="stat-value" id="statExpiring1d">-</div>
      </div>
      <div class="stat">
        <div class="stat-label">3 天内</div>
        <div class="stat-value" id="statExpiring3d">-</div>
      </div>
      <div class="stat">
        <div class="stat-label">7 天内</div>
        <div class="stat-value" id="statExpiring7d">-</div>
      </div>
    </div>
    <div class="muted" id="statNextExpiry" style="margin-top: 12px;"></div>
  </section>

  <script>
    const refreshStatsBtn = document.getElementById('refreshStats');
    const statFileCountEl = document.getElementById('statFileCount');
    const statLatestUploadEl = document.getElementById('statLatestUpload');
    const statTotalBytesEl = document.getElementById('statTotalBytes');
    const statTotalBreakdownEl = document.getElementById('statTotalBreakdown');
    const statMaxBytesEl = document.getElementById('statMaxBytes');
    const statUsagePercentEl = document.getElementById('statUsagePercent');
    const statsUsageBarEl = document.getElementById('statsUsageBar');
    const statExpiredEl = document.getElementById('statExpired');
    const statExpiring1dEl = document.getElementById('statExpiring1d');
    const statExpiring3dEl = document.getElementById('statExpiring3d');
    const statExpiring7dEl = document.getElementById('statExpiring7d');
    const statNextExpiryEl = document.getElementById('statNextExpiry');

    function formatBytes(bytes) {
      if (!Number.isFinite(bytes)) return '-';
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      const value = Math.round(bytes / Math.pow(k, i) * 100) / 100;
      return value + ' ' + sizes[i];
    }

    function formatDate(value) {
      if (!value) return '-';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return '-';
      return date.toLocaleString('zh-CN');
    }

    async function loadStats() {
      const res = await fetch('/api/stats');
      if (!res.ok) {
        statNextExpiryEl.textContent = '统计加载失败';
        return;
      }
      const data = await res.json();
      const total = (data.usedBytes || 0) + (data.reservedBytes || 0);
      const maxTotal = data.maxTotalBytes || 0;
      const percent = maxTotal ? Math.min(100, Math.round(total / maxTotal * 100)) : 0;
      statFileCountEl.textContent = data.fileCount || 0;
      statLatestUploadEl.textContent = '最近上传：' + formatDate(data.latestUploadAt);
      statTotalBytesEl.textContent = formatBytes(total);
      statTotalBreakdownEl.textContent = '已用 ' + formatBytes(data.usedBytes) + ' · 预留 ' + formatBytes(data.reservedBytes || 0);
      statMaxBytesEl.textContent = formatBytes(maxTotal);
      statUsagePercentEl.textContent = percent + '%';
      statsUsageBarEl.style.width = percent + '%';
      statExpiredEl.textContent = data.expiredCount || 0;
      statExpiring1dEl.textContent = data.expiring1d || 0;
      statExpiring3dEl.textContent = data.expiring3d || 0;
      statExpiring7dEl.textContent = data.expiring7d || 0;
      statNextExpiryEl.textContent = data.nextExpiryAt ? ('最近到期：' + formatDate(data.nextExpiryAt)) : '暂无即将到期的文件';
    }

    loadStats();
    refreshStatsBtn.addEventListener('click', loadStats);
  </script>`;

  return adminShell({ title: "Temp Media Stats", active: "stats", body });
}

function viewPage({ mediaUrl, name, contentType, isPlaylist }) {
  const isVideo = contentType.startsWith("video/") || contentType.includes("mpegurl");
  const hlsScript = isPlaylist
    ? `<script src="https://cdn.jsdelivr.net/npm/hls.js@1.5.8/dist/hls.min.js"></script>
  <script>
    (function () {
      var video = document.getElementById('player');
      var notice = document.getElementById('notice');
      var mediaUrl = ${JSON.stringify(mediaUrl)};
      if (window.Hls && window.Hls.isSupported()) {
        var hls = new window.Hls();
        hls.loadSource(mediaUrl);
        hls.attachMedia(video);
        return;
      }
      if (video.canPlayType('application/vnd.apple.mpegurl')) {
        video.src = mediaUrl;
        return;
      }
      if (notice) {
        notice.textContent = 'Your browser does not support HLS playback.';
      }
    })();
  </script>`
    : "";
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${name}</title>
  <style>
    body { font-family: sans-serif; margin: 24px; }
    video, img { max-width: 100%; height: auto; }
    #notice { margin-top: 12px; color: #b00020; }
    @media (max-width: 600px) {
      body { margin: 16px; }
      h1 { font-size: 20px; }
    }
  </style>
</head>
<body>
  <h1>${name}</h1>
  ${isVideo ? (isPlaylist ? `<video id="player" controls></video><div id="notice"></div>` : `<video controls src="${mediaUrl}"></video>`) : `<img alt="${name}" src="${mediaUrl}" />`}
  ${hlsScript}
</body>
</html>`;
}

function sharePage({ name, size, uploadedAt, expiresAt, remaining, shareUrl, viewUrl, downloadUrl }) {
  const safeName = escapeHtml(name);
  const safeShareUrl = escapeHtml(shareUrl || "");
  const safeViewUrl = escapeHtml(viewUrl || "");
  const safeDownloadUrl = escapeHtml(downloadUrl || "");
  const uploadedText = uploadedAt ? new Date(uploadedAt).toLocaleString("zh-CN") : "未知";
  const expiresText = expiresAt ? new Date(expiresAt).toLocaleString("zh-CN") : "未知";
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${safeName}</title>
  <style>
    body { font-family: sans-serif; margin: 24px; }
    .meta { color: #555; margin-top: 6px; }
    .actions { margin: 16px 0; display: flex; gap: 12px; flex-wrap: wrap; }
    .btn { background: #0057ff; color: #fff; padding: 8px 14px; border-radius: 6px; text-decoration: none; }
    .link-group { margin-top: 16px; }
    input { width: 100%; padding: 8px; }
    button { margin-left: 8px; padding: 8px 12px; }
    .row { display: flex; align-items: center; gap: 8px; }
    @media (max-width: 600px) {
      body { margin: 16px; }
      .actions { flex-direction: column; }
      .btn { width: 100%; text-align: center; }
      .row { flex-direction: column; align-items: stretch; }
      button { margin-left: 0; width: 100%; }
    }
  </style>
</head>
<body>
  <h1>${safeName}</h1>
  <div class="meta">大小：${formatBytes(size)}</div>
  <div class="meta">上传时间：${uploadedText}</div>
  <div class="meta">到期时间：${expiresText}</div>
  <div class="meta">剩余时间：${escapeHtml(remaining)}</div>

  <div class="actions">
    ${safeViewUrl ? `<a class="btn" href="${safeViewUrl}" target="_blank">预览</a>` : ""}
    ${safeDownloadUrl ? `<a class="btn" href="${safeDownloadUrl}" target="_blank">下载</a>` : ""}
  </div>

  ${safeShareUrl ? `
  <div class="link-group">
    <div>短链接</div>
    <div class="row">
      <input id="shortUrl" value="${safeShareUrl}" readonly />
      <button data-copy="shortUrl">复制</button>
    </div>
  </div>` : ""}

  <div class="link-group">
    <div>预览链接</div>
    <div class="row">
      <input id="viewUrl" value="${safeViewUrl}" readonly />
      <button data-copy="viewUrl">复制</button>
    </div>
  </div>

  <div class="link-group">
    <div>下载链接</div>
    <div class="row">
      <input id="downloadUrl" value="${safeDownloadUrl}" readonly />
      <button data-copy="downloadUrl">复制</button>
    </div>
  </div>

  <script>
    function copyInput(id) {
      var input = document.getElementById(id);
      if (!input) return;
      try {
        navigator.clipboard.writeText(input.value);
      } catch (e) {
        window.prompt('复制链接', input.value);
      }
    }
    document.querySelectorAll('button[data-copy]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        copyInput(btn.getAttribute('data-copy'));
      });
    });
  </script>
</body>
</html>`;
}

function parseRangeHeader(rangeHeader, size) {
  if (!rangeHeader || !rangeHeader.startsWith("bytes=")) return null;
  const range = rangeHeader.replace(/bytes=/, "").split("-");
  let start = range[0] ? Number(range[0]) : NaN;
  let end = range[1] ? Number(range[1]) : NaN;
  if (Number.isNaN(start)) {
    const suffixLength = end;
    if (Number.isNaN(suffixLength)) return null;
    start = Math.max(size - suffixLength, 0);
    end = size - 1;
  } else if (Number.isNaN(end)) {
    end = size - 1;
  }
  if (start < 0 || end < start || start >= size) return null;
  return { start, end };
}

function rewriteM3U8(content, token) {
  const lines = content.split(/\r?\n/);
  const encodedToken = encodeURIComponent(token);
  const output = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      output.push(line);
      continue;
    }
    if (/^https?:\/\//i.test(trimmed)) {
      output.push(line);
      continue;
    }
    const separator = trimmed.includes("?") ? "&" : "?";
    output.push(trimmed + separator + "token=" + encodedToken);
  }
  return output.join("\n");
}

async function handleLogin(request, env) {
  const form = await request.formData();
  const username = String(form.get("username") || "");
  const password = String(form.get("password") || "");
  if (username !== env.ADMIN_USERNAME || password !== env.ADMIN_PASSWORD) {
    return htmlResponse(loginPage("Invalid credentials"), { status: 401 });
  }
  const token = randomId();
  const sessionTtl = getEnvNumber(env, "SESSION_TTL_SECONDS", 604800);
  await env.APP_KV.put(`session:${token}`, "1", { expirationTtl: sessionTtl });
  const headers = new Headers();
  setCookie(headers, COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    path: "/",
    maxAge: sessionTtl,
  });
  headers.set("Location", "/admin");
  return new Response(null, { status: 302, headers });
}

async function handleLogout(request, env) {
  const token = getCookie(request, COOKIE_NAME);
  if (token) {
    await env.APP_KV.delete(`session:${token}`);
  }
  const headers = new Headers();
  setCookie(headers, COOKIE_NAME, "", {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    path: "/",
    maxAge: 0,
  });
  headers.set("Location", "/login");
  return new Response(null, { status: 302, headers });
}

async function handleStatus(env) {
  const usageRes = await usageGet(env, "/status");
  if (!usageRes.ok) {
    return textResponse("Usage unavailable", { status: 503 });
  }
  const usage = await usageRes.json();
  const maxFileBytes = getEnvNumber(env, "MAX_FILE_BYTES", 1073741824);
  const maxTotalBytes = getEnvNumber(env, "MAX_TOTAL_BYTES", 5368709120);
  const mediaTtlSeconds = getEnvNumber(env, "MEDIA_TTL_SECONDS", 86400);
  return jsonResponse({
    totalBytes: usage.usedBytes,
    reservedBytes: usage.reservedBytes,
    maxFileBytes,
    maxTotalBytes,
    mediaTtlSeconds,
  });
}

async function handleStats(env) {
  const usageRes = await usageGet(env, "/status");
  if (!usageRes.ok) {
    return textResponse("Usage unavailable", { status: 503 });
  }
  const usage = await usageRes.json();
  const maxFileBytes = getEnvNumber(env, "MAX_FILE_BYTES", 1073741824);
  const maxTotalBytes = getEnvNumber(env, "MAX_TOTAL_BYTES", 5368709120);
  const mediaTtlSeconds = getEnvNumber(env, "MEDIA_TTL_SECONDS", 86400);
  const now = Date.now();
  const dayMs = 86400 * 1000;
  let fileCount = 0;
  let totalBytes = 0;
  let expiredCount = 0;
  let expiring1d = 0;
  let expiring3d = 0;
  let expiring7d = 0;
  let nextExpiryAt = null;
  let latestUploadAt = null;

  let cursor;
  do {
    const listing = await env.MEDIA_BUCKET.list({ cursor, limit: 1000 });
    for (const obj of listing.objects) {
      fileCount += 1;
      totalBytes += obj.size || 0;
      const head = await env.MEDIA_BUCKET.head(obj.key);
      if (!head) continue;
      const meta = await readMeta(env, obj.key);
      const expiresAt = meta?.expiresAt || head.customMetadata?.expiresAt || null;
      const expiresAtMs = expiresAt ? Date.parse(expiresAt) : NaN;
      if (Number.isFinite(expiresAtMs)) {
        if (expiresAtMs <= now) {
          expiredCount += 1;
        } else {
          if (expiresAtMs <= now + dayMs) expiring1d += 1;
          if (expiresAtMs <= now + dayMs * 3) expiring3d += 1;
          if (expiresAtMs <= now + dayMs * 7) expiring7d += 1;
          if (!nextExpiryAt || expiresAtMs < nextExpiryAt) nextExpiryAt = expiresAtMs;
        }
      }
      const uploadedAt = meta?.uploadedAt || head.customMetadata?.uploadedAt || null;
      const uploadedAtMs = uploadedAt ? Date.parse(uploadedAt) : NaN;
      if (Number.isFinite(uploadedAtMs)) {
        if (!latestUploadAt || uploadedAtMs > latestUploadAt) latestUploadAt = uploadedAtMs;
      }
    }
    cursor = listing.truncated ? listing.cursor : undefined;
  } while (cursor);

  return jsonResponse({
    usedBytes: usage.usedBytes,
    reservedBytes: usage.reservedBytes,
    totalBytes,
    maxFileBytes,
    maxTotalBytes,
    mediaTtlSeconds,
    fileCount,
    expiredCount,
    expiring1d,
    expiring3d,
    expiring7d,
    nextExpiryAt: nextExpiryAt ? new Date(nextExpiryAt).toISOString() : null,
    latestUploadAt: latestUploadAt ? new Date(latestUploadAt).toISOString() : null,
  });
}

async function handleUploadStart(request, env) {
  const body = await request.json();
  const filename = sanitizeFilename(String(body.filename || "file"));
  const size = Number(body.size || 0);
  const groupId = body.groupId ? sanitizeFilename(String(body.groupId)) : randomId();
  const contentType = String(body.contentType || "").trim() || guessContentType(filename);

  const maxFileBytes = getEnvNumber(env, "MAX_FILE_BYTES", 1073741824);
  const maxTotalBytes = getEnvNumber(env, "MAX_TOTAL_BYTES", 5368709120);
  const mediaTtlSeconds = getEnvNumber(env, "MEDIA_TTL_SECONDS", 86400);

  if (!Number.isFinite(size) || size <= 0) {
    return textResponse("Invalid size", { status: 400 });
  }
  if (size > maxFileBytes) {
    return textResponse("File too large", { status: 413 });
  }

  const uploadToken = randomId();
  const reserveRes = await usageRequest(env, "/reserve", {
    token: uploadToken,
    size,
    maxTotalBytes,
  });
  if (!reserveRes.ok) {
    if (reserveRes.status === 409) {
      return textResponse("Total storage limit reached", { status: 409 });
    }
    return textResponse("Usage unavailable", { status: 503 });
  }

  const key = `${groupId}/${filename}`;
  const expiresAt = new Date(Date.now() + mediaTtlSeconds * 1000).toISOString();
  const uploadedAt = new Date().toISOString();

  let upload;
  try {
    upload = await env.MEDIA_BUCKET.createMultipartUpload(key, {
      httpMetadata: { contentType },
      customMetadata: {
        expiresAt,
        uploadedAt,
        groupId,
        originalName: filename,
        size: String(size),
      },
    });
  } catch (error) {
    await usageRequest(env, "/release", { token: uploadToken });
    throw error;
  }

  const record = {
    key,
    uploadId: upload.uploadId,
    size,
    uploadedBytes: 0,
    partSize: PART_SIZE_BYTES,
    groupId,
    expiresAt,
    uploadedAt,
    originalName: filename,
  };
  await env.APP_KV.put(`upload:${uploadToken}`, JSON.stringify(record), { expirationTtl: 86400 });

  return jsonResponse({
    uploadToken,
    key,
    groupId,
    partSize: PART_SIZE_BYTES,
    expiresAt,
  });
}

async function handleUploadPart(request, env, url) {
  const uploadToken = url.searchParams.get("uploadToken");
  const partNumber = Number(url.searchParams.get("partNumber"));
  if (!uploadToken || !Number.isFinite(partNumber) || partNumber <= 0) {
    return textResponse("Missing uploadToken or partNumber", { status: 400 });
  }
  const recordRaw = await env.APP_KV.get(`upload:${uploadToken}`);
  if (!recordRaw) {
    return textResponse("Upload not found", { status: 404 });
  }
  const record = JSON.parse(recordRaw);
  const body = await request.arrayBuffer();
  if (!body.byteLength) {
    return textResponse("Empty body", { status: 400 });
  }

  const upload = await env.MEDIA_BUCKET.resumeMultipartUpload(record.key, record.uploadId);
  const part = await upload.uploadPart(partNumber, body);

  record.uploadedBytes += body.byteLength;
  if (record.uploadedBytes > record.size) {
    await upload.abort();
    await env.APP_KV.delete(`upload:${uploadToken}`);
    await usageRequest(env, "/release", { token: uploadToken });
    return textResponse("Upload exceeds declared size", { status: 400 });
  }

  record.parts = record.parts || [];
  record.parts.push({ partNumber, etag: part.etag });
  await env.APP_KV.put(`upload:${uploadToken}`, JSON.stringify(record), { expirationTtl: 86400 });

  return jsonResponse({ etag: part.etag });
}

async function handleUploadComplete(request, env) {
  const body = await request.json();
  const uploadToken = body.uploadToken;
  if (!uploadToken) return textResponse("Missing uploadToken", { status: 400 });
  const recordRaw = await env.APP_KV.get(`upload:${uploadToken}`);
  if (!recordRaw) return textResponse("Upload not found", { status: 404 });
  const record = JSON.parse(recordRaw);

  if (!record.parts || !record.parts.length) {
    return textResponse("No parts uploaded", { status: 400 });
  }
  const parts = record.parts.sort((a, b) => a.partNumber - b.partNumber);

  const upload = await env.MEDIA_BUCKET.resumeMultipartUpload(record.key, record.uploadId);
  await upload.complete(parts);
  await env.APP_KV.delete(`upload:${uploadToken}`);
  await usageRequest(env, "/commit", { token: uploadToken });

  const mediaTtlSeconds = getEnvNumber(env, "MEDIA_TTL_SECONDS", 86400);
  const expiresAtMs = record.expiresAt ? Date.parse(record.expiresAt) : null;
  const expiresAtSeconds = Number.isFinite(expiresAtMs)
    ? Math.floor(expiresAtMs / 1000)
    : Math.floor(Date.now() / 1000) + mediaTtlSeconds;
  const token = await createToken(env.TOKEN_SIGNING_SECRET, record.key, expiresAtSeconds);
  const baseUrl = buildBaseUrl(request);
  const urls = buildTokenUrls(request, record.key, token);
  const mediaUrl = urls.mediaUrl;
  const viewUrl = urls.viewUrl;
  const downloadUrl = urls.downloadUrl;

  const meta = {
    key: record.key,
    originalName: record.originalName,
    size: record.size,
    uploadedAt: record.uploadedAt,
    expiresAt: record.expiresAt,
    groupId: record.groupId,
    shortCode: null,
  };
  const shortCode = await ensureShortCode(env, record.key, meta);
  if (shortCode) {
    meta.shortCode = shortCode;
  } else {
    await saveMeta(env, record.key, meta);
  }
  const shareUrl = shortCode ? `${baseUrl}/s/${shortCode}` : null;
  const sharePageUrl = shortCode ? `${baseUrl}/share/${shortCode}` : null;

  return jsonResponse({
    key: record.key,
    groupId: record.groupId,
    mediaUrl,
    viewUrl,
    downloadUrl,
    shortUrl: shareUrl,
    sharePageUrl,
    shortCode,
    expiresAt: record.expiresAt,
  });
}

async function handleMedia(request, env, url) {
  const key = decodeURIComponent(url.pathname.replace("/media/", ""));
  const token = url.searchParams.get("token");
  if (!key || !token) return textResponse("Missing token", { status: 401 });
  const verified = await verifyToken(env.TOKEN_SIGNING_SECRET, token, key);
  if (!verified) return textResponse("Invalid token", { status: 403 });

  const rangeHeader = request.headers.get("Range");
  const head = await env.MEDIA_BUCKET.head(key);
  if (!head) return textResponse("Not found", { status: 404 });

  const meta = await getMetaForKey(env, key, head);
  const expiresAt = extractExpiresAt(meta, head);
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
    await deleteObjectAndMeta(env, key, head, meta);
    return textResponse("Expired", { status: 410 });
  }

  const contentType = head.httpMetadata?.contentType || "";
  const isPlaylist = key.toLowerCase().endsWith(".m3u8") || contentType.includes("mpegurl");
  if (isPlaylist) {
    const object = await env.MEDIA_BUCKET.get(key);
    if (!object) return textResponse("Not found", { status: 404 });
    const body = rewriteM3U8(await object.text(), token);
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("Content-Type", "application/vnd.apple.mpegurl");
    headers.set("Cache-Control", "public, max-age=3600");
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Allow-Headers", "Range,Content-Type");
    return new Response(body, { status: 200, headers });
  }

  let range = null;
  if (rangeHeader) {
    range = parseRangeHeader(rangeHeader, head.size);
    if (!range) {
      return new Response(null, {
        status: 416,
        headers: { "Content-Range": `bytes */${head.size}` },
      });
    }
  }

  const object = await env.MEDIA_BUCKET.get(key, range ? { range: { offset: range.start, length: range.end - range.start + 1 } } : {});
  if (!object) return textResponse("Not found", { status: 404 });

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Cache-Control", "public, max-age=3600");
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Headers", "Range,Content-Type");
  if (url.searchParams.get("download") === "1") {
    const filename = meta?.originalName || key.split("/").pop() || "file";
    headers.set("Content-Disposition", `attachment; filename="${sanitizeHeaderValue(filename)}"`);
  }

  if (range) {
    headers.set("Content-Range", `bytes ${range.start}-${range.end}/${head.size}`);
    headers.set("Content-Length", String(range.end - range.start + 1));
    return new Response(object.body, { status: 206, headers });
  }

  return new Response(object.body, { status: 200, headers });
}

async function handleView(request, env, url) {
  const key = decodeURIComponent(url.pathname.replace("/view/", ""));
  const token = url.searchParams.get("token");
  if (!key || !token) return textResponse("Missing token", { status: 401 });

  const verified = await verifyToken(env.TOKEN_SIGNING_SECRET, token, key);
  if (!verified) return textResponse("Invalid token", { status: 403 });

  const head = await env.MEDIA_BUCKET.head(key);
  if (!head) return textResponse("Not found", { status: 404 });

  const meta = await getMetaForKey(env, key, head);
  const expiresAt = extractExpiresAt(meta, head);
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
    await deleteObjectAndMeta(env, key, head, meta);
    return textResponse("Expired", { status: 410 });
  }

  const mediaUrl = `/media/${encodeURIComponent(key)}?token=${encodeURIComponent(token)}`;
  const contentType = head.httpMetadata?.contentType || "application/octet-stream";
  const isPlaylist = key.toLowerCase().endsWith(".m3u8") || contentType.includes("mpegurl");
  const name = meta?.originalName || key.split("/").pop();
  return htmlResponse(viewPage({ mediaUrl, name, contentType, isPlaylist }));
}

async function handleSharePage(request, env, url) {
  const code = decodeURIComponent(url.pathname.replace("/share/", ""));
  if (!code) return textResponse("Not found", { status: 404 });
  const key = await resolveShortCode(env, code);
  if (!key) return textResponse("Not found", { status: 404 });

  const head = await env.MEDIA_BUCKET.head(key);
  if (!head) return textResponse("Not found", { status: 404 });
  const meta = await getMetaForKey(env, key, head);
  const expiresAt = extractExpiresAt(meta, head);
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
    await deleteObjectAndMeta(env, key, head, meta);
    return textResponse("Expired", { status: 410 });
  }

  const expiresAtMs = expiresAt ? Date.parse(expiresAt) : null;
  const expiresAtSeconds = Number.isFinite(expiresAtMs)
    ? Math.floor(expiresAtMs / 1000)
    : Math.floor(Date.now() / 1000) + getEnvNumber(env, "MEDIA_TTL_SECONDS", 86400);
  const token = await createToken(env.TOKEN_SIGNING_SECRET, key, expiresAtSeconds);
  const urls = buildTokenUrls(request, key, token);
  const baseUrl = buildBaseUrl(request);

  return htmlResponse(
    sharePage({
      name: meta?.originalName || key.split("/").pop(),
      size: meta?.size || head.size,
      uploadedAt: meta?.uploadedAt || head.customMetadata?.uploadedAt,
      expiresAt,
      remaining: formatRemainingSeconds(
        Number.isFinite(expiresAtMs) ? Math.floor((expiresAtMs - Date.now()) / 1000) : null
      ),
      shareUrl: `${baseUrl}/s/${code}`,
      viewUrl: urls.viewUrl,
      downloadUrl: urls.downloadUrl,
    })
  );
}

async function handleShortPreview(request, env, url) {
  const code = decodeURIComponent(url.pathname.replace("/s/", ""));
  if (!code) return textResponse("Not found", { status: 404 });
  const key = await resolveShortCode(env, code);
  if (!key) return textResponse("Not found", { status: 404 });
  const head = await env.MEDIA_BUCKET.head(key);
  if (!head) return textResponse("Not found", { status: 404 });
  const meta = await getMetaForKey(env, key, head);
  const expiresAt = extractExpiresAt(meta, head);
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
    await deleteObjectAndMeta(env, key, head, meta);
    return textResponse("Expired", { status: 410 });
  }
  const expiresAtMs = expiresAt ? Date.parse(expiresAt) : null;
  const expiresAtSeconds = Number.isFinite(expiresAtMs)
    ? Math.floor(expiresAtMs / 1000)
    : Math.floor(Date.now() / 1000) + getEnvNumber(env, "MEDIA_TTL_SECONDS", 86400);
  const token = await createToken(env.TOKEN_SIGNING_SECRET, key, expiresAtSeconds);
  const urls = buildTokenUrls(request, key, token);
  return Response.redirect(urls.viewUrl, 302);
}

async function handleFilesList(request, env, url) {
  const limit = Math.min(Number(url.searchParams.get("limit") || 50), 200);
  const cursor = url.searchParams.get("cursor") || undefined;
  const listing = await env.MEDIA_BUCKET.list({ cursor, limit });
  const items = [];
  const baseUrl = buildBaseUrl(request);
  const now = Date.now();
  for (const obj of listing.objects) {
    const head = await env.MEDIA_BUCKET.head(obj.key);
    if (!head) continue;
    const meta = await getMetaForKey(env, obj.key, head);
    const expiresAt = extractExpiresAt(meta, head);
    const expiresAtMs = expiresAt ? Date.parse(expiresAt) : null;
    const expired = Number.isFinite(expiresAtMs) && expiresAtMs <= now;
    let viewUrl = null;
    let directUrl = null;
    let downloadUrl = null;
    if (!expired) {
      const expiresAtSeconds = Number.isFinite(expiresAtMs)
        ? Math.floor(expiresAtMs / 1000)
        : Math.floor(Date.now() / 1000) + getEnvNumber(env, "MEDIA_TTL_SECONDS", 86400);
      const token = await createToken(env.TOKEN_SIGNING_SECRET, obj.key, expiresAtSeconds);
      const urls = buildTokenUrls(request, obj.key, token);
      viewUrl = urls.viewUrl;
      directUrl = urls.mediaUrl;
      downloadUrl = urls.downloadUrl;
    }
    const shortCode = meta?.shortCode || null;
    items.push({
      key: obj.key,
      filename: meta?.originalName || obj.key.split("/").pop(),
      size: meta?.size || head.size,
      uploadedAt: meta?.uploadedAt || head.customMetadata?.uploadedAt,
      expiresAt,
      remainingSeconds: Number.isFinite(expiresAtMs) ? Math.floor((expiresAtMs - now) / 1000) : null,
      viewUrl,
      directUrl,
      downloadUrl,
      shortCode,
      shortUrl: shortCode ? `${baseUrl}/s/${shortCode}` : null,
      sharePageUrl: shortCode ? `${baseUrl}/share/${shortCode}` : null,
      expired,
    });
  }
  return jsonResponse({
    items,
    cursor: listing.truncated ? listing.cursor : null,
    hasMore: listing.truncated,
  });
}

async function handleFilesDelete(request, env) {
  const body = await request.json();
  const key = body.key;
  if (!key) return textResponse("Missing key", { status: 400 });
  const head = await env.MEDIA_BUCKET.head(key);
  const meta = await readMeta(env, key);
  if (!head) {
    await deleteShortCode(env, meta);
    await deleteMeta(env, key);
    return textResponse("Not found", { status: 404 });
  }
  await deleteObjectAndMeta(env, key, head, meta);
  return jsonResponse({ ok: true });
}

async function handleFilesExtend(request, env) {
  const body = await request.json();
  const key = body.key;
  const days = Number(body.days);
  if (!key) return textResponse("Missing key", { status: 400 });
  if (![1, 3, 5].includes(days)) return textResponse("Invalid days", { status: 400 });
  const head = await env.MEDIA_BUCKET.head(key);
  if (!head) return textResponse("Not found", { status: 404 });
  const meta = (await getMetaForKey(env, key, head)) || buildMetaFromHead(key, head);
  const currentExpiresAt = extractExpiresAt(meta, head);
  const baseMs = Math.max(Date.now(), currentExpiresAt ? Date.parse(currentExpiresAt) : Date.now());
  const newExpiresAt = new Date(baseMs + days * 86400 * 1000).toISOString();
  const nextMeta = {
    ...meta,
    key,
    originalName: meta.originalName || key.split("/").pop(),
    size: meta.size || head.size,
    uploadedAt: meta.uploadedAt || head.customMetadata?.uploadedAt,
    expiresAt: newExpiresAt,
  };
  await saveMeta(env, key, nextMeta);
  return jsonResponse({ expiresAt: newExpiresAt });
}

async function handleFilesShorten(request, env) {
  const body = await request.json();
  const key = body.key;
  if (!key) return textResponse("Missing key", { status: 400 });
  const head = await env.MEDIA_BUCKET.head(key);
  if (!head) return textResponse("Not found", { status: 404 });
  const meta = (await getMetaForKey(env, key, head)) || buildMetaFromHead(key, head);
  const shortCode = await ensureShortCode(env, key, meta);
  if (!shortCode) return textResponse("Short link unavailable", { status: 500 });
  const baseUrl = buildBaseUrl(request);
  return jsonResponse({ shortCode, shareUrl: `${baseUrl}/s/${shortCode}` });
}

async function handleCleanup(env) {
  let cursor;
  let total = 0;
  do {
    const listing = await env.MEDIA_BUCKET.list({ cursor });
    for (const obj of listing.objects) {
      const head = await env.MEDIA_BUCKET.head(obj.key);
      if (!head) continue;
      const meta = await getMetaForKey(env, obj.key, head);
      const expiresAt = extractExpiresAt(meta, head);
      if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
        await deleteObjectAndMeta(env, obj.key, head, meta);
        continue;
      }
      total += head.size;
    }
    cursor = listing.truncated ? listing.cursor : undefined;
  } while (cursor);
  await usageRequest(env, "/sync-used", { usedBytes: total });

  const reserved = {};
  let kvCursor;
  do {
    const list = await env.APP_KV.list({ prefix: "upload:", cursor: kvCursor });
    for (const key of list.keys) {
      const recordRaw = await env.APP_KV.get(key.name);
      if (!recordRaw) continue;
      const record = JSON.parse(recordRaw);
      const token = key.name.replace("upload:", "");
      const size = Number(record.size);
      if (Number.isFinite(size) && size > 0) {
        reserved[token] = size;
      }
    }
    kvCursor = list.list_complete ? undefined : list.cursor;
  } while (kvCursor);
  await usageRequest(env, "/sync-reserved", { reserved });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS" && url.pathname.startsWith("/media/")) {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (url.pathname === "/login" && request.method === "GET") {
      return htmlResponse(loginPage());
    }
    if (url.pathname === "/login" && request.method === "POST") {
      return handleLogin(request, env);
    }

    if (url.pathname === "/logout" && request.method === "POST") {
      return handleLogout(request, env);
    }

    if (url.pathname === "/") {
      return htmlResponse(publicHomePage());
    }

    if (url.pathname === "/admin") {
      const session = await requireAdmin(request, env);
      if (!session) return Response.redirect(new URL("/login", request.url).toString(), 302);
      return htmlResponse(adminPage());
    }

    if (url.pathname === "/admin/stats") {
      const session = await requireAdmin(request, env);
      if (!session) return Response.redirect(new URL("/login", request.url).toString(), 302);
      return htmlResponse(statsPage());
    }

    if (url.pathname === "/api/status") {
      const session = await requireAdmin(request, env);
      if (!session) return textResponse("Unauthorized", { status: 401 });
      return handleStatus(env);
    }

    if (url.pathname === "/api/stats") {
      const session = await requireAdmin(request, env);
      if (!session) return textResponse("Unauthorized", { status: 401 });
      return handleStats(env);
    }

    if (url.pathname === "/api/uploads/start") {
      const session = await requireAdmin(request, env);
      if (!session) return textResponse("Unauthorized", { status: 401 });
      return handleUploadStart(request, env);
    }

    if (url.pathname === "/api/uploads/part") {
      const session = await requireAdmin(request, env);
      if (!session) return textResponse("Unauthorized", { status: 401 });
      return handleUploadPart(request, env, url);
    }

    if (url.pathname === "/api/uploads/complete") {
      const session = await requireAdmin(request, env);
      if (!session) return textResponse("Unauthorized", { status: 401 });
      return handleUploadComplete(request, env);
    }

    if (url.pathname === "/api/files" && request.method === "GET") {
      const session = await requireAdmin(request, env);
      if (!session) return textResponse("Unauthorized", { status: 401 });
      return handleFilesList(request, env, url);
    }

    if (url.pathname === "/api/files/delete" && request.method === "POST") {
      const session = await requireAdmin(request, env);
      if (!session) return textResponse("Unauthorized", { status: 401 });
      return handleFilesDelete(request, env);
    }

    if (url.pathname === "/api/files/extend" && request.method === "POST") {
      const session = await requireAdmin(request, env);
      if (!session) return textResponse("Unauthorized", { status: 401 });
      return handleFilesExtend(request, env);
    }

    if (url.pathname === "/api/files/shorten" && request.method === "POST") {
      const session = await requireAdmin(request, env);
      if (!session) return textResponse("Unauthorized", { status: 401 });
      return handleFilesShorten(request, env);
    }

    if (url.pathname.startsWith("/share/")) {
      return handleSharePage(request, env, url);
    }

    if (url.pathname.startsWith("/s/")) {
      return handleShortPreview(request, env, url);
    }

    if (url.pathname.startsWith("/media/")) {
      return handleMedia(request, env, url);
    }

    if (url.pathname.startsWith("/view/")) {
      return handleView(request, env, url);
    }

    return textResponse("Not found", { status: 404 });
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleCleanup(env));
  },
};

export { Usage } from "./usage";
