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
  <title>Admin Login</title>
  <style>
    body { font-family: sans-serif; margin: 40px; }
    .box { max-width: 360px; margin: 0 auto; }
    label { display: block; margin-top: 12px; }
    input { width: 100%; padding: 8px; }
    button { margin-top: 16px; padding: 8px 12px; }
    .error { color: #b00020; margin-top: 12px; }
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
  <title>Temp Media</title>
  <style>
    body { font-family: sans-serif; margin: 32px; }
    a { color: #0057ff; text-decoration: none; }
  </style>
</head>
<body>
  <h1>临时文件服务</h1>
  <p><a href="/login">管理员登录</a></p>
</body>
</html>`;
}

function adminPage() {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Temp Media Admin</title>
  <style>
    body { font-family: sans-serif; margin: 32px; }
    input, button { padding: 8px; }
    .row { margin-top: 12px; }
    .log { white-space: pre-wrap; background: #f4f4f4; padding: 12px; margin-top: 12px; }
    .links a { display: block; margin-top: 6px; }
    .files-table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    .files-table th, .files-table td { border-bottom: 1px solid #eee; padding: 8px; text-align: left; font-size: 14px; }
    .files-actions button { margin-right: 6px; margin-top: 4px; }
    .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; background: #eee; font-size: 12px; }
  </style>
</head>
<body>
  <h1>Temp Media Admin</h1>
  <form id="logout" method="post" action="/logout">
    <button type="submit">Logout</button>
  </form>
  <div class="row" id="status">Loading status...</div>

  <h2>Upload</h2>
  <div class="row">
    <label>Group ID (optional, same value for HLS folders)</label><br />
    <input id="groupId" placeholder="auto-generate if empty" />
  </div>
  <div class="row">
    <input id="files" type="file" multiple />
  </div>
  <div class="row">
    <button id="upload">Upload</button>
  </div>

  <div class="log" id="log"></div>
  <div class="links" id="links"></div>

  <h2>已上传文件</h2>
  <div class="row">
    <button id="refreshFiles">刷新列表</button>
  </div>
  <div class="row">
    <table class="files-table">
      <thead>
        <tr>
          <th>文件名</th>
          <th>大小</th>
          <th>到期</th>
          <th>剩余</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody id="filesBody"></tbody>
    </table>
  </div>
  <div class="row">
    <button id="loadMoreFiles">加载更多</button>
  </div>

  <script>
    const statusEl = document.getElementById('status');
    const logEl = document.getElementById('log');
    const linksEl = document.getElementById('links');
    const groupInput = document.getElementById('groupId');
    const filesBody = document.getElementById('filesBody');
    const refreshFilesBtn = document.getElementById('refreshFiles');
    const loadMoreFilesBtn = document.getElementById('loadMoreFiles');
    let filesCursor = null;
    let filesLoading = false;

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
    }

    function renderFileRow(item) {
      const tr = document.createElement('tr');
      const nameTd = document.createElement('td');
      nameTd.textContent = item.filename;
      const sizeTd = document.createElement('td');
      sizeTd.textContent = formatBytes(item.size);
      const expTd = document.createElement('td');
      expTd.textContent = item.expiresAt ? new Date(item.expiresAt).toLocaleString('zh-CN') : '-';
      const remainingTd = document.createElement('td');
      remainingTd.textContent = formatRemaining(item.remainingSeconds);
      const actionsTd = document.createElement('td');
      actionsTd.className = 'files-actions';

      const viewBtn = document.createElement('button');
      viewBtn.textContent = '预览';
      viewBtn.dataset.action = 'view';
      viewBtn.dataset.url = item.viewUrl || '';

      const downloadBtn = document.createElement('button');
      downloadBtn.textContent = '下载';
      downloadBtn.dataset.action = 'download';
      downloadBtn.dataset.url = item.downloadUrl || '';

      const copyShareBtn = document.createElement('button');
      copyShareBtn.textContent = item.shortUrl ? '复制短链' : '生成短链';
      copyShareBtn.dataset.action = item.shortUrl ? 'copyShare' : 'shorten';
      copyShareBtn.dataset.key = encodeURIComponent(item.key);
      copyShareBtn.dataset.url = item.shortUrl || '';

      const sharePageBtn = document.createElement('button');
      sharePageBtn.textContent = '分享页';
      sharePageBtn.dataset.action = 'sharePage';
      sharePageBtn.dataset.url = item.sharePageUrl || '';

      const copyDirectBtn = document.createElement('button');
      copyDirectBtn.textContent = '复制直链';
      copyDirectBtn.dataset.action = 'copyDirect';
      copyDirectBtn.dataset.url = item.directUrl || '';

      const extend1 = document.createElement('button');
      extend1.textContent = '+1天';
      extend1.dataset.action = 'extend';
      extend1.dataset.key = encodeURIComponent(item.key);
      extend1.dataset.days = '1';

      const extend3 = document.createElement('button');
      extend3.textContent = '+3天';
      extend3.dataset.action = 'extend';
      extend3.dataset.key = encodeURIComponent(item.key);
      extend3.dataset.days = '3';

      const extend5 = document.createElement('button');
      extend5.textContent = '+5天';
      extend5.dataset.action = 'extend';
      extend5.dataset.key = encodeURIComponent(item.key);
      extend5.dataset.days = '5';

      const deleteBtn = document.createElement('button');
      deleteBtn.textContent = '删除';
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
      data.items.forEach(renderFileRow);
      filesCursor = data.cursor || null;
      loadMoreFilesBtn.disabled = !data.hasMore;
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

    async function refreshStatus() {
      const res = await fetch('/api/status');
      if (!res.ok) {
        statusEl.textContent = 'Failed to load status';
        return;
      }
      const data = await res.json();
      const used = data.totalBytes;
      const reserved = data.reservedBytes || 0;
      const total = used + reserved;
      statusEl.textContent = 'Usage: ' + total + ' (used ' + used + ', reserved ' + reserved + ') / ' + data.maxTotalBytes + ' bytes | Max file: ' + data.maxFileBytes + ' bytes | TTL: ' + data.mediaTtlSeconds + 's';
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
        log('Uploaded part ' + partNumber + '/' + totalParts + ' for ' + file.name);
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
        log('No files selected.');
        return;
      }
      let groupId = groupInput.value.trim();
      for (const file of files) {
        log('Starting upload for ' + file.name);
        const result = await uploadFile(file, groupId || undefined);
        if (!groupId) {
          groupId = result.groupId;
          groupInput.value = groupId;
        }
        log('Completed ' + file.name);
        const link = document.createElement('a');
        link.href = result.viewUrl;
        link.textContent = file.name + ' -> view';
        link.target = '_blank';
        linksEl.appendChild(link);
        const raw = document.createElement('a');
        raw.href = result.downloadUrl || result.mediaUrl;
        raw.textContent = file.name + ' -> direct';
        raw.target = '_blank';
        linksEl.appendChild(raw);
        if (result.shortUrl) {
          const share = document.createElement('a');
          share.href = result.shortUrl;
          share.textContent = file.name + ' -> short';
          share.target = '_blank';
          linksEl.appendChild(share);
        }
        if (result.sharePageUrl) {
          const sharePage = document.createElement('a');
          sharePage.href = result.sharePageUrl;
          sharePage.textContent = file.name + ' -> share';
          sharePage.target = '_blank';
          linksEl.appendChild(sharePage);
        }
      }
      await refreshStatus();
      await loadFiles(true);
    });

    refreshStatus();
    loadFiles(true);
    refreshFilesBtn.addEventListener('click', () => loadFiles(true));
    loadMoreFilesBtn.addEventListener('click', () => loadFiles(false));
  </script>
</body>
</html>`;
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
  <title>${name}</title>
  <style>
    body { font-family: sans-serif; margin: 32px; }
    video, img { max-width: 100%; height: auto; }
    #notice { margin-top: 12px; color: #b00020; }
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
  <title>${safeName}</title>
  <style>
    body { font-family: sans-serif; margin: 32px; }
    .meta { color: #555; margin-top: 6px; }
    .actions { margin: 16px 0; display: flex; gap: 12px; flex-wrap: wrap; }
    .btn { background: #0057ff; color: #fff; padding: 8px 14px; border-radius: 6px; text-decoration: none; }
    .link-group { margin-top: 16px; }
    input { width: 100%; padding: 8px; }
    button { margin-left: 8px; padding: 8px 12px; }
    .row { display: flex; align-items: center; gap: 8px; }
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

    if (url.pathname === "/api/status") {
      const session = await requireAdmin(request, env);
      if (!session) return textResponse("Unauthorized", { status: 401 });
      return handleStatus(env);
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
