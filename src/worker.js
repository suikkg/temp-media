const COOKIE_NAME = "kkinto_session";
const PART_SIZE_BYTES = 8 * 1024 * 1024;

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

  <script>
    const statusEl = document.getElementById('status');
    const logEl = document.getElementById('log');
    const linksEl = document.getElementById('links');
    const groupInput = document.getElementById('groupId');

    function log(message) {
      logEl.textContent += message + "\n";
    }

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
        raw.href = result.mediaUrl;
        raw.textContent = file.name + ' -> direct';
        raw.target = '_blank';
        linksEl.appendChild(raw);
      }
      await refreshStatus();
    });

    refreshStatus();
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
  const expiresAtSeconds = Math.floor(Date.now() / 1000) + mediaTtlSeconds;
  const token = await createToken(env.TOKEN_SIGNING_SECRET, record.key, expiresAtSeconds);
  const baseUrl = new URL("/", request.url).toString().replace(/\/$/, "");
  const mediaUrl = `${baseUrl}/media/${encodeURIComponent(record.key)}?token=${encodeURIComponent(token)}`;
  const viewUrl = `${baseUrl}/view/${encodeURIComponent(record.key)}?token=${encodeURIComponent(token)}`;

  return jsonResponse({
    key: record.key,
    groupId: record.groupId,
    mediaUrl,
    viewUrl,
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

  const expiresAt = head.customMetadata?.expiresAt;
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
    await env.MEDIA_BUCKET.delete(key);
    await usageRequest(env, "/adjust", { delta: -head.size });
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

  const expiresAt = head.customMetadata?.expiresAt;
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
    await env.MEDIA_BUCKET.delete(key);
    await usageRequest(env, "/adjust", { delta: -head.size });
    return textResponse("Expired", { status: 410 });
  }

  const mediaUrl = `/media/${encodeURIComponent(key)}?token=${encodeURIComponent(token)}`;
  const contentType = head.httpMetadata?.contentType || "application/octet-stream";
  const isPlaylist = key.toLowerCase().endsWith(".m3u8") || contentType.includes("mpegurl");
  const name = key.split("/").pop();
  return htmlResponse(viewPage({ mediaUrl, name, contentType, isPlaylist }));
}

async function handleCleanup(env) {
  let cursor;
  let total = 0;
  do {
    const listing = await env.MEDIA_BUCKET.list({ cursor });
    for (const obj of listing.objects) {
      const head = await env.MEDIA_BUCKET.head(obj.key);
      if (!head) continue;
      const expiresAt = head.customMetadata?.expiresAt;
      if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
        await env.MEDIA_BUCKET.delete(obj.key);
        continue;
      }
      total += obj.size;
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
