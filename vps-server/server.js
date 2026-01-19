import http from "http";
import fs from "fs/promises";
import { createReadStream } from "fs";
import path from "path";
import crypto from "crypto";

const PORT = Number(process.env.PORT || 8787);
const STORAGE_DIR = process.env.STORAGE_DIR || "/var/tmp-media/storage";
const UPLOAD_DIR = process.env.UPLOAD_DIR || "/var/tmp-media/uploads";
const AUTH_TOKEN = process.env.VPS_AUTH_TOKEN || "";
const PART_SIZE_BYTES = Number(process.env.PART_SIZE_BYTES || 8 * 1024 * 1024);
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES || 1073741824);

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}

function sendText(res, status, text) {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(text);
}

function requireAuth(req, res) {
  if (!AUTH_TOKEN) {
    sendText(res, 500, "Missing VPS_AUTH_TOKEN");
    return false;
  }
  const auth = req.headers.authorization || "";
  if (auth !== `Bearer ${AUTH_TOKEN}`) {
    sendText(res, 401, "Unauthorized");
    return false;
  }
  return true;
}

function normalizeKey(input) {
  if (!input) return null;
  const raw = input.replace(/\\/g, "/").replace(/^\/+/, "");
  if (!raw || raw.includes("\0")) return null;
  const normalized = path.posix.normalize(raw);
  if (normalized === "." || normalized === "..") return null;
  const segments = normalized.split("/");
  if (segments.some((seg) => seg === "..")) return null;
  return normalized;
}

function resolveStoragePath(key) {
  const normalized = normalizeKey(key);
  if (!normalized) return null;
  const root = path.resolve(STORAGE_DIR);
  const filePath = path.resolve(root, normalized);
  if (!filePath.startsWith(root + path.sep)) return null;
  return { filePath, metaPath: `${filePath}.meta.json`, key: normalized };
}

function uploadPaths(uploadId) {
  return {
    recordPath: path.join(UPLOAD_DIR, `${uploadId}.json`),
    tempPath: path.join(UPLOAD_DIR, `${uploadId}.bin`),
  };
}

function guessContentType(name) {
  const lower = name.toLowerCase();
  if (lower.endsWith(".m3u8")) return "application/vnd.apple.mpegurl";
  if (lower.endsWith(".ts")) return "video/mp2t";
  if (lower.endsWith(".mp4")) return "video/mp4";
  if (lower.endsWith(".webm")) return "video/webm";
  if (lower.endsWith(".png")) return "image/png";
  if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
  if (lower.endsWith(".gif")) return "image/gif";
  if (lower.endsWith(".webp")) return "image/webp";
  if (lower.endsWith(".pdf")) return "application/pdf";
  if (lower.endsWith(".txt")) return "text/plain; charset=utf-8";
  return "application/octet-stream";
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

async function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function readJson(req) {
  const body = await readBody(req);
  if (!body.length) return null;
  try {
    return JSON.parse(body.toString("utf-8"));
  } catch (error) {
    return null;
  }
}

async function loadUploadRecord(uploadId) {
  const { recordPath } = uploadPaths(uploadId);
  const raw = await fs.readFile(recordPath, "utf-8").catch(() => null);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (error) {
    return null;
  }
}

async function saveUploadRecord(uploadId, record) {
  const { recordPath } = uploadPaths(uploadId);
  await fs.mkdir(path.dirname(recordPath), { recursive: true });
  await fs.writeFile(recordPath, JSON.stringify(record));
}

async function removeUploadRecord(uploadId) {
  const { recordPath, tempPath } = uploadPaths(uploadId);
  await fs.unlink(recordPath).catch(() => {});
  await fs.unlink(tempPath).catch(() => {});
}

async function ensureDirs() {
  await fs.mkdir(STORAGE_DIR, { recursive: true });
  await fs.mkdir(UPLOAD_DIR, { recursive: true });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

    if (url.pathname === "/health") {
      return sendJson(res, 200, { ok: true });
    }

    if (!requireAuth(req, res)) return;

    if (url.pathname === "/uploads/start" && req.method === "POST") {
      const body = await readJson(req);
      const key = normalizeKey(String(body?.key || ""));
      const size = Number(body?.size || 0);
      const contentType = String(body?.contentType || "").trim();
      const partSize = Number(body?.partSize || PART_SIZE_BYTES);
      const originalName = String(body?.originalName || "");
      if (!key || !Number.isFinite(size) || size <= 0) {
        return sendText(res, 400, "Invalid request");
      }
      if (size > MAX_FILE_BYTES) {
        return sendText(res, 413, "File too large");
      }
      const uploadId = crypto.randomUUID();
      const record = {
        uploadId,
        key,
        size,
        contentType,
        partSize,
        originalName,
        createdAt: new Date().toISOString(),
      };
      await saveUploadRecord(uploadId, record);
      return sendJson(res, 200, { uploadId, partSize });
    }

    if (url.pathname === "/uploads/part" && req.method === "POST") {
      const uploadId = url.searchParams.get("uploadId") || "";
      const partNumber = Number(url.searchParams.get("partNumber"));
      if (!uploadId || !Number.isFinite(partNumber) || partNumber <= 0) {
        return sendText(res, 400, "Invalid request");
      }
      const record = await loadUploadRecord(uploadId);
      if (!record) return sendText(res, 404, "Upload not found");
      const body = await readBody(req);
      if (!body.length) return sendText(res, 400, "Empty body");
      const offset = (partNumber - 1) * Number(record.partSize || PART_SIZE_BYTES);
      if (offset + body.length > record.size) {
        return sendText(res, 400, "Upload exceeds declared size");
      }
      const { tempPath } = uploadPaths(uploadId);
      await fs.mkdir(path.dirname(tempPath), { recursive: true });
      const exists = await fs.stat(tempPath).catch(() => null);
      const handle = await fs.open(tempPath, exists ? "r+" : "w+");
      await handle.write(body, 0, body.length, offset);
      await handle.close();
      return sendJson(res, 200, { ok: true });
    }

    if (url.pathname === "/uploads/complete" && req.method === "POST") {
      const body = await readJson(req);
      const uploadId = String(body?.uploadId || "");
      if (!uploadId) return sendText(res, 400, "Invalid request");
      const record = await loadUploadRecord(uploadId);
      if (!record) return sendText(res, 404, "Upload not found");
      const { tempPath } = uploadPaths(uploadId);
      const tempStat = await fs.stat(tempPath).catch(() => null);
      if (!tempStat) return sendText(res, 404, "Upload not found");
      if (tempStat.size !== record.size) {
        return sendText(res, 400, "Size mismatch");
      }
      const storage = resolveStoragePath(record.key);
      if (!storage) return sendText(res, 400, "Invalid key");
      await fs.mkdir(path.dirname(storage.filePath), { recursive: true });
      try {
        await fs.rename(tempPath, storage.filePath);
      } catch (error) {
        if (error && error.code === "EXDEV") {
          await fs.copyFile(tempPath, storage.filePath);
          await fs.unlink(tempPath);
        } else {
          throw error;
        }
      }
      const meta = {
        contentType: record.contentType || guessContentType(record.key),
        size: record.size,
        originalName: record.originalName || null,
        uploadedAt: new Date().toISOString(),
      };
      await fs.writeFile(storage.metaPath, JSON.stringify(meta));
      await removeUploadRecord(uploadId);
      return sendJson(res, 200, { ok: true });
    }

    if (url.pathname.startsWith("/files/")) {
      const rawKey = url.pathname.replace("/files/", "");
      let decodedKey = null;
      try {
        decodedKey = decodeURIComponent(rawKey);
      } catch (error) {
        return sendText(res, 400, "Invalid key");
      }
      const storage = resolveStoragePath(decodedKey);
      if (!storage) return sendText(res, 400, "Invalid key");
      const stat = await fs.stat(storage.filePath).catch(() => null);
      if (!stat || !stat.isFile()) return sendText(res, 404, "Not found");
      const size = stat.size;
      const metaRaw = await fs.readFile(storage.metaPath, "utf-8").catch(() => null);
      let meta = null;
      if (metaRaw) {
        try {
          meta = JSON.parse(metaRaw);
        } catch (error) {
          meta = null;
        }
      }
      const contentType = meta?.contentType || guessContentType(storage.filePath);
      if (req.method === "DELETE") {
        await fs.unlink(storage.filePath).catch(() => {});
        await fs.unlink(storage.metaPath).catch(() => {});
        return sendJson(res, 200, { ok: true });
      }
      const rangeHeader = req.headers.range;
      const range = rangeHeader ? parseRangeHeader(rangeHeader, size) : null;
      if (rangeHeader && !range) {
        res.writeHead(416, { "Content-Range": `bytes */${size}` });
        return res.end();
      }
      const headers = {
        "Content-Type": contentType,
        "Accept-Ranges": "bytes",
        "Cache-Control": "public, max-age=3600",
      };
      if (range) {
        headers["Content-Range"] = `bytes ${range.start}-${range.end}/${size}`;
        headers["Content-Length"] = String(range.end - range.start + 1);
      } else {
        headers["Content-Length"] = String(size);
      }
      if (req.method === "HEAD") {
        res.writeHead(range ? 206 : 200, headers);
        return res.end();
      }
      res.writeHead(range ? 206 : 200, headers);
      const stream = createReadStream(storage.filePath, range ? { start: range.start, end: range.end } : undefined);
      return stream.pipe(res);
    }

    return sendText(res, 404, "Not found");
  } catch (error) {
    console.error(error);
    return sendText(res, 500, "Server error");
  }
});

await ensureDirs();
server.listen(PORT, () => {
  console.log(`VPS storage server listening on :${PORT}`);
});
