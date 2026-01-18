function jsonResponse(data, init = {}) {
  const headers = new Headers(init.headers || {});
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(data), { ...init, headers });
}

function normalizeUsage(usage) {
  if (!usage) {
    return { usedBytes: 0, reservedBytes: 0, reserved: {} };
  }
  if (!usage.reserved || typeof usage.reserved !== "object") {
    usage.reserved = {};
  }
  if (!Number.isFinite(usage.usedBytes)) {
    usage.usedBytes = 0;
  }
  if (!Number.isFinite(usage.reservedBytes)) {
    usage.reservedBytes = 0;
  }
  return usage;
}

export class Usage {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async load() {
    const usage = await this.state.storage.get("usage");
    return normalizeUsage(usage);
  }

  async save(usage) {
    await this.state.storage.put("usage", usage);
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/status" && request.method === "GET") {
      const usage = await this.load();
      return jsonResponse({
        usedBytes: usage.usedBytes,
        reservedBytes: usage.reservedBytes,
        totalBytes: usage.usedBytes + usage.reservedBytes,
      });
    }

    if (request.method !== "POST") {
      return new Response("Not found", { status: 404 });
    }

    const body = await request.json();
    const usage = await this.load();

    if (url.pathname === "/reserve") {
      const token = String(body.token || "");
      const size = Number(body.size);
      const maxTotalBytes = Number(body.maxTotalBytes);
      if (!token || !Number.isFinite(size) || size <= 0 || !Number.isFinite(maxTotalBytes)) {
        return new Response("Invalid request", { status: 400 });
      }
      if (usage.reserved[token]) {
        return jsonResponse({ ok: true });
      }
      const projected = usage.usedBytes + usage.reservedBytes + size;
      if (projected > maxTotalBytes) {
        return new Response("Limit reached", { status: 409 });
      }
      usage.reserved[token] = size;
      usage.reservedBytes += size;
      await this.save(usage);
      return jsonResponse({ ok: true });
    }

    if (url.pathname === "/commit") {
      const token = String(body.token || "");
      const size = usage.reserved[token];
      if (size) {
        usage.usedBytes += size;
        usage.reservedBytes = Math.max(usage.reservedBytes - size, 0);
        delete usage.reserved[token];
        await this.save(usage);
      }
      return jsonResponse({ ok: true });
    }

    if (url.pathname === "/release") {
      const token = String(body.token || "");
      const size = usage.reserved[token];
      if (size) {
        usage.reservedBytes = Math.max(usage.reservedBytes - size, 0);
        delete usage.reserved[token];
        await this.save(usage);
      }
      return jsonResponse({ ok: true });
    }

    if (url.pathname === "/adjust") {
      const delta = Number(body.delta);
      if (!Number.isFinite(delta)) {
        return new Response("Invalid request", { status: 400 });
      }
      usage.usedBytes = Math.max(usage.usedBytes + delta, 0);
      await this.save(usage);
      return jsonResponse({ ok: true });
    }

    if (url.pathname === "/sync-used") {
      const usedBytes = Number(body.usedBytes);
      usage.usedBytes = Number.isFinite(usedBytes) && usedBytes > 0 ? usedBytes : 0;
      await this.save(usage);
      return jsonResponse({ ok: true });
    }

    if (url.pathname === "/sync-reserved") {
      const reserved = body.reserved && typeof body.reserved === "object" ? body.reserved : {};
      let reservedBytes = 0;
      const nextReserved = {};
      for (const [token, sizeValue] of Object.entries(reserved)) {
        const size = Number(sizeValue);
        if (Number.isFinite(size) && size > 0) {
          nextReserved[token] = size;
          reservedBytes += size;
        }
      }
      usage.reserved = nextReserved;
      usage.reservedBytes = reservedBytes;
      await this.save(usage);
      return jsonResponse({ ok: true });
    }

    return new Response("Not found", { status: 404 });
  }
}
