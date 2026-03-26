import fs from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";

async function ensureDir(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

export class PersistentJsonCache {
  constructor(filePath, ttlSec, logger) {
    this.filePath = filePath;
    this.ttlMs = Math.max(0, Number(ttlSec || 0)) * 1000;
    this.logger = logger;
    this.entries = new Map();
    this.loaded = false;
  }

  async init() {
    if (this.loaded) {
      return;
    }
    this.loaded = true;
    try {
      const raw = await fs.readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw);
      for (const [key, value] of Object.entries(parsed.entries || {})) {
        this.entries.set(key, value);
      }
      this.pruneExpired();
    } catch (error) {
      if (error && error.code !== "ENOENT") {
        this.logger?.warn?.(
          `[openclaw-scanner] failed reading cache ${this.filePath}: ${String(error)}`,
        );
      }
    }
  }

  pruneExpired(now = Date.now()) {
    if (this.ttlMs <= 0) {
      return;
    }
    for (const [key, entry] of this.entries) {
      if (!entry || typeof entry.savedAt !== "number") {
        this.entries.delete(key);
        continue;
      }
      if (now - entry.savedAt > this.ttlMs) {
        this.entries.delete(key);
      }
    }
  }

  async get(key) {
    await this.init();
    this.pruneExpired();
    return this.entries.get(key)?.value;
  }

  async set(key, value) {
    await this.init();
    this.entries.set(key, { savedAt: Date.now(), value });
    await this.flush();
    return value;
  }

  async delete(key) {
    await this.init();
    this.entries.delete(key);
    await this.flush();
  }

  async values() {
    await this.init();
    this.pruneExpired();
    return Array.from(this.entries.values()).map((entry) => entry?.value).filter(Boolean);
  }

  async flush() {
    await ensureDir(this.filePath);
    const payload = {
      entries: Object.fromEntries(this.entries.entries()),
    };
    const nextPath = `${this.filePath}.${process.pid}.${randomUUID()}.tmp`;
    await fs.writeFile(nextPath, JSON.stringify(payload, null, 2), "utf8");
    await fs.rename(nextPath, this.filePath);
  }
}
