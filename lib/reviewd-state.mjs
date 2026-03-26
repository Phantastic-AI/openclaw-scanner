import fs from "node:fs/promises";
import path from "node:path";

function asObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function clone(value) {
  return structuredClone(value);
}

async function writeJsonAtomic(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await fs.rename(tempPath, filePath);
}

export class ReviewdStateStore {
  constructor({ filePath }) {
    this.filePath = String(filePath || "").trim();
    this.state = {
      requests: {},
    };
  }

  async init() {
    if (!this.filePath) {
      throw new Error("missing reviewd state file path");
    }
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    await this.load();
  }

  async load() {
    try {
      const raw = await fs.readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw);
      this.state = {
        requests: asObject(parsed.requests),
      };
    } catch (error) {
      if (error?.code === "ENOENT") {
        this.state = { requests: {} };
        return this.state;
      }
      throw error;
    }
    return clone(this.state);
  }

  getRequest(requestId) {
    return clone(asObject(this.state.requests?.[requestId]));
  }

  async setRequest(requestId, value) {
    const normalizedRequestId = String(requestId || "").trim();
    if (!normalizedRequestId) {
      throw new Error("missing requestId");
    }
    this.state.requests[normalizedRequestId] = clone(asObject(value));
    await writeJsonAtomic(this.filePath, this.state);
    return this.getRequest(normalizedRequestId);
  }

  async deleteRequest(requestId) {
    const normalizedRequestId = String(requestId || "").trim();
    if (!normalizedRequestId) {
      return;
    }
    delete this.state.requests[normalizedRequestId];
    await writeJsonAtomic(this.filePath, this.state);
  }
}
