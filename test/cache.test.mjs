import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { PersistentJsonCache } from "../lib/cache.mjs";

test("persistent cache tolerates concurrent writers for the same file", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-scanner-cache-"));
  const cachePath = path.join(tempDir, "posture-status.json");
  const logger = { warn() {} };

  const writers = Array.from({ length: 6 }, (_, index) => {
    const cache = new PersistentJsonCache(cachePath, 0, logger);
    return cache.set("current", {
      posture: index % 2 === 0 ? "normal" : "degraded",
      updatedAt: Date.now() + index,
    });
  });

  await Promise.all(writers);

  const payload = JSON.parse(fs.readFileSync(cachePath, "utf8"));
  assert.ok(payload.entries.current);
  assert.match(payload.entries.current.value.posture, /^(normal|degraded)$/);

  fs.rmSync(tempDir, { recursive: true, force: true });
});
