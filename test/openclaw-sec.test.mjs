import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

import {
  buildScanBrokerRequest,
  normalizeScanBrokerConfig,
  requestScanBroker,
} from "../lib/scan-broker.mjs";
import { createScanBrokerServer } from "../lib/scan-broker-server.mjs";
import {
  buildOsvBubblewrapArgs,
  createOpenclawSecHandlers,
  normalizeOpenclawSecConfig,
} from "../lib/openclaw-sec-service.mjs";

function writeExecutableScript(filePath, source) {
  fs.writeFileSync(filePath, source, { encoding: "utf8", mode: 0o755 });
}

async function withFakeClamd(run, options = {}) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-sec-clamd-"));
  const socketPath = path.join(tempDir, "clamd.sock");
  const responses = options.responses || {};
  const server = net.createServer((socket) => {
    let payload = "";
    socket.on("data", (chunk) => {
      payload += chunk.toString("utf8");
    });
    socket.on("end", () => {
      const command = payload.replace(/^n/, "").trim();
      if (command === "PING") {
        socket.end("PONG\n");
        return;
      }
      if (command.startsWith("SCAN ")) {
        const targetPath = command.slice(5).trim();
        const response = responses[targetPath] || `${targetPath}: OK\n`;
        socket.end(response);
        return;
      }
      socket.end("UNKNOWN COMMAND\n");
    });
  });
  await new Promise((resolve) => server.listen(socketPath, resolve));
  try {
    return await run({ socketPath, tempDir });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

test("scan broker client round-trips a status request over a Unix socket", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-sec-socket-"));
  const socketPath = path.join(tempDir, "ocs.sock");
  const broker = createScanBrokerServer({
    socketPath,
    handlers: {
      async status() {
        return {
          backend: "openclaw-sec",
          status: {
            malwareScan: { engine: "clamd", status: "active" },
            packageSca: { engine: "osv-scanner", status: "active" },
          },
        };
      },
    },
  });
  await broker.listen();

  try {
    const response = await requestScanBroker(
      normalizeScanBrokerConfig({
        scanBrokerMode: "required",
        scanBrokerSocketPath: socketPath,
      }),
      buildScanBrokerRequest({ op: "status" }),
    );
    assert.equal(response.ok, true);
    assert.equal(response.backend, "openclaw-sec");
    assert.equal(response.status.malwareScan.status, "active");
    assert.equal(response.status.packageSca.status, "active");
  } finally {
    await broker.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("openclaw-sec packageSca returns advisories through fake bubblewrap and fake osv-scanner", async () => {
  const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-sec-osv-project-"));
  fs.writeFileSync(path.join(projectDir, "package-lock.json"), '{"name":"demo"}\n', "utf8");

  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-sec-osv-bin-"));
  const fakeOsvPath = path.join(binDir, "osv-scanner");
  const fakeBwrapPath = path.join(binDir, "bwrap");

  writeExecutableScript(
    fakeOsvPath,
    `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = "--version" ]; then
  echo "osv-scanner vTEST"
  exit 0
fi
echo "Scanning dir $4" >&2
echo "Found vulnerable lockfile" >&2
cat <<'JSON'
{"results":[{"source":{"path":"package-lock.json","type":"lockfile"},"packages":[{"package":{"name":"left-pad","version":"1.3.0","ecosystem":"npm"},"groups":[{"ids":["GHSA-test-1"]}]}]}]}
JSON
exit 1
`,
  );

  writeExecutableScript(
    fakeBwrapPath,
    `#!/usr/bin/env bash
set -euo pipefail
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--" ]; then
    shift
    break
  fi
  shift
done
exec "$@"
`,
  );

  const config = normalizeOpenclawSecConfig({
    socketPath: path.join(projectDir, "ignored.sock"),
    logPath: path.join(projectDir, "ignored.jsonl"),
    osvScannerPath: fakeOsvPath,
    bwrapPath: fakeBwrapPath,
  });

  const args = await buildOsvBubblewrapArgs(
    {
      ...config.sca,
      bwrapPath: fakeBwrapPath,
    },
    projectDir,
  );
  assert.match(args.join(" "), /--ro-bind \/ \//);
  assert.match(args.join(" "), /--ro-bind/);
  assert.match(args.join(" "), /--tmpfs \/tmp/);

  const handlers = createOpenclawSecHandlers(config);
  const response = await handlers.packageSca({
    roots: [projectDir],
  });

  assert.equal(response.backend, "osv-scanner");
  assert.equal(response.status, "active");
  assert.equal(response.verdict, "advisory");
  assert.equal(response.advisories.length, 1);
  assert.equal(response.advisories[0].packageName, "left-pad");
});

test("openclaw-sec malwareScan returns clean through fake clamd", async () => {
  const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-sec-av-project-"));
  fs.writeFileSync(path.join(projectDir, "package.json"), '{"name":"demo"}\n', "utf8");

  await withFakeClamd(async ({ socketPath }) => {
    const config = normalizeOpenclawSecConfig({
      socketPath: path.join(projectDir, "ignored.sock"),
      logPath: path.join(projectDir, "ignored.jsonl"),
      antivirusSocketPath: socketPath,
    });
    const handlers = createOpenclawSecHandlers(config);
    const response = await handlers.malwareScan({
      roots: [projectDir],
    });

    assert.equal(response.backend, "clamd");
    assert.equal(response.status, "active");
    assert.equal(response.verdict, "clean");
    assert.deepEqual(response.findings, []);
    assert.ok(Array.isArray(response.scannedPaths));
  });
});

test("openclaw-sec executable prints help", () => {
  const binPath = path.join(process.cwd(), "bin", "openclaw-sec.mjs");
  const result = spawnSync(process.execPath, [binPath, "--help"], {
    encoding: "utf8",
  });

  assert.equal(result.status, 0);
  assert.match(result.stdout, /Usage: openclaw-sec/);
  assert.match(result.stdout, /--socket-path/);
});
