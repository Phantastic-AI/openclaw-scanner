#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { createScanDaemonServer } from "../lib/scan-daemon-server.mjs";
import {
  DEFAULT_OPENCLAW_SCAND_LOG_PATH,
  createOpenclawScandHandlers,
  normalizeOpenclawScandConfig,
} from "../lib/openclaw-scand-service.mjs";
import { DEFAULT_SCAN_DAEMON_SOCKET_PATH } from "../lib/scan-daemon.mjs";

function printHelp() {
  process.stdout.write(
    [
      "Usage: openclaw-scand [serve] [options]",
      "",
      "Options:",
      "  --socket-path <path>           Unix socket path",
      "  --log-path <path>              JSONL log path",
      "  --clamd-socket-path <path>     ClamAV daemon socket path",
      "  --clamd-config-path <path>     ClamAV config path",
      "  --antivirus-timeout-ms <n>     ClamAV request timeout",
      "  --osv-scanner-path <path>      osv-scanner executable",
      "  --sca-timeout-ms <n>           OSV scan timeout",
      "  --bwrap-path <path>            bubblewrap executable",
      "  --help                         Show this help text",
      "",
      "Environment overrides:",
      "  OPENCLAW_SCAND_SOCKET_PATH",
      "  OPENCLAW_SCAND_LOG_PATH",
      "  OPENCLAW_SCAND_CLAMD_SOCKET_PATH",
      "  OPENCLAW_SCAND_CLAMD_CONFIG_PATH",
      "  OPENCLAW_SCAND_ANTIVIRUS_TIMEOUT_MS",
      "  OPENCLAW_SCAND_OSV_SCANNER_PATH",
      "  OPENCLAW_SCAND_SCA_TIMEOUT_MS",
      "  OPENCLAW_SCAND_BWRAP_PATH",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const result = {};
  const args = [...argv];
  if (args[0] === "serve") {
    args.shift();
  }
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (token === "--help" || token === "-h") {
      result.help = true;
      continue;
    }
    const next = args[index + 1];
    if (!token.startsWith("--") || next == null) {
      throw new Error(`invalid argument: ${token}`);
    }
    const key = token.slice(2);
    result[key] = next;
    index += 1;
  }
  return result;
}

async function loadPackageVersion() {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const packageJsonPath = path.join(__dirname, "..", "package.json");
  try {
    const payload = JSON.parse(await fs.readFile(packageJsonPath, "utf8"));
    return String(payload.version || "").trim() || undefined;
  } catch {
    return undefined;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    process.exit(0);
  }

  const version = await loadPackageVersion();
  const config = normalizeOpenclawScandConfig({
    socketPath: args["socket-path"] || process.env.OPENCLAW_SCAND_SOCKET_PATH || DEFAULT_SCAN_DAEMON_SOCKET_PATH,
    logPath: args["log-path"] || process.env.OPENCLAW_SCAND_LOG_PATH || DEFAULT_OPENCLAW_SCAND_LOG_PATH,
    antivirusSocketPath:
      args["clamd-socket-path"] || process.env.OPENCLAW_SCAND_CLAMD_SOCKET_PATH,
    antivirusClamdConfigPath:
      args["clamd-config-path"] || process.env.OPENCLAW_SCAND_CLAMD_CONFIG_PATH,
    antivirusScanTimeoutMs:
      Number(args["antivirus-timeout-ms"] || process.env.OPENCLAW_SCAND_ANTIVIRUS_TIMEOUT_MS),
    osvScannerPath: args["osv-scanner-path"] || process.env.OPENCLAW_SCAND_OSV_SCANNER_PATH,
    scaScanTimeoutMs: Number(args["sca-timeout-ms"] || process.env.OPENCLAW_SCAND_SCA_TIMEOUT_MS),
    bwrapPath: args["bwrap-path"] || process.env.OPENCLAW_SCAND_BWRAP_PATH,
    version,
  });

  const daemon = createScanDaemonServer({
    socketPath: config.socketPath,
    logPath: config.logPath,
    logger: console,
    handlers: createOpenclawScandHandlers(config),
  });

  const shutdown = async (signal) => {
    try {
      await daemon.close();
    } finally {
      if (signal) {
        process.exit(0);
      }
    }
  };

  process.on("SIGINT", () => {
    shutdown("SIGINT").catch((error) => {
      console.error(`[openclaw-scand] shutdown failed: ${String(error)}`);
      process.exit(1);
    });
  });
  process.on("SIGTERM", () => {
    shutdown("SIGTERM").catch((error) => {
      console.error(`[openclaw-scand] shutdown failed: ${String(error)}`);
      process.exit(1);
    });
  });

  await daemon.listen();
  console.log(
    `[openclaw-scand] listening on ${config.socketPath} logPath=${config.logPath} version=${config.version || "unknown"}`,
  );
}

main().catch((error) => {
  console.error(`[openclaw-scand] fatal: ${String(error)}`);
  process.exit(1);
});
