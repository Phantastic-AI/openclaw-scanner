#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { createActionReviewdServer } from "../lib/action-reviewd-server.mjs";
import {
  DEFAULT_OPENCLAW_ACTION_REVIEWD_LOG_PATH,
  DEFAULT_OPENCLAW_ACTION_REVIEWD_SOCKET_PATH,
  createOpenclawActionReviewdContext,
  createOpenclawActionReviewdHandlers,
  normalizeOpenclawActionReviewdConfig,
  runMattermostThreadReviewCycle,
} from "../lib/openclaw-action-reviewd-service.mjs";

function printHelp() {
  process.stdout.write(
    [
      "Usage: openclaw-action-reviewd [serve] [options]",
      "",
      "Options:",
      "  --config <path>                JSON config path",
      "  --socket-path <path>           Unix socket path",
      "  --log-path <path>              JSONL log path",
      "  --store-dir <path>             State directory",
      "  --state-file <path>            Reviewd transport state file",
      "  --poll-interval-ms <n>         Review transport poll interval",
      "  --help                         Show this help text",
      "",
      "Environment overrides:",
      "  OPENCLAW_ACTION_REVIEWD_SOCKET_PATH",
      "  OPENCLAW_ACTION_REVIEWD_LOG_PATH",
      "  OPENCLAW_ACTION_REVIEWD_STORE_DIR",
      "  OPENCLAW_ACTION_REVIEWD_STATE_FILE",
      "  ACTION_REVIEWD_MATTERMOST_BASE_URL",
      "  ACTION_REVIEWD_MATTERMOST_BOT_TOKEN",
      "  ACTION_REVIEWD_MATTERMOST_CHANNEL_ID",
      "  ACTION_REVIEWD_MATTERMOST_REVIEWER_USER_IDS",
      "  ACTION_REVIEWD_MATTERMOST_REVIEWER_USERNAMES",
      "  ACTION_REVIEWD_INTENT_BASE_URL",
      "  ACTION_REVIEWD_INTENT_API_KEY",
      "  ACTION_REVIEWD_INTENT_MODEL",
      "  OPENCLAW_ACTION_REVIEWD_GATEWAY_URL",
      "  OPENCLAW_ACTION_REVIEWD_GATEWAY_TOKEN",
      "  OPENCLAW_ACTION_REVIEWD_OPENCLAW_CMD",
      "  OPENCLAW_ACTION_REVIEWD_AGENT_TIMEOUT_MS",
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
    result[token.slice(2)] = next;
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

async function loadJsonConfig(configPath) {
  if (!configPath) {
    return {};
  }
  const raw = await fs.readFile(configPath, "utf8");
  return JSON.parse(raw);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    process.exit(0);
  }

  const version = await loadPackageVersion();
  const fileConfig = await loadJsonConfig(args.config || process.env.OPENCLAW_ACTION_REVIEWD_CONFIG_PATH);
  const config = normalizeOpenclawActionReviewdConfig({
    ...fileConfig,
    socketPath:
      args["socket-path"] ||
      process.env.OPENCLAW_ACTION_REVIEWD_SOCKET_PATH ||
      fileConfig.socketPath ||
      DEFAULT_OPENCLAW_ACTION_REVIEWD_SOCKET_PATH,
    logPath:
      args["log-path"] ||
      process.env.OPENCLAW_ACTION_REVIEWD_LOG_PATH ||
      fileConfig.logPath ||
      DEFAULT_OPENCLAW_ACTION_REVIEWD_LOG_PATH,
    storeDir:
      args["store-dir"] ||
      process.env.OPENCLAW_ACTION_REVIEWD_STORE_DIR ||
      fileConfig.storeDir,
    reviewdStateFile:
      args["state-file"] ||
      process.env.OPENCLAW_ACTION_REVIEWD_STATE_FILE ||
      fileConfig.reviewdStateFile,
    pollIntervalMs:
      Number(args["poll-interval-ms"] || process.env.OPENCLAW_ACTION_REVIEWD_POLL_INTERVAL_MS) ||
      fileConfig.pollIntervalMs,
    version,
  });

  const context = await createOpenclawActionReviewdContext(config, console);
  const daemon = createActionReviewdServer({
    socketPath: config.socketPath,
    logPath: config.logPath,
    logger: console,
    handlers: createOpenclawActionReviewdHandlers(context),
  });

  let pollTimer;
  let pollPromise = null;
  const runReviewCycle = async (source) => {
    if (pollPromise) {
      return await pollPromise;
    }
    pollPromise = runMattermostThreadReviewCycle(context).catch((error) => {
      console.error(`[openclaw-action-reviewd] ${source} review cycle failed: ${String(error)}`);
    });
    try {
      await pollPromise;
    } finally {
      pollPromise = null;
    }
  };

  const startPolling = () => {
    pollTimer = setInterval(() => {
      void runReviewCycle("poll");
    }, config.pollIntervalMs);
    pollTimer.unref?.();
  };

  const shutdown = async (signal) => {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = undefined;
    }
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
      console.error(`[openclaw-action-reviewd] shutdown failed: ${String(error)}`);
      process.exit(1);
    });
  });
  process.on("SIGTERM", () => {
    shutdown("SIGTERM").catch((error) => {
      console.error(`[openclaw-action-reviewd] shutdown failed: ${String(error)}`);
      process.exit(1);
    });
  });

  await daemon.listen();
  startPolling();
  await runReviewCycle("initial");
  console.log(
    `[openclaw-action-reviewd] listening on ${config.socketPath} logPath=${config.logPath} version=${config.version || "unknown"}`,
  );
}

main().catch((error) => {
  console.error(`[openclaw-action-reviewd] fatal: ${String(error)}`);
  process.exit(1);
});
