import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export const REVIEW_LEDGER_PLUGIN_ID = "openclaw-scanner";
export const REVIEW_LEDGER_PLUGIN_NAME = "OpenClaw Scanner";
export const REVIEW_LEDGER_CLI_COMMAND = "ocs";
export const DEFAULT_REVIEW_LEDGER_LIMIT = 20;
export const DEFAULT_ANTIVIRUS_LEDGER_LIMIT = 20;
export const DEFAULT_SCA_LEDGER_LIMIT = 20;

export function defaultReviewLedgerStateDir(homeDir = os.homedir()) {
  return path.join(homeDir, ".openclaw", "plugins", REVIEW_LEDGER_PLUGIN_ID);
}

export function resolveReviewLedgerStateDir(openClawStateDir) {
  return path.join(openClawStateDir, "plugins", REVIEW_LEDGER_PLUGIN_ID);
}

export function resolveReviewLedgerPath(stateDir) {
  return path.join(stateDir, "review-ledger.json");
}

export function resolveAntivirusLedgerPath(stateDir) {
  return path.join(stateDir, "antivirus-ledger.json");
}

export function resolveAntivirusStatusPath(stateDir) {
  return path.join(stateDir, "antivirus-status.json");
}

export function resolveScaLedgerPath(stateDir) {
  return path.join(stateDir, "sca-ledger.json");
}

export function resolveScaStatusPath(stateDir) {
  return path.join(stateDir, "sca-status.json");
}

export function resolvePostureStatusPath(stateDir) {
  return path.join(stateDir, "posture-status.json");
}

export function normalizeReviewLedgerLimit(value) {
  const numeric = typeof value === "number" ? value : Number.parseInt(String(value || ""), 10);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    throw new Error("limit must be a positive integer");
  }
  return Math.trunc(numeric);
}

export function formatReviewLedgerTimestamp(value) {
  if (!Number.isFinite(value) || value <= 0) {
    return "unknown-time";
  }
  return new Date(value).toISOString();
}

export function selectReviewLedgerRecords(payload, limit = DEFAULT_REVIEW_LEDGER_LIMIT) {
  const resolvedLimit = normalizeReviewLedgerLimit(limit);
  return Object.values(payload?.entries || {})
    .map((entry) => entry?.value)
    .filter(Boolean)
    .sort((a, b) => (b?.recordedAt || 0) - (a?.recordedAt || 0))
    .slice(0, resolvedLimit);
}

export function selectAntivirusRecords(payload, limit = DEFAULT_ANTIVIRUS_LEDGER_LIMIT) {
  const resolvedLimit = normalizeReviewLedgerLimit(limit);
  return Object.values(payload?.entries || {})
    .map((entry) => entry?.value)
    .filter(Boolean)
    .sort((a, b) => (b?.recordedAt || 0) - (a?.recordedAt || 0))
    .slice(0, resolvedLimit);
}

export function selectScaRecords(payload, limit = DEFAULT_SCA_LEDGER_LIMIT) {
  const resolvedLimit = normalizeReviewLedgerLimit(limit);
  return Object.values(payload?.entries || {})
    .map((entry) => entry?.value)
    .filter(Boolean)
    .sort((a, b) => (b?.recordedAt || 0) - (a?.recordedAt || 0))
    .slice(0, resolvedLimit);
}

export async function loadReviewLedgerReport({
  stateDir = defaultReviewLedgerStateDir(),
  limit = DEFAULT_REVIEW_LEDGER_LIMIT,
} = {}) {
  const ledgerPath = resolveReviewLedgerPath(stateDir);
  let payload;
  try {
    payload = JSON.parse(await fs.readFile(ledgerPath, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        found: false,
        ledgerPath,
        records: [],
      };
    }
    throw error;
  }

  return {
    found: true,
    ledgerPath,
    records: selectReviewLedgerRecords(payload, limit),
  };
}

async function readPersistentValue(filePath, key = "current") {
  try {
    const payload = JSON.parse(await fs.readFile(filePath, "utf8"));
    return payload?.entries?.[key]?.value;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

export async function loadAntivirusReport({
  stateDir = defaultReviewLedgerStateDir(),
  limit = DEFAULT_ANTIVIRUS_LEDGER_LIMIT,
} = {}) {
  const ledgerPath = resolveAntivirusLedgerPath(stateDir);
  const statusPath = resolveAntivirusStatusPath(stateDir);
  let payload;
  try {
    payload = JSON.parse(await fs.readFile(ledgerPath, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        found: false,
        ledgerPath,
        statusPath,
        status: await readPersistentValue(statusPath),
        records: [],
      };
    }
    throw error;
  }

  return {
    found: true,
    ledgerPath,
    statusPath,
    status: await readPersistentValue(statusPath),
    records: selectAntivirusRecords(payload, limit),
  };
}

export async function loadScaReport({
  stateDir = defaultReviewLedgerStateDir(),
  limit = DEFAULT_SCA_LEDGER_LIMIT,
} = {}) {
  const ledgerPath = resolveScaLedgerPath(stateDir);
  const statusPath = resolveScaStatusPath(stateDir);
  let payload;
  try {
    payload = JSON.parse(await fs.readFile(ledgerPath, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        found: false,
        ledgerPath,
        statusPath,
        status: await readPersistentValue(statusPath),
        records: [],
      };
    }
    throw error;
  }

  return {
    found: true,
    ledgerPath,
    statusPath,
    status: await readPersistentValue(statusPath),
    records: selectScaRecords(payload, limit),
  };
}

export async function loadPostureReport({
  stateDir = defaultReviewLedgerStateDir(),
} = {}) {
  const statusPath = resolvePostureStatusPath(stateDir);
  return {
    statusPath,
    status: await readPersistentValue(statusPath),
  };
}

export function renderReviewLedgerReport({ found, ledgerPath, records }) {
  if (!found) {
    return `No review ledger found at ${ledgerPath}\n`;
  }

  if (!records.length) {
    return `No review records in ${ledgerPath}\n`;
  }

  let output = "";
  for (const record of records) {
    const sourceRef = record.sourceRef || {};
    const review = record.review || {};
    const usage = record.usage || {};
    output += `${formatReviewLedgerTimestamp(record.recordedAt)} ${record.guard || "review"} ${review.finalAction || "unknown"} ${sourceRef.toolName || "unknown"}\n`;
    output += `  session=${sourceRef.sessionKey || "unknown"} toolCallId=${sourceRef.toolCallId || "unknown"}\n`;
    if (sourceRef.transcriptLocator) {
      output += `  link=${sourceRef.transcriptLocator}\n`;
    }
    output += `  response=${review.reasonCode || "unknown"} source=${review.decisionSource || "unknown"} backend=${review.backend || "unknown"} model=${review.model || "unknown"}\n`;
    if (Number.isFinite(usage.totalTokens)) {
      output += `  usage=input:${usage.inputTokens || 0} output:${usage.outputTokens || 0} cacheRead:${usage.cacheReadTokens || 0} cacheWrite:${usage.cacheWriteTokens || 0} total:${usage.totalTokens}\n`;
    }
    if (review.reason) {
      output += `  reason=${review.reason}\n`;
    }
  }
  return output;
}

export function renderAntivirusReport({ found, ledgerPath, status, records }) {
  if (!found && !status) {
    return `No antivirus ledger found at ${ledgerPath}\n`;
  }

  let output = "";
  if (status) {
    output += `status=${status.status || "unknown"} protection=${status.protection || "unknown"} message=${status.statusMessage || "unknown"}\n`;
    if (status.socketPath) {
      output += `  socket=${status.socketPath}\n`;
    }
    if (status.clamdConfigPath) {
      output += `  config=${status.clamdConfigPath}\n`;
    }
    if (Array.isArray(status.onAccessRoots) && status.onAccessRoots.length > 0) {
      output += `  onAccessRoots=${status.onAccessRoots.join(",")}\n`;
    }
  }

  if (!records.length) {
    output += `No antivirus records in ${ledgerPath}\n`;
    return output;
  }

  for (const record of records) {
    output += `${formatReviewLedgerTimestamp(record.recordedAt)} antivirus ${record.verdict || "unknown"} ${record.toolName || "unknown"}\n`;
    output += `  session=${record.sessionKey || "unknown"} toolCallId=${record.toolCallId || "unknown"} action=${record.actionKind || "unknown"} protection=${record.protection || "unknown"}\n`;
    if (Array.isArray(record.targetPaths) && record.targetPaths.length > 0) {
      output += `  targets=${record.targetPaths.join(",")}\n`;
    }
    if (record.message) {
      output += `  message=${record.message}\n`;
    }
    if (Array.isArray(record.findings) && record.findings.length > 0) {
      output += `  findings=${record.findings.map((entry) => `${entry.signature}@${entry.path || entry.rootPath || "unknown"}`).join(",")}\n`;
    }
    if (Array.isArray(record.errors) && record.errors.length > 0) {
      output += `  errors=${record.errors.map((entry) => entry.detail || "unknown").join(" | ")}\n`;
    }
  }
  return output;
}

export function renderScaReport({ found, ledgerPath, status, records }) {
  if (!found && !status) {
    return `No SCA ledger found at ${ledgerPath}\n`;
  }

  let output = "";
  if (status) {
    output += `status=${status.status || "unknown"} engine=${status.engine || "unknown"} message=${status.statusMessage || "unknown"}\n`;
    if (status.version) {
      output += `  version=${status.version}\n`;
    }
  }

  if (!records.length) {
    output += `No SCA records in ${ledgerPath}\n`;
    return output;
  }

  for (const record of records) {
    output += `${formatReviewLedgerTimestamp(record.recordedAt)} sca ${record.verdict || "unknown"} ${record.toolName || "unknown"}\n`;
    output += `  session=${record.sessionKey || "unknown"} toolCallId=${record.toolCallId || "unknown"} action=${record.actionKind || "unknown"}\n`;
    if (Array.isArray(record.scannedRoots) && record.scannedRoots.length > 0) {
      output += `  roots=${record.scannedRoots.join(",")}\n`;
    }
    if (record.message) {
      output += `  message=${record.message}\n`;
    }
    if (Array.isArray(record.advisories) && record.advisories.length > 0) {
      output += `  advisories=${record.advisories
        .map((entry) => `${entry.packageName}@${entry.packageVersion}:${(entry.ids || []).join("+")}`)
        .join(",")}\n`;
    }
    if (Array.isArray(record.errors) && record.errors.length > 0) {
      output += `  errors=${record.errors.map((entry) => entry.detail || "unknown").join(" | ")}\n`;
    }
  }
  return output;
}

export function renderPostureReport({ statusPath, status }) {
  if (!status) {
    return `No posture status found at ${statusPath}\n`;
  }
  let output = `posture=${status.posture || "unknown"} reason=${status.reasonCode || "unknown"} message=${status.statusMessage || "unknown"}\n`;
  output += `  configuredExecCapable=${status.configuredExecCapable === true ? "true" : "false"} observedExec=${status.observedExec === true ? "true" : "false"}\n`;
  if (status.globalProfile) {
    output += `  globalProfile=${status.globalProfile}\n`;
  }
  if (Array.isArray(status.execCapableAgents) && status.execCapableAgents.length > 0) {
    output += `  execCapableAgents=${status.execCapableAgents.join(",")}\n`;
  }
  if (status.lastObservedToolName) {
    output += `  lastObservedTool=${status.lastObservedToolName}\n`;
  }
  if (Number.isFinite(status.lastObservedAt)) {
    output += `  lastObservedAt=${formatReviewLedgerTimestamp(status.lastObservedAt)}\n`;
  }
  return output;
}

export async function printReviewLedgerReport({
  stateDir = defaultReviewLedgerStateDir(),
  limit = DEFAULT_REVIEW_LEDGER_LIMIT,
  json = false,
  write = (text) => process.stdout.write(text),
} = {}) {
  const report = await loadReviewLedgerReport({ stateDir, limit });
  if (json) {
    write(`${JSON.stringify(report.records, null, 2)}\n`);
    return report;
  }
  write(renderReviewLedgerReport(report));
  return report;
}

export async function printAntivirusReport({
  stateDir = defaultReviewLedgerStateDir(),
  limit = DEFAULT_ANTIVIRUS_LEDGER_LIMIT,
  json = false,
  write = (text) => process.stdout.write(text),
} = {}) {
  const report = await loadAntivirusReport({ stateDir, limit });
  if (json) {
    write(`${JSON.stringify({ status: report.status, records: report.records }, null, 2)}\n`);
    return report;
  }
  write(renderAntivirusReport(report));
  return report;
}

export async function printScaReport({
  stateDir = defaultReviewLedgerStateDir(),
  limit = DEFAULT_SCA_LEDGER_LIMIT,
  json = false,
  write = (text) => process.stdout.write(text),
} = {}) {
  const report = await loadScaReport({ stateDir, limit });
  if (json) {
    write(`${JSON.stringify({ status: report.status, records: report.records }, null, 2)}\n`);
    return report;
  }
  write(renderScaReport(report));
  return report;
}

export async function printPostureReport({
  stateDir = defaultReviewLedgerStateDir(),
  json = false,
  write = (text) => process.stdout.write(text),
} = {}) {
  const report = await loadPostureReport({ stateDir });
  if (json) {
    write(`${JSON.stringify(report.status || {}, null, 2)}\n`);
    return report;
  }
  write(renderPostureReport(report));
  return report;
}

export function registerReviewLedgerCli(program, params = {}) {
  const defaultStateDir =
    String(params.defaultStateDir || "").trim() || defaultReviewLedgerStateDir();
  const write = typeof params.write === "function" ? params.write : undefined;
  const root = program
    .command(REVIEW_LEDGER_CLI_COMMAND)
    .description(`${REVIEW_LEDGER_PLUGIN_NAME} (OCS) plugin tools`);

  root
    .command("report")
    .description("Print recent ingress review records")
    .option("--json", "Print JSON", false)
    .option("--state-dir <dir>", "Plugin state directory", defaultStateDir)
    .option(
      "--limit <n>",
      "Max records to print",
      (value) => normalizeReviewLedgerLimit(value),
      DEFAULT_REVIEW_LEDGER_LIMIT,
    )
    .action(async (opts) => {
      await printReviewLedgerReport({
        stateDir: opts.stateDir,
        limit: opts.limit,
        json: Boolean(opts.json),
        ...(write ? { write } : {}),
      });
    });

  root
    .command("antivirus-report")
    .description("Print recent antivirus status and file-scan records")
    .option("--json", "Print JSON", false)
    .option("--state-dir <dir>", "Plugin state directory", defaultStateDir)
    .option(
      "--limit <n>",
      "Max records to print",
      (value) => normalizeReviewLedgerLimit(value),
      DEFAULT_ANTIVIRUS_LEDGER_LIMIT,
    )
    .action(async (opts) => {
      await printAntivirusReport({
        stateDir: opts.stateDir,
        limit: opts.limit,
        json: Boolean(opts.json),
        ...(write ? { write } : {}),
      });
    });

  root
    .command("sca-report")
    .description("Print recent package vulnerability scan status and records")
    .option("--json", "Print JSON", false)
    .option("--state-dir <dir>", "Plugin state directory", defaultStateDir)
    .option(
      "--limit <n>",
      "Max records to print",
      (value) => normalizeReviewLedgerLimit(value),
      DEFAULT_SCA_LEDGER_LIMIT,
    )
    .action(async (opts) => {
      await printScaReport({
        stateDir: opts.stateDir,
        limit: opts.limit,
        json: Boolean(opts.json),
        ...(write ? { write } : {}),
      });
    });

  root
    .command("posture-report")
    .description("Print current exec posture status")
    .option("--json", "Print JSON", false)
    .option("--state-dir <dir>", "Plugin state directory", defaultStateDir)
    .action(async (opts) => {
      await printPostureReport({
        stateDir: opts.stateDir,
        json: Boolean(opts.json),
        ...(write ? { write } : {}),
      });
    });

  return root;
}
