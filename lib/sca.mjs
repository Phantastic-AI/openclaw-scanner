import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const DEFAULT_OSV_SCANNER_PATH = "osv-scanner";

export const SCA_INLINE_UNAVAILABLE_MESSAGE =
  "WARNING: OSV package vulnerability scanning was unavailable for this action. Known vulnerable dependencies may not have been detected.";
export const SCA_INLINE_INCONCLUSIVE_MESSAGE =
  "WARNING: OSV package vulnerability scanning could not find supported lockfiles or manifests for this action. Installed packages may not have been fully assessed for known vulnerabilities.";
export const SCA_INLINE_ADVISORY_MESSAGE =
  "WARNING: OSV package vulnerability scanning found known vulnerable dependencies for this action. Review the OCS SCA report before trusting installed packages.";
export const SCA_STATUS_UNAVAILABLE_MESSAGE =
  "Package vulnerability scanning: unavailable";
export const SCA_STATUS_ACTIVE_MESSAGE =
  "Package vulnerability scanning: active (OSV-Scanner)";

function normalizeMode(value) {
  const normalized = String(value || "auto").trim().toLowerCase();
  if (normalized === "disabled" || normalized === "required") {
    return normalized;
  }
  return "auto";
}

function unique(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

export function normalizeScaConfig(raw = {}) {
  return {
    mode: normalizeMode(raw.scaMode),
    warnUnavailable: raw.scaWarnUnavailable !== false,
    warnDetected: raw.scaWarnDetected !== false,
    warnInconclusive: raw.scaWarnInconclusive !== false,
    osvScannerPath: String(raw.osvScannerPath || "").trim() || DEFAULT_OSV_SCANNER_PATH,
    scanTimeoutMs:
      Number.isFinite(raw.scaScanTimeoutMs) && raw.scaScanTimeoutMs > 0
        ? Math.trunc(Number(raw.scaScanTimeoutMs))
        : 8000,
    maxBufferBytes:
      Number.isFinite(raw.scaMaxBufferBytes) && raw.scaMaxBufferBytes > 0
        ? Math.trunc(Number(raw.scaMaxBufferBytes))
        : 4 * 1024 * 1024,
  };
}

export function shouldRunScaForAction(action) {
  return action?.kind === "package install" || action?.kind === "python package install";
}

async function pathExists(filePath) {
  try {
    await fs.stat(filePath);
    return true;
  } catch {
    return false;
  }
}

function buildActionSummary(action) {
  if (!action) {
    return "recent package action";
  }
  const directory = action.roots?.[0];
  if (directory) {
    return `${action.kind} in ${directory}`;
  }
  return action.kind;
}

function parseJson(text) {
  try {
    return JSON.parse(String(text || ""));
  } catch {
    return undefined;
  }
}

function parseJsonDocument(text) {
  const raw = String(text || "").trim();
  if (!raw) {
    return undefined;
  }
  const direct = parseJson(raw);
  if (direct) {
    return direct;
  }

  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start < 0 || end <= start) {
    return undefined;
  }
  return parseJson(raw.slice(start, end + 1));
}

async function defaultOsvCommandRunner(config, rootPath) {
  try {
    const result = await execFileAsync(
      config.osvScannerPath,
      ["scan", "source", "-r", rootPath, "--format", "json"],
      {
        timeout: config.scanTimeoutMs,
        maxBuffer: config.maxBufferBytes,
      },
    );
    return {
      stdout: String(result.stdout || ""),
      stderr: String(result.stderr || ""),
      exitCode: 0,
    };
  } catch (error) {
    return {
      stdout: String(error?.stdout || ""),
      stderr: String(error?.stderr || ""),
      exitCode: Number.isFinite(error?.code) ? Number(error.code) : 127,
    };
  }
}

function collectGroupedIds(packageRecord = {}) {
  const grouped = Array.isArray(packageRecord.groups) ? packageRecord.groups : [];
  const ids = grouped.flatMap((group) =>
    Array.isArray(group?.ids) ? group.ids.map((value) => String(value || "").trim()).filter(Boolean) : [],
  );
  if (ids.length > 0) {
    return unique(ids);
  }
  const vulnerabilities = Array.isArray(packageRecord.vulnerabilities)
    ? packageRecord.vulnerabilities
    : [];
  return unique(
    vulnerabilities
      .map((entry) => String(entry?.id || "").trim())
      .filter(Boolean),
  );
}

function extractAdvisories(payload) {
  const results = Array.isArray(payload?.results) ? payload.results : [];
  const advisories = [];
  for (const result of results) {
    const sourcePath = String(result?.source?.path || "").trim() || undefined;
    const sourceType = String(result?.source?.type || "").trim() || undefined;
    const packages = Array.isArray(result?.packages) ? result.packages : [];
    for (const packageRecord of packages) {
      const ids = collectGroupedIds(packageRecord);
      if (ids.length === 0) {
        continue;
      }
      advisories.push({
        sourcePath,
        sourceType,
        packageName: String(packageRecord?.package?.name || "").trim() || "unknown",
        packageVersion: String(packageRecord?.package?.version || "").trim() || "unknown",
        ecosystem: String(packageRecord?.package?.ecosystem || "").trim() || "unknown",
        ids,
      });
    }
  }
  return advisories;
}

export async function detectScaBackend(config) {
  if (config.mode === "disabled") {
    return {
      status: "disabled",
      engine: "disabled",
      warnUnavailable: false,
      statusMessage: "Package vulnerability scanning disabled",
    };
  }

  try {
    const { stdout, stderr } = await execFileAsync(config.osvScannerPath, ["--version"], {
      timeout: config.scanTimeoutMs,
      maxBuffer: config.maxBufferBytes,
    });
    const versionLine = String(stdout || stderr || "").trim().split(/\r?\n/).find(Boolean);
    return {
      status: "active",
      engine: "osv-scanner",
      version: versionLine || undefined,
      warnUnavailable: false,
      statusMessage: SCA_STATUS_ACTIVE_MESSAGE,
    };
  } catch (error) {
    return {
      status: "unavailable",
      engine: "osv-scanner",
      warnUnavailable: config.warnUnavailable,
      statusMessage: SCA_STATUS_UNAVAILABLE_MESSAGE,
      error: String(error),
    };
  }
}

export async function runOsvSourceScan(config, targetPaths = [], options = {}) {
  const candidateRoots = unique(targetPaths.map((value) => path.normalize(String(value || "").trim()))).filter(Boolean);
  const existingRoots = [];
  for (const candidate of candidateRoots) {
    if (await pathExists(candidate)) {
      existingRoots.push(candidate);
    }
  }

  if (existingRoots.length === 0) {
    return {
      verdict: "inconclusive",
      scannedRoots: [],
      advisories: [],
      errors: [{ detail: "no existing scan roots" }],
    };
  }

  const runs = [];
  const runCommand = typeof options.runCommand === "function" ? options.runCommand : defaultOsvCommandRunner;
  for (const rootPath of existingRoots) {
    const { stdout = "", stderr = "", exitCode = 0 } = await runCommand(config, rootPath);

    const payload =
      parseJsonDocument(stdout) ||
      parseJsonDocument(stderr) ||
      parseJsonDocument(`${stdout}\n${stderr}`);
    if (exitCode === 128) {
      runs.push({
        rootPath,
        verdict: "inconclusive",
        advisories: [],
        errors: [{ detail: "no supported lockfiles or manifests found" }],
      });
      continue;
    }
    if (!payload) {
      runs.push({
        rootPath,
        verdict: exitCode === 0 ? "clean" : "error",
        advisories: [],
        errors:
          exitCode === 0
            ? []
            : [{ detail: stderr || stdout || `osv-scanner failed with exit code ${exitCode}` }],
      });
      continue;
    }

    const advisories = extractAdvisories(payload).map((entry) => ({
      ...entry,
      rootPath,
    }));
    runs.push({
      rootPath,
      verdict: advisories.length > 0 || exitCode === 1 ? "advisory" : "clean",
      advisories,
      errors: [],
    });
  }

  const advisories = runs.flatMap((entry) => entry.advisories || []);
  const errors = runs.flatMap((entry) => entry.errors || []);
  const hasError = runs.some((entry) => entry.verdict === "error");
  const hasInconclusive = runs.some((entry) => entry.verdict === "inconclusive");

  if (advisories.length > 0) {
    return {
      verdict: "advisory",
      scannedRoots: existingRoots,
      advisories,
      errors,
    };
  }
  if (hasError) {
    return {
      verdict: "error",
      scannedRoots: existingRoots,
      advisories,
      errors,
    };
  }
  if (hasInconclusive) {
    return {
      verdict: "inconclusive",
      scannedRoots: existingRoots,
      advisories,
      errors,
    };
  }
  return {
    verdict: "clean",
    scannedRoots: existingRoots,
    advisories,
    errors,
  };
}

export function buildScaNotice(config, outcome) {
  if (!outcome || config.mode === "disabled") {
    return undefined;
  }
  if (outcome.verdict === "unavailable" && config.warnUnavailable) {
    return {
      severity: "warn",
      message: SCA_INLINE_UNAVAILABLE_MESSAGE,
      actionSummary: buildActionSummary(outcome.action),
    };
  }
  if (outcome.verdict === "inconclusive" && config.warnInconclusive) {
    return {
      severity: "warn",
      message: SCA_INLINE_INCONCLUSIVE_MESSAGE,
      actionSummary: buildActionSummary(outcome.action),
    };
  }
  if (outcome.verdict === "advisory" && config.warnDetected) {
    return {
      severity: "warn",
      message: SCA_INLINE_ADVISORY_MESSAGE,
      actionSummary: buildActionSummary(outcome.action),
    };
  }
  return undefined;
}
