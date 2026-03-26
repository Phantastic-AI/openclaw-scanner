import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import {
  detectAntivirusBackend,
  normalizeAntivirusConfig,
  runTriggeredClamdScan,
} from "./antivirus.mjs";
import {
  detectScaBackend,
  normalizeScaConfig,
  runOsvSourceScan,
} from "./sca.mjs";

const execFileAsync = promisify(execFile);

export const DEFAULT_OPENCLAW_SCAND_LOG_PATH = "/var/log/openclaw-scand/scans.jsonl";
export const DEFAULT_BWRAP_PATH = "bwrap";

function toPositiveInteger(value, fallback) {
  if (Number.isFinite(value) && Number(value) > 0) {
    return Math.trunc(Number(value));
  }
  return fallback;
}

async function pathExists(filePath) {
  try {
    await fs.stat(filePath);
    return true;
  } catch {
    return false;
  }
}

async function resolveExecutablePath(command) {
  const raw = String(command || "").trim();
  if (!raw) {
    return undefined;
  }
  if (path.isAbsolute(raw)) {
    return (await pathExists(raw)) ? raw : undefined;
  }
  try {
    const { stdout } = await execFileAsync("which", [raw], {
      timeout: 2000,
      maxBuffer: 64 * 1024,
    });
    const resolved = String(stdout || "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find(Boolean);
    return resolved || undefined;
  } catch {
    return undefined;
  }
}

export async function buildOsvBubblewrapArgs(config, rootPath) {
  const resolvedRoot = path.resolve(String(rootPath || "."));
  const resolvedOsvPath = await resolveExecutablePath(config.osvScannerPath);
  if (!resolvedOsvPath) {
    throw new Error(`osv-scanner executable not found: ${config.osvScannerPath}`);
  }

  const args = [
    "--die-with-parent",
    "--new-session",
    // OSV 2.3.5 hangs after scan completion under the tighter unshare-all profile
    // we tested on dev-security. Keep the sandbox as a read-only mount view plus
    // tmpfs scratch space until we have a tighter profile that exits cleanly.
    "--ro-bind",
    "/",
    "/",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
    "--dir",
    "/run",
    "--setenv",
    "HOME",
    "/tmp",
    "--setenv",
    "TMPDIR",
    "/tmp",
    "--chdir",
    resolvedRoot,
  ];

  args.push("--", resolvedOsvPath, "scan", "source", "-r", resolvedRoot, "--format", "json");
  return args;
}

async function runBubblewrappedOsvScan(config, rootPath) {
  const resolvedBwrapPath = await resolveExecutablePath(config.bwrapPath);
  if (!resolvedBwrapPath) {
    return {
      stdout: "",
      stderr: `bubblewrap executable not found: ${config.bwrapPath}`,
      exitCode: 127,
    };
  }
  const args = await buildOsvBubblewrapArgs(config, rootPath);
  try {
    const result = await execFileAsync(resolvedBwrapPath, args, {
      timeout: config.scanTimeoutMs,
      maxBuffer: config.maxBufferBytes,
    });
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

function normalizeMalwareVerdict(verdict) {
  if (verdict === "clean" || verdict === "infected" || verdict === "covered") {
    return verdict;
  }
  if (verdict === "unavailable") {
    return verdict;
  }
  return "error";
}

export function normalizeOpenclawScandConfig(raw = {}) {
  const antivirus = normalizeAntivirusConfig({
    antivirusMode: raw.antivirusMode || "auto",
    antivirusWarnUnavailable: raw.antivirusWarnUnavailable !== false,
    antivirusSocketPath: raw.antivirusSocketPath,
    antivirusClamdConfigPath: raw.antivirusClamdConfigPath,
    antivirusScanTimeoutMs: raw.antivirusScanTimeoutMs,
  });
  const sca = normalizeScaConfig({
    scaMode: raw.scaMode || "auto",
    scaWarnUnavailable: raw.scaWarnUnavailable !== false,
    scaWarnDetected: raw.scaWarnDetected !== false,
    scaWarnInconclusive: raw.scaWarnInconclusive !== false,
    osvScannerPath: raw.osvScannerPath,
    scaScanTimeoutMs: raw.scaScanTimeoutMs,
    scaMaxBufferBytes: raw.scaMaxBufferBytes,
  });

  return {
    socketPath: String(raw.socketPath || "").trim(),
    logPath: String(raw.logPath || "").trim() || DEFAULT_OPENCLAW_SCAND_LOG_PATH,
    bwrapPath: String(raw.bwrapPath || "").trim() || DEFAULT_BWRAP_PATH,
    antivirus,
    sca,
    version: String(raw.version || "").trim() || undefined,
  };
}

export function createOpenclawScandHandlers(config) {
  return {
    async status() {
      const [malwareScan, packageSca] = await Promise.all([
        detectAntivirusBackend(config.antivirus, []),
        detectScaBackend(config.sca),
      ]);
      return {
        backend: "openclaw-scand",
        version: config.version,
        status: {
          malwareScan: {
            engine: "clamd",
            status: malwareScan.status || "unknown",
            protection: malwareScan.protection || "unknown",
            statusMessage: malwareScan.statusMessage,
            socketPath: malwareScan.socketPath,
            clamdConfigPath: malwareScan.clamdConfigPath,
          },
          packageSca: {
            engine: packageSca.engine || "osv-scanner",
            status: packageSca.status || "unknown",
            statusMessage: packageSca.statusMessage,
            version: packageSca.version,
          },
        },
      };
    },

    async malwareScan(request) {
      const roots = Array.isArray(request?.roots) ? request.roots : [];
      const backend = await detectAntivirusBackend(config.antivirus, roots);
      if (backend.status === "unavailable") {
        return {
          backend: "clamd",
          engine: "clamd",
          status: backend.status,
          protection: backend.protection,
          statusMessage: backend.statusMessage,
          verdict: "unavailable",
          scannedPaths: [],
          findings: [],
          errors: [],
        };
      }
      if (backend.protection === "on-access") {
        return {
          backend: "clamd",
          engine: "clamd",
          status: backend.status,
          protection: backend.protection,
          statusMessage: backend.statusMessage,
          verdict: "covered",
          onAccessRoots: backend.onAccessRoots || [],
          coveredPaths: backend.coveredPaths || [],
          scannedPaths: [],
          findings: [],
          errors: [],
        };
      }

      const scan = await runTriggeredClamdScan(
        {
          ...backend,
          scanTimeoutMs: config.antivirus.scanTimeoutMs,
        },
        roots,
      );
      return {
        backend: "clamd",
        engine: "clamd",
        status: backend.status,
        protection: backend.protection,
        statusMessage: backend.statusMessage,
        verdict: normalizeMalwareVerdict(scan.verdict),
        scannedPaths: scan.scannedPaths || [],
        findings: scan.findings || [],
        errors: scan.errors || [],
      };
    },

    async packageSca(request) {
      const roots = Array.isArray(request?.roots) ? request.roots : [];
      const backend = await detectScaBackend(config.sca);
      if (backend.status === "unavailable") {
        return {
          backend: "osv-scanner",
          engine: backend.engine || "osv-scanner",
          status: backend.status,
          statusMessage: backend.statusMessage,
          verdict: "unavailable",
          scannedRoots: [],
          advisories: [],
          errors: [],
        };
      }

      const scan = await runOsvSourceScan(config.sca, roots, {
        runCommand: (runtimeConfig, rootPath) =>
          runBubblewrappedOsvScan(
            {
              ...runtimeConfig,
              bwrapPath: config.bwrapPath,
            },
            rootPath,
          ),
      });
      return {
        backend: "osv-scanner",
        engine: backend.engine || "osv-scanner",
        status: backend.status,
        statusMessage: backend.statusMessage,
        verdict: scan.verdict,
        scannedRoots: scan.scannedRoots || [],
        advisories: scan.advisories || [],
        errors: scan.errors || [],
      };
    },
  };
}
