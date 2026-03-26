import net from "node:net";
import path from "node:path";
import { randomUUID } from "node:crypto";

export const SCAN_DAEMON_NAME = "openclaw-scand";
export const DEFAULT_SCAN_DAEMON_SOCKET_PATH = "/run/openclaw-scand/ocs.sock";
export const DEFAULT_SCAN_DAEMON_TIMEOUT_MS = 8000;

function normalizeMode(value) {
  const normalized = String(value || "auto").trim().toLowerCase();
  if (normalized === "disabled" || normalized === "required") {
    return normalized;
  }
  return "auto";
}

function toPositiveInteger(value, fallback) {
  if (Number.isFinite(value) && Number(value) > 0) {
    return Math.trunc(Number(value));
  }
  return fallback;
}

function normalizeRoots(values) {
  if (!Array.isArray(values)) {
    return [];
  }
  return Array.from(
    new Set(
      values
        .map((value) => path.normalize(String(value || "").trim()))
        .filter(Boolean),
    ),
  );
}

export function normalizeScanDaemonConfig(raw = {}) {
  return {
    mode: normalizeMode(raw.scanBrokerMode),
    socketPath:
      String(raw.scanBrokerSocketPath || "").trim() || DEFAULT_SCAN_DAEMON_SOCKET_PATH,
    timeoutMs: toPositiveInteger(raw.scanBrokerTimeoutMs, DEFAULT_SCAN_DAEMON_TIMEOUT_MS),
  };
}

export function scanDaemonEnabled(config) {
  return config?.mode === "auto" || config?.mode === "required";
}

export function scanDaemonRequired(config) {
  return config?.mode === "required";
}

export function buildScanDaemonRequest({
  op,
  sessionKey,
  toolCallId,
  actionKind,
  roots,
  metadata = {},
} = {}) {
  return {
    version: 1,
    requestId: randomUUID(),
    op: String(op || "").trim(),
    sessionKey: String(sessionKey || "").trim() || undefined,
    toolCallId: String(toolCallId || "").trim() || undefined,
    actionKind: String(actionKind || "").trim() || undefined,
    roots: normalizeRoots(roots),
    ...metadata,
  };
}

export function validateScanDaemonResponse(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("scan daemon returned a non-object response");
  }
  if (typeof payload.ok !== "boolean") {
    throw new Error("scan daemon response missing boolean ok field");
  }
  return payload;
}

function requestJsonLine(socketPath, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let buffer = "";
    const socket = net.createConnection(socketPath);

    const finish = (fn, value) => {
      if (settled) {
        return;
      }
      settled = true;
      fn(value);
    };

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      finish(reject, new Error(`scan daemon request timed out after ${timeoutMs}ms`));
    });

    socket.on("error", (error) => finish(reject, error));
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
    });
    socket.on("end", () => finish(resolve, buffer));
    socket.on("close", () => finish(resolve, buffer));
    socket.on("connect", () => {
      socket.write(`${JSON.stringify(payload)}\n`);
      socket.end();
    });
  });
}

export async function requestScanDaemon(config, request, options = {}) {
  if (!scanDaemonEnabled(config)) {
    throw new Error("scan daemon is disabled");
  }
  const timeoutMs = toPositiveInteger(options.timeoutMs, config?.timeoutMs || DEFAULT_SCAN_DAEMON_TIMEOUT_MS);
  const socketPath = String(config?.socketPath || "").trim() || DEFAULT_SCAN_DAEMON_SOCKET_PATH;
  const payload = {
    version: 1,
    requestId: request?.requestId || randomUUID(),
    ...request,
  };
  const raw = await requestJsonLine(socketPath, payload, timeoutMs);
  const firstLine = String(raw || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find(Boolean);
  if (!firstLine) {
    throw new Error("scan daemon returned an empty response");
  }
  let parsed;
  try {
    parsed = JSON.parse(firstLine);
  } catch (error) {
    throw new Error(`scan daemon returned invalid JSON: ${String(error)}`);
  }
  return validateScanDaemonResponse(parsed);
}

export async function getScanDaemonStatus(config, options = {}) {
  return requestScanDaemon(
    config,
    buildScanDaemonRequest({
      op: "status",
      metadata: options.metadata,
    }),
    options,
  );
}

export function buildRequiredScanDaemonBlockReason(actionKind, daemonName = SCAN_DAEMON_NAME) {
  const normalizedAction = String(actionKind || "scan-covered").trim() || "scan-covered";
  return `OpenClaw Scanner blocked this ${normalizedAction} action because ${daemonName} is required but unavailable.`;
}
