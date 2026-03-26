import net from "node:net";
import { randomUUID } from "node:crypto";

export const ACTION_REVIEWD_NAME = "openclaw-action-reviewd";
export const DEFAULT_ACTION_REVIEWD_SOCKET_PATH = "/run/openclaw-action-reviewd/ocs.sock";
export const DEFAULT_ACTION_REVIEWD_TIMEOUT_MS = 8000;

function normalizeMode(value) {
  const normalized = String(value || "disabled").trim().toLowerCase();
  if (normalized === "auto" || normalized === "required") {
    return normalized;
  }
  return "disabled";
}

function toPositiveInteger(value, fallback) {
  if (Number.isFinite(value) && Number(value) > 0) {
    return Math.trunc(Number(value));
  }
  return fallback;
}

export function normalizeActionReviewdConfig(raw = {}) {
  return {
    mode: normalizeMode(raw.actionReviewMode),
    socketPath:
      String(raw.actionReviewSocketPath || "").trim() || DEFAULT_ACTION_REVIEWD_SOCKET_PATH,
    timeoutMs: toPositiveInteger(raw.actionReviewTimeoutMs, DEFAULT_ACTION_REVIEWD_TIMEOUT_MS),
  };
}

export function actionReviewdEnabled(config) {
  return config?.mode === "auto" || config?.mode === "required";
}

export function actionReviewdRequired(config) {
  return config?.mode === "required";
}

export function buildActionReviewdRequest(op, params = {}) {
  return {
    version: 1,
    requestId: randomUUID(),
    op: String(op || "").trim(),
    ...params,
  };
}

function validateActionReviewdResponse(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("action reviewd returned a non-object response");
  }
  if (typeof payload.ok !== "boolean") {
    throw new Error("action reviewd response missing boolean ok field");
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
      finish(reject, new Error(`action reviewd request timed out after ${timeoutMs}ms`));
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

export async function requestActionReviewd(config, request, options = {}) {
  if (!actionReviewdEnabled(config)) {
    throw new Error("action reviewd is disabled");
  }
  const timeoutMs = toPositiveInteger(
    options.timeoutMs,
    config?.timeoutMs || DEFAULT_ACTION_REVIEWD_TIMEOUT_MS,
  );
  const socketPath =
    String(config?.socketPath || "").trim() || DEFAULT_ACTION_REVIEWD_SOCKET_PATH;
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
    throw new Error("action reviewd returned an empty response");
  }
  let parsed;
  try {
    parsed = JSON.parse(firstLine);
  } catch (error) {
    throw new Error(`action reviewd returned invalid JSON: ${String(error)}`);
  }
  return validateActionReviewdResponse(parsed);
}

export function buildRequiredActionReviewdBlockReason(daemonName = ACTION_REVIEWD_NAME) {
  return `OpenClaw Scanner blocked this action because ${daemonName} is required but unavailable.`;
}
