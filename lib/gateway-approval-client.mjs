import { randomUUID } from "node:crypto";

const PROTOCOL_VERSION = 3;
const DEFAULT_GATEWAY_RPC_TIMEOUT_MS = 10000;
const DEFAULT_CONNECT_DELAY_MS = 150;
const DEFAULT_GATEWAY_AGENT_TIMEOUT_MS = 30000;

function toPositiveInteger(value, fallback) {
  if (Number.isFinite(value) && Number(value) > 0) {
    return Math.trunc(Number(value));
  }
  return fallback;
}

function trimToUndefined(value) {
  const text = String(value || "").trim();
  return text || undefined;
}

function toBoolean(value, fallback) {
  if (typeof value === "boolean") {
    return value;
  }
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) {
    return fallback;
  }
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return fallback;
}

function isLoopbackGatewayUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return ["127.0.0.1", "localhost", "::1"].includes(url.hostname);
  } catch {
    return false;
  }
}

export function normalizeGatewayApprovalConfig(raw = {}) {
  const url =
    trimToUndefined(raw.url) ||
    trimToUndefined(process.env.OPENCLAW_ACTION_REVIEWD_GATEWAY_URL) ||
    undefined;
  const token =
    trimToUndefined(raw.token) ||
    trimToUndefined(process.env.OPENCLAW_ACTION_REVIEWD_GATEWAY_TOKEN) ||
    undefined;
  const role = trimToUndefined(raw.role) || "operator";
  const scopes = Array.isArray(raw.scopes) && raw.scopes.length > 0 ? raw.scopes : ["operator.approvals"];
  return {
    kind: url && token ? "gateway-rpc" : "",
    url,
    token,
    role,
    scopes,
    timeoutMs: toPositiveInteger(
      raw.timeoutMs || process.env.OPENCLAW_ACTION_REVIEWD_GATEWAY_TIMEOUT_MS,
      DEFAULT_GATEWAY_RPC_TIMEOUT_MS,
    ),
    connectDelayMs: toPositiveInteger(
      raw.connectDelayMs || process.env.OPENCLAW_ACTION_REVIEWD_GATEWAY_CONNECT_DELAY_MS,
      DEFAULT_CONNECT_DELAY_MS,
    ),
    clientId: trimToUndefined(raw.clientId) || "openclaw-action-reviewd",
    clientDisplayName: trimToUndefined(raw.clientDisplayName) || "OpenClaw Action Reviewd",
    clientVersion: trimToUndefined(raw.clientVersion) || undefined,
    autoContinue: toBoolean(raw.autoContinue || process.env.OPENCLAW_ACTION_REVIEWD_AUTO_CONTINUE, true),
    openclawCommand:
      trimToUndefined(raw.openclawCommand) ||
      trimToUndefined(raw.agentCommand) ||
      trimToUndefined(process.env.OPENCLAW_ACTION_REVIEWD_OPENCLAW_CMD) ||
      "openclaw",
    agentTimeoutMs: toPositiveInteger(
      raw.agentTimeoutMs || process.env.OPENCLAW_ACTION_REVIEWD_AGENT_TIMEOUT_MS,
      DEFAULT_GATEWAY_AGENT_TIMEOUT_MS,
    ),
  };
}

function ensureGatewaySecurity(config) {
  if (!config?.url) {
    throw new Error("gateway approval url is required");
  }
  if (!config?.token) {
    throw new Error("gateway approval token is required");
  }
  if (config.url.startsWith("ws://") && !isLoopbackGatewayUrl(config.url)) {
    throw new Error("gateway approval url must use wss:// unless it targets loopback");
  }
}

function buildConnectParams(config, connectNonce) {
  return {
    minProtocol: PROTOCOL_VERSION,
    maxProtocol: PROTOCOL_VERSION,
    client: {
      id: config.clientId || "openclaw-action-reviewd",
      displayName: config.clientDisplayName || "OpenClaw Action Reviewd",
      version: config.clientVersion || "dev",
      platform: process.platform,
      mode: "backend",
    },
    caps: [],
    auth: {
      token: config.token,
    },
    role: config.role || "operator",
    scopes: Array.isArray(config.scopes) && config.scopes.length > 0 ? config.scopes : ["operator.approvals"],
    ...(connectNonce ? { device: undefined } : {}),
  };
}

export async function callGatewayApprovalRpc(config, method, params = {}) {
  ensureGatewaySecurity(config);
  const timeoutMs = toPositiveInteger(config.timeoutMs, DEFAULT_GATEWAY_RPC_TIMEOUT_MS);
  const connectDelayMs = toPositiveInteger(config.connectDelayMs, DEFAULT_CONNECT_DELAY_MS);

  return await new Promise((resolve, reject) => {
    let settled = false;
    let connectSent = false;
    let connectNonce;
    let connectRequestId = null;
    let methodRequestId = null;
    let connectTimer = null;

    const finish = (error, value) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      if (connectTimer) {
        clearTimeout(connectTimer);
      }
      try {
        socket.close();
      } catch {}
      if (error) {
        reject(error);
        return;
      }
      resolve(value);
    };

    const timeout = setTimeout(() => {
      finish(new Error(`gateway approval RPC timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    const socket = new WebSocket(config.url);

    const sendFrame = (frame) => {
      socket.send(JSON.stringify(frame));
    };

    const sendConnect = () => {
      if (connectSent || socket.readyState !== WebSocket.OPEN) {
        return;
      }
      connectSent = true;
      connectRequestId = randomUUID();
      sendFrame({
        type: "req",
        id: connectRequestId,
        method: "connect",
        params: buildConnectParams(config, connectNonce),
      });
    };

    socket.addEventListener("open", () => {
      connectTimer = setTimeout(() => {
        sendConnect();
      }, connectDelayMs);
    });

    socket.addEventListener("error", (event) => {
      finish(new Error(`gateway approval websocket error: ${String(event?.message || "unknown error")}`));
    });

    socket.addEventListener("close", (event) => {
      if (!settled) {
        finish(new Error(`gateway approval websocket closed: ${event.code} ${event.reason || ""}`.trim()));
      }
    });

    socket.addEventListener("message", (event) => {
      let frame;
      try {
        frame = JSON.parse(String(event.data || ""));
      } catch (error) {
        finish(new Error(`gateway approval websocket returned invalid JSON: ${String(error)}`));
        return;
      }

      if (frame?.type === "evt" && frame?.event === "connect.challenge") {
        const nonce = String(frame?.payload?.nonce || "").trim();
        if (nonce) {
          connectNonce = nonce;
        }
        sendConnect();
        return;
      }

      if (frame?.type !== "res" || typeof frame.id !== "string") {
        return;
      }

      if (frame.id === connectRequestId) {
        if (frame.ok !== true) {
          finish(new Error(frame?.error?.message || "gateway connect failed"));
          return;
        }
        methodRequestId = randomUUID();
        sendFrame({
          type: "req",
          id: methodRequestId,
          method,
          params,
        });
        return;
      }

      if (frame.id !== methodRequestId) {
        return;
      }

      if (frame.ok !== true) {
        finish(new Error(frame?.error?.message || `${method} failed`));
        return;
      }
      finish(null, frame.payload);
    });
  });
}

export function createGatewayApprovalResolver(config) {
  const normalized = normalizeGatewayApprovalConfig(config);
  if (normalized.kind !== "gateway-rpc") {
    return undefined;
  }
  return {
    config: normalized,
    async resolveApproval(approvalId, decision) {
      const normalizedApprovalId = String(approvalId || "").trim();
      if (!normalizedApprovalId) {
        throw new Error("missing exec approval id");
      }
      const normalizedDecision = String(decision || "").trim();
      if (!["allow-once", "deny"].includes(normalizedDecision)) {
        throw new Error(`unsupported exec approval decision: ${normalizedDecision}`);
      }
      return await callGatewayApprovalRpc(normalized, "exec.approval.resolve", {
        id: normalizedApprovalId,
        decision: normalizedDecision,
      });
    },
  };
}
