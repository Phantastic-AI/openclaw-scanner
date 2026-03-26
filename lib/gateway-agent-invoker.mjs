import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

function trimToUndefined(value) {
  const text = String(value || "").trim();
  return text || undefined;
}

function shellQuote(value) {
  return `'${String(value || "").replace(/'/g, `'\"'\"'`)}'`;
}

export function createGatewayAgentInvoker(config, logger = console) {
  const defaultUrl = trimToUndefined(config?.url);
  const defaultToken = trimToUndefined(config?.token);
  const openclawCommand = trimToUndefined(config?.openclawCommand);
  const defaultTimeoutMs = Number.isFinite(config?.agentTimeoutMs) && Number(config.agentTimeoutMs) > 0
    ? Math.trunc(Number(config.agentTimeoutMs))
    : 30000;

  if (!config?.autoContinue || !defaultUrl || !defaultToken || !openclawCommand) {
    return undefined;
  }

  return {
    async continueSession({ sessionKey, message, idempotencyKey, gateway }) {
      const normalizedSessionKey = trimToUndefined(sessionKey);
      const normalizedMessage = trimToUndefined(message);
      const normalizedIdempotencyKey = trimToUndefined(idempotencyKey);
      const url = trimToUndefined(gateway?.url) || defaultUrl;
      const token = trimToUndefined(gateway?.token) || defaultToken;
      const requestedTimeoutMs =
        Number.isFinite(gateway?.timeoutMs) && Number(gateway.timeoutMs) > 0
          ? Math.trunc(Number(gateway.timeoutMs))
          : 0;
      // Request-level gateway timeouts are tuned for short approval RPCs. Session
      // continuation can legitimately take longer, especially for approved exec
      // actions, so never let the forwarded request timeout shrink the continuation.
      const timeoutMs = Math.max(defaultTimeoutMs, requestedTimeoutMs);
      if (!normalizedSessionKey) {
        throw new Error("missing continuation session key");
      }
      if (!normalizedMessage) {
        throw new Error("missing continuation message");
      }
      if (!normalizedIdempotencyKey) {
        throw new Error("missing continuation idempotency key");
      }

      const params = JSON.stringify({
        message: normalizedMessage,
        sessionKey: normalizedSessionKey,
        idempotencyKey: normalizedIdempotencyKey,
      });
      const command =
        `${openclawCommand} gateway call agent ` +
        `--url ${shellQuote(url)} ` +
        `--token ${shellQuote(token)} ` +
        `--expect-final ` +
        `--timeout ${shellQuote(String(timeoutMs))} ` +
        `--json ` +
        `--params ${shellQuote(params)}`;

      logger.info?.(
        `[openclaw-action-reviewd] continuing session ${normalizedSessionKey} via gateway agent call`,
      );

      const { stdout, stderr } = await execFileAsync("bash", ["-lc", command], {
        timeout: timeoutMs + 5000,
        maxBuffer: 1024 * 1024 * 4,
      });

      if (stderr?.trim()) {
        logger.warn?.(
          `[openclaw-action-reviewd] gateway agent continuation stderr: ${stderr.trim()}`,
        );
      }

      const payload = JSON.parse(String(stdout || "").trim() || "{}");
      if (payload?.status !== "ok") {
        throw new Error(
          payload?.error?.message ||
            payload?.summary ||
            "gateway agent continuation did not complete successfully",
        );
      }
      return payload;
    },
  };
}
