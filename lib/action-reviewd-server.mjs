import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";

const SUPPORTED_OPS = new Set([
  "status",
  "submit_request",
  "consume_approval",
  "consume_session_notes",
  "get_session_status",
  "list_pending_requests",
]);

function truncateMessage(value, maxLength = 240) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (!text) {
    return "unknown action reviewd error";
  }
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength - 3)}...`;
}

async function appendJsonLine(filePath, record) {
  if (!filePath) {
    return;
  }
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.appendFile(filePath, `${JSON.stringify(record)}\n`, "utf8");
}

function validateRequest(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("request must be a JSON object");
  }
  if (Number(payload.version) !== 1) {
    throw new Error("unsupported request version");
  }
  if (!SUPPORTED_OPS.has(String(payload.op || ""))) {
    throw new Error("unsupported operation");
  }
  return payload;
}

function createErrorResponse(reasonCode, message) {
  return {
    ok: false,
    reasonCode,
    message: truncateMessage(message),
    errors: [],
  };
}

function createSuccessResponse(response = {}) {
  return {
    ok: true,
    ...response,
  };
}

async function unlinkIfPresent(filePath) {
  try {
    await fs.unlink(filePath);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
}

async function listenServer(server, socketPath) {
  await fs.mkdir(path.dirname(socketPath), { recursive: true });
  await unlinkIfPresent(socketPath);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
}

function summarizeResponse(response = {}) {
  return {
    status: response.status || undefined,
    requestId: response.request?.requestId || response.requestId || undefined,
    approvalId: response.approval?.approvalId || response.approvalId || undefined,
    noteCount: Array.isArray(response.notes) ? response.notes.length : undefined,
    pendingCount: Number.isFinite(response?.pendingCount) ? response.pendingCount : undefined,
  };
}

export function createActionReviewdServer({
  socketPath,
  logPath,
  logger = console,
  handlers = {},
} = {}) {
  if (!socketPath) {
    throw new Error("socketPath is required");
  }

  const inflight = new Set();
  const server = net.createServer({ allowHalfOpen: true }, (socket) => {
    let buffer = "";

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
    });

    socket.on("end", () => {
      const task = (async () => {
      const startedAt = Date.now();
      let request;
      let response;
      try {
        const firstLine = buffer
          .split(/\r?\n/)
          .map((line) => line.trim())
          .find(Boolean);
        if (!firstLine) {
          response = createErrorResponse("empty_request", "empty action reviewd request");
        } else {
          request = validateRequest(JSON.parse(firstLine));
          switch (request.op) {
            case "status":
              response = createSuccessResponse(await handlers.status?.(request));
              break;
            case "submit_request":
              response = createSuccessResponse(await handlers.submitRequest?.(request));
              break;
            case "consume_approval":
              response = createSuccessResponse(await handlers.consumeApproval?.(request));
              break;
            case "consume_session_notes":
              response = createSuccessResponse(await handlers.consumeSessionNotes?.(request));
              break;
            case "get_session_status":
              response = createSuccessResponse(await handlers.getSessionStatus?.(request));
              break;
            case "list_pending_requests":
              response = createSuccessResponse(await handlers.listPendingRequests?.(request));
              break;
            default:
              response = createErrorResponse("unsupported_operation", "unsupported action reviewd operation");
              break;
          }
        }
      } catch (error) {
        response = createErrorResponse("internal_error", error);
        logger.warn?.(`[openclaw-action-reviewd] request handling failed: ${truncateMessage(error)}`);
      }

      try {
        socket.end(`${JSON.stringify(response)}\n`);
      } catch {
        socket.destroy();
      }

      if (request?.op && request.op !== "status") {
        try {
          await appendJsonLine(logPath, {
            recordedAt: new Date().toISOString(),
            durationMs: Date.now() - startedAt,
            requestId: request?.requestId || null,
            op: request?.op || "unknown",
            sessionKey: request?.sessionKey || null,
            toolName: request?.toolName || null,
            argsHash: request?.argsHash || null,
            ok: response?.ok === true,
            ...summarizeResponse(response),
          });
        } catch (error) {
          logger.warn?.(`[openclaw-action-reviewd] failed to append log: ${truncateMessage(error)}`);
        }
      }
      })();
      inflight.add(task);
      task.finally(() => {
        inflight.delete(task);
      });
    });
  });

  return {
    server,
    async listen() {
      await listenServer(server, socketPath);
    },
    async close() {
      await new Promise((resolve) => server.close(resolve));
      if (inflight.size > 0) {
        await Promise.allSettled(Array.from(inflight));
      }
      await unlinkIfPresent(socketPath);
    },
  };
}
