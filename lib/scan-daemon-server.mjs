import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";

const SUPPORTED_OPS = new Set(["status", "malware_scan", "package_sca"]);

function truncateMessage(value, maxLength = 240) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (!text) {
    return "unknown scan daemon error";
  }
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength - 3)}...`;
}

function summarizeResponse(response = {}) {
  return {
    backend: response.backend || undefined,
    status: response.status || undefined,
    protection: response.protection || undefined,
    verdict: response.verdict || undefined,
    reasonCode: response.reasonCode || undefined,
    advisoryCount: Array.isArray(response.advisories) ? response.advisories.length : undefined,
    findingCount: Array.isArray(response.findings) ? response.findings.length : undefined,
    errorCount: Array.isArray(response.errors) ? response.errors.length : undefined,
    scannedRoots: Array.isArray(response.scannedRoots) ? response.scannedRoots.length : undefined,
    scannedPaths: Array.isArray(response.scannedPaths) ? response.scannedPaths.length : undefined,
  };
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

export function createScanDaemonServer({
  socketPath,
  logPath,
  logger = console,
  handlers = {},
} = {}) {
  if (!socketPath) {
    throw new Error("socketPath is required");
  }

  const server = net.createServer({ allowHalfOpen: true }, (socket) => {
    let buffer = "";

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
    });

    socket.on("end", async () => {
      const startedAt = Date.now();
      let request;
      let response;
      try {
        const firstLine = buffer
          .split(/\r?\n/)
          .map((line) => line.trim())
          .find(Boolean);
        if (!firstLine) {
          response = createErrorResponse("empty_request", "empty scan daemon request");
        } else {
          request = validateRequest(JSON.parse(firstLine));
          if (request.op === "status") {
            response = createSuccessResponse(await handlers.status?.(request));
          } else if (request.op === "malware_scan") {
            response = createSuccessResponse(await handlers.malwareScan?.(request));
          } else if (request.op === "package_sca") {
            response = createSuccessResponse(await handlers.packageSca?.(request));
          } else {
            response = createErrorResponse("unsupported_operation", "unsupported scan daemon operation");
          }
        }
      } catch (error) {
        response = createErrorResponse("internal_error", error);
        logger.warn?.(`[openclaw-scand] request handling failed: ${truncateMessage(error)}`);
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
            toolCallId: request?.toolCallId || null,
            actionKind: request?.actionKind || null,
            roots: Array.isArray(request?.roots) ? request.roots : [],
            ok: response?.ok === true,
            ...summarizeResponse(response),
          });
        } catch (error) {
          logger.warn?.(`[openclaw-scand] failed to append scan-daemon log: ${truncateMessage(error)}`);
        }
      }
    });
  });

  return {
    server,
    async listen() {
      await listenServer(server, socketPath);
    },
    async close() {
      await new Promise((resolve) => server.close(resolve));
      await unlinkIfPresent(socketPath);
    },
  };
}
