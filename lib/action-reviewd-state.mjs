import fs from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";

const DEFAULT_LOCK_TIMEOUT_MS = 5000;
const DEFAULT_LOCK_POLL_MS = 25;
const DEFAULT_LOCK_STALE_MS = 30000;

async function sleep(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

function clone(value) {
  return structuredClone(value);
}

function normalizeGatewayTarget(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const url = String(value.url || "").trim();
  const token = String(value.token || "").trim();
  if (!url || !token) {
    return undefined;
  }
  const timeoutMs =
    Number.isFinite(value.timeoutMs) && Number(value.timeoutMs) > 0
      ? Math.trunc(Number(value.timeoutMs))
      : undefined;
  return {
    url,
    token,
    ...(timeoutMs ? { timeoutMs } : {}),
  };
}

async function loadJsonArray(filePath) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    if (error?.code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

async function loadJsonLines(filePath) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return raw
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (error) {
    if (error?.code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

async function writeJsonAtomic(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await fs.rename(tempPath, filePath);
}

async function appendJsonLine(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.appendFile(filePath, `${JSON.stringify(value)}\n`, "utf8");
}

function findRequestById(requests, requestId) {
  return requests.find((request) => request.requestId === requestId);
}

function findApprovalById(approvals, approvalId) {
  return approvals.find((approval) => approval.approvalId === approvalId);
}

function findMatchingRequest(requests, { sessionKey, toolName, argsHash }) {
  return requests.find(
    (request) =>
      request.sessionKey === (sessionKey || "") &&
      request.toolName === (toolName || "") &&
      request.argsHash === (argsHash || ""),
  );
}

function findMatchingActiveApproval(approvals, { sessionKey, toolName, argsHash }) {
  return approvals.find(
    (approval) =>
      approval.state === "active" &&
      approval.sessionKey === (sessionKey || "") &&
      approval.toolName === (toolName || "") &&
      approval.argsHash === (argsHash || ""),
  );
}

function expireActiveApprovals(approvals, now) {
  let changed = false;
  for (const approval of approvals) {
    if (approval.state !== "active") {
      continue;
    }
    if (typeof approval.expiresAt === "number" && approval.expiresAt <= now) {
      approval.state = "expired";
      approval.updatedAt = now;
      changed = true;
    }
  }
  return changed;
}

async function clearStaleLock(lockPath, staleMs) {
  try {
    const stat = await fs.stat(lockPath);
    if (Date.now() - stat.mtimeMs < staleMs) {
      return false;
    }
    await fs.rm(lockPath, { recursive: true, force: true });
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

async function withDirectoryLock(
  lockPath,
  fn,
  {
    timeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
    pollMs = DEFAULT_LOCK_POLL_MS,
    staleMs = DEFAULT_LOCK_STALE_MS,
  } = {},
) {
  const startedAt = Date.now();
  while (true) {
    try {
      await fs.mkdir(lockPath);
      break;
    } catch (error) {
      if (error?.code !== "EEXIST") {
        throw error;
      }
      await clearStaleLock(lockPath, staleMs);
      if (Date.now() - startedAt >= timeoutMs) {
        throw new Error(`timed out waiting for action reviewd state lock: ${lockPath}`);
      }
      await sleep(pollMs);
    }
  }

  try {
    return await fn();
  } finally {
    await fs.rm(lockPath, { recursive: true, force: true });
  }
}

function newestFirst(left, right) {
  return (right.updatedAt || right.createdAt || 0) - (left.updatedAt || left.createdAt || 0);
}

export class ActionReviewState {
  constructor({ dir, auditFileName = "audit.jsonl", now = () => Date.now() }) {
    this.dir = String(dir || "").trim();
    this.now = now;
    this.requestsPath = path.join(this.dir, "requests.json");
    this.approvalsPath = path.join(this.dir, "approvals.json");
    this.notesPath = path.join(this.dir, "notes.json");
    this.auditPath = path.join(this.dir, auditFileName);
    this.lockPath = path.join(this.dir, ".state.lock");
    this.requests = [];
    this.approvals = [];
    this.notes = [];
  }

  async init() {
    await fs.mkdir(this.dir, { recursive: true });
    await this.loadSnapshot();
  }

  setCache(snapshot) {
    this.requests = clone(snapshot.requests);
    this.approvals = clone(snapshot.approvals);
    this.notes = clone(snapshot.notes);
  }

  async readSnapshot() {
    const [requests, approvals, notes] = await Promise.all([
      loadJsonArray(this.requestsPath),
      loadJsonArray(this.approvalsPath),
      loadJsonArray(this.notesPath),
    ]);
    return { requests, approvals, notes };
  }

  async loadSnapshot() {
    const snapshot = await this.readSnapshot();
    this.setCache(snapshot);
    return snapshot;
  }

  createAuditEvent(eventType, details = {}) {
    return {
      eventId: `evt_${randomUUID()}`,
      eventType,
      recordedAt: this.now(),
      ...details,
    };
  }

  async withLockedState(mutator) {
    await fs.mkdir(this.dir, { recursive: true });
    return await withDirectoryLock(this.lockPath, async () => {
      const snapshot = await this.readSnapshot();
      const outcome = (await mutator(snapshot)) || {};
      if (outcome.changedRequests) {
        await writeJsonAtomic(this.requestsPath, snapshot.requests);
      }
      if (outcome.changedApprovals) {
        await writeJsonAtomic(this.approvalsPath, snapshot.approvals);
      }
      if (outcome.changedNotes) {
        await writeJsonAtomic(this.notesPath, snapshot.notes);
      }
      const auditEvents = Array.isArray(outcome.auditEvents) ? outcome.auditEvents : [];
      for (const event of auditEvents) {
        await appendJsonLine(this.auditPath, event);
      }
      this.setCache(snapshot);
      return outcome.result === undefined ? undefined : clone(outcome.result);
    });
  }

  async listPendingRequestsFresh() {
    const snapshot = await this.loadSnapshot();
    const pending = snapshot.requests
      .filter((request) => request.state === "pending")
      .sort(newestFirst);
    return clone(pending);
  }

  async listAuditEventsFresh() {
    return await loadJsonLines(this.auditPath);
  }

  async getSessionSummaryFresh(sessionKey) {
    const snapshot = await this.loadSnapshot();
    const requests = snapshot.requests
      .filter((request) => request.sessionKey === (sessionKey || ""))
      .sort(newestFirst);
    return clone(requests[0]);
  }

  async consumeSessionNotes(sessionKey) {
    return await this.withLockedState((snapshot) => {
      const notes = snapshot.notes.filter((note) => note.sessionKey === (sessionKey || ""));
      if (notes.length === 0) {
        return { result: [] };
      }
      snapshot.notes = snapshot.notes.filter((note) => note.sessionKey !== (sessionKey || ""));
      return {
        changedNotes: true,
        result: notes.sort(newestFirst),
      };
    });
  }

  async submitOrCheckRequest({
    sessionKey,
    toolName,
    argsHash,
    capability,
    actionSummary,
    reasonCode,
    reason,
    source,
    gateway,
  }) {
    return await this.withLockedState((snapshot) => {
      const now = this.now();
      const changedApprovals = expireActiveApprovals(snapshot.approvals, now);
      const activeApproval = findMatchingActiveApproval(snapshot.approvals, {
        sessionKey,
        toolName,
        argsHash,
      });
      if (activeApproval) {
        return {
          changedApprovals,
          result: { status: "approved", approval: activeApproval },
        };
      }

      const existing = findMatchingRequest(snapshot.requests, {
        sessionKey,
        toolName,
        argsHash,
      });
      if (existing) {
        if (existing.state === "approved") {
          existing.state = "pending";
        }
        existing.capability = capability;
        existing.actionSummary = actionSummary;
        existing.reasonCode = reasonCode;
        existing.reason = reason;
        existing.source = source;
        existing.gateway = normalizeGatewayTarget(gateway);
        existing.updatedAt = now;
        return {
          changedRequests: true,
          changedApprovals,
          result: { status: existing.state, request: existing },
        };
      }

      const request = {
        requestId: `req_${randomUUID()}`,
        sessionKey: String(sessionKey || "").trim(),
        toolName: String(toolName || "").trim(),
        argsHash: String(argsHash || "").trim(),
        capability: String(capability || "").trim(),
        actionSummary: String(actionSummary || "").trim(),
        reasonCode: String(reasonCode || "").trim(),
        reason: String(reason || "").trim(),
        source: String(source || "").trim(),
        gateway: normalizeGatewayTarget(gateway),
        state: "pending",
        createdAt: now,
        updatedAt: now,
      };
      snapshot.requests.push(request);
      return {
        changedRequests: true,
        changedApprovals,
        result: { status: "pending", request },
        auditEvents: [
          this.createAuditEvent("request_created", {
            requestId: request.requestId,
            actor: "plugin:openclaw-scanner",
            details: {
              sessionKey: request.sessionKey,
              toolName: request.toolName,
              argsHash: request.argsHash,
            },
          }),
        ],
      };
    });
  }

  async approveRequest(requestId, { ttlSec, actor, noteMessage } = {}) {
    return await this.withLockedState((snapshot) => {
      const request = findRequestById(snapshot.requests, requestId);
      if (!request) {
        throw new Error(`unknown request: ${requestId}`);
      }
      const now = this.now();
      expireActiveApprovals(snapshot.approvals, now);
      request.state = "approved";
      request.updatedAt = now;

      let approval = snapshot.approvals.find(
        (candidate) => candidate.requestId === request.requestId && candidate.state === "active",
      );
      if (!approval) {
        approval = {
          approvalId: `apr_${randomUUID()}`,
          requestId: request.requestId,
          sessionKey: request.sessionKey,
          toolName: request.toolName,
          argsHash: request.argsHash,
          remainingUses: 1,
          expiresAt: now + Number(ttlSec || 900) * 1000,
          state: "active",
          grantedBy: String(actor || "").trim() || "reviewd:manual",
          createdAt: now,
          updatedAt: now,
        };
        snapshot.approvals.push(approval);
      }

      if (noteMessage) {
        snapshot.notes.push({
          noteId: `note_${randomUUID()}`,
          sessionKey: request.sessionKey,
          message: String(noteMessage || "").trim(),
          createdAt: now,
          updatedAt: now,
        });
      }

      return {
        changedRequests: true,
        changedApprovals: true,
        changedNotes: Boolean(noteMessage),
        result: { request, approval },
        auditEvents: [
          this.createAuditEvent("approval_granted", {
            requestId: request.requestId,
            approvalId: approval.approvalId,
            actor: String(actor || "").trim() || "reviewd:manual",
          }),
        ],
      };
    });
  }

  async denyRequest(requestId, { actor, noteMessage } = {}) {
    return await this.withLockedState((snapshot) => {
      const request = findRequestById(snapshot.requests, requestId);
      if (!request) {
        throw new Error(`unknown request: ${requestId}`);
      }
      const now = this.now();
      request.state = "denied";
      request.updatedAt = now;
      if (noteMessage) {
        snapshot.notes.push({
          noteId: `note_${randomUUID()}`,
          sessionKey: request.sessionKey,
          message: String(noteMessage || "").trim(),
          createdAt: now,
          updatedAt: now,
        });
      }
      return {
        changedRequests: true,
        changedNotes: Boolean(noteMessage),
        result: request,
        auditEvents: [
          this.createAuditEvent("request_denied", {
            requestId: request.requestId,
            actor: String(actor || "").trim() || "reviewd:manual",
          }),
        ],
      };
    });
  }

  async noteUnclearRequest(requestId, { actor, noteMessage } = {}) {
    if (!noteMessage) {
      return undefined;
    }
    return await this.withLockedState((snapshot) => {
      const request = findRequestById(snapshot.requests, requestId);
      if (!request) {
        throw new Error(`unknown request: ${requestId}`);
      }
      const now = this.now();
      request.updatedAt = now;
      snapshot.notes.push({
        noteId: `note_${randomUUID()}`,
        sessionKey: request.sessionKey,
        message: String(noteMessage || "").trim(),
        createdAt: now,
        updatedAt: now,
      });
      return {
        changedRequests: true,
        changedNotes: true,
        result: request,
        auditEvents: [
          this.createAuditEvent("request_unclear", {
            requestId: request.requestId,
            actor: String(actor || "").trim() || "reviewd:manual",
          }),
        ],
      };
    });
  }

  async consumeApproval({ sessionKey, toolName, argsHash, actor }) {
    return await this.withLockedState((snapshot) => {
      const changedApprovals = expireActiveApprovals(snapshot.approvals, this.now());
      const approval = findMatchingActiveApproval(snapshot.approvals, {
        sessionKey,
        toolName,
        argsHash,
      });
      if (!approval) {
        return {
          changedApprovals,
          result: undefined,
        };
      }
      approval.remainingUses = 0;
      approval.state = "used";
      approval.updatedAt = this.now();
      return {
        changedApprovals: true,
        result: approval,
        auditEvents: [
          this.createAuditEvent("approval_used", {
            requestId: approval.requestId,
            approvalId: approval.approvalId,
            actor: String(actor || "").trim() || "plugin:openclaw-scanner",
          }),
        ],
      };
    });
  }

  async getStatus() {
    const snapshot = await this.loadSnapshot();
    expireActiveApprovals(snapshot.approvals, this.now());
    const pendingCount = snapshot.requests.filter((request) => request.state === "pending").length;
    const deniedCount = snapshot.requests.filter((request) => request.state === "denied").length;
    const activeApprovalCount = snapshot.approvals.filter((approval) => approval.state === "active").length;
    return {
      pendingCount,
      deniedCount,
      activeApprovalCount,
      totalRequests: snapshot.requests.length,
      totalApprovals: snapshot.approvals.length,
    };
  }
}
