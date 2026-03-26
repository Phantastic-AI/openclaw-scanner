import path from "node:path";

import { ActionReviewState } from "./action-reviewd-state.mjs";
import {
  classifyApprovalIntent,
  createOpenAiCompatibleIntentClassifier,
  normalizeIntentClassifierConfig,
} from "./action-reviewd-classifier.mjs";
import {
  createMattermostClient,
  createMattermostPost,
  fetchMattermostUserByUsername,
  listMattermostChannelPosts,
} from "./mattermost-client.mjs";
import {
  createGatewayApprovalResolver,
  normalizeGatewayApprovalConfig,
} from "./gateway-approval-client.mjs";
import { createGatewayAgentInvoker } from "./gateway-agent-invoker.mjs";

export const DEFAULT_OPENCLAW_ACTION_REVIEWD_SOCKET_PATH = "/run/openclaw-action-reviewd/ocs.sock";
export const DEFAULT_OPENCLAW_ACTION_REVIEWD_LOG_PATH = "/var/log/openclaw-action-reviewd/actions.jsonl";
export const DEFAULT_OPENCLAW_ACTION_REVIEWD_STORE_DIR = "/var/lib/openclaw-action-reviewd";

function asObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function normalizeStringArray(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return Array.from(
    new Set(value.map((entry) => String(entry || "").trim()).filter(Boolean)),
  );
}

function toPositiveInteger(value, fallback) {
  if (Number.isFinite(value) && Number(value) > 0) {
    return Math.trunc(Number(value));
  }
  return fallback;
}

function buildThreadReviewMessage(request, transport = {}) {
  const lines = [
    transport.hostLabel
      ? `OpenClaw requested one high-impact action on ${transport.hostLabel}.`
      : "OpenClaw requested one high-impact action.",
    request.actionSummary ? `Action: ${request.actionSummary}` : "",
    request.reason ? `Reason: ${request.reason}` : "",
    request.reasonCode ? `Reason code: ${request.reasonCode}` : "",
    request.capability ? `Capability: ${request.capability}` : "",
    `Request ID: ${request.requestId}`,
    "Reply in this thread with free text. Examples: do it, yes, no, deny, not now.",
  ];
  return lines.filter(Boolean).join("\n");
}

function buildDecisionReplyMessage(decision) {
  if (decision === "yes") {
    return "Approved. OpenClaw may retry the exact pending action once.";
  }
  if (decision === "no") {
    return "Denied. OpenClaw will keep the exact pending action blocked.";
  }
  return "That reply was unclear. The approval request is still pending.";
}

function buildGatewayExecUnclearReplyMessage() {
  return "That reply was unclear. The exec approval request is still pending.";
}

function buildApprovedSessionNote(request) {
  return (
    "OpenClaw Action Reviewd approved one pending action out of band. " +
    `You may retry only the exact approved action once.\nApproved action: ${request.actionSummary}`
  );
}

function buildDeniedSessionNote(request) {
  return (
    "OpenClaw Action Reviewd denied one pending action out of band. " +
    `Do not retry that exact action unless a reviewer later approves it.\nDenied action: ${request.actionSummary}`
  );
}

function buildUnclearSessionNote(request) {
  return (
    "OpenClaw Action Reviewd could not classify the latest reviewer reply. " +
    `The approval request is still pending.\nPending action: ${request.actionSummary}`
  );
}

function buildContinuationMessage(request, decision) {
  const lines = [];
  if (decision === "yes") {
    lines.push("An out-of-band reviewer approved exactly one pending action.");
    if (request?.actionSummary) {
      lines.push(`Approved action: ${request.actionSummary}`);
    }
    lines.push("Continue the same conversation and retry only that exact approved action now.");
    return lines.join("\n");
  }
  if (decision === "no") {
    lines.push("An out-of-band reviewer denied exactly one pending action.");
    if (request?.actionSummary) {
      lines.push(`Denied action: ${request.actionSummary}`);
    }
    lines.push("Do not retry it.");
    lines.push("Briefly explain that the action remains blocked, then continue the conversation.");
    return lines.join("\n");
  }
  lines.push("An out-of-band reviewer reply was unclear, so one pending action is still awaiting approval.");
  if (request?.actionSummary) {
    lines.push(`Pending action: ${request.actionSummary}`);
  }
  lines.push("Do not retry it.");
  lines.push("Briefly explain that approval is still pending, then continue the conversation.");
  return lines.join("\n");
}

function buildGatewayExecStateKey(approvalId) {
  return `gateway-exec:${String(approvalId || "").trim()}`;
}

function parseExecApprovalId(text) {
  const match = String(text || "").match(/^\s*ID:\s*(\S+)/m);
  return String(match?.[1] || "").trim();
}

function parseExecApprovalCommand(text) {
  const message = String(text || "");
  const fenced = message.match(/^Command:\s*\n(```[\s\S]*?```)/m);
  if (fenced?.[1]) {
    return fenced[1].replace(/^```(?:[a-z0-9_-]+)?\s*/i, "").replace(/\s*```$/i, "").trim();
  }
  const inline = message.match(/^Command:\s*`([^`]+)`/m);
  if (inline?.[1]) {
    return inline[1].trim();
  }
  const plain = message.match(/^Command:\s*(.+)$/m);
  return String(plain?.[1] || "").trim();
}

function parseForwardedExecApproval(post) {
  const message = String(post?.message || "").trim();
  if (!/^🔒\s*Exec approval required/m.test(message)) {
    return null;
  }
  const approvalId = parseExecApprovalId(message);
  if (!approvalId) {
    return null;
  }
  return {
    approvalId,
    stateKey: buildGatewayExecStateKey(approvalId),
    rootPostId: String(post?.id || "").trim(),
    channelId: String(post?.channel_id || "").trim(),
    createdAt: Number(post?.create_at || Date.now()),
    command: parseExecApprovalCommand(message),
    threadMessage: message,
  };
}

async function resolveReviewerUserIds(client, transport) {
  const resolved = new Set(normalizeStringArray(transport.reviewerUserIds));
  for (const username of normalizeStringArray(transport.reviewerUsernames)) {
    const user = await fetchMattermostUserByUsername(client, username);
    const userId = String(user?.id || "").trim();
    if (userId) {
      resolved.add(userId);
    }
  }
  return Array.from(resolved);
}

async function ensureMattermostRequestThread({ client, request, transport, reviewState }) {
  const current = reviewState.getRequest(request.requestId);
  if (current?.mattermost?.channelId && current?.mattermost?.rootPostId) {
    return current;
  }

  const post = await createMattermostPost(client, {
    channelId: transport.channelId,
    message: buildThreadReviewMessage(request, transport),
  });

  return await reviewState.setRequest(request.requestId, {
    ...current,
    mattermost: {
      channelId: String(transport.channelId || "").trim(),
      rootPostId: String(post?.id || "").trim(),
      notifiedAt: Number(post?.create_at || Date.now()),
      lastSeenPostId: String(post?.id || "").trim(),
      lastSeenCreateAt: Number(post?.create_at || Date.now()),
      lastIntent: "",
    },
  });
}

function pickLatestThreadReply(posts, stateEntry, reviewerUserIds) {
  const mattermost = stateEntry?.mattermost || {};
  const rootPostId = String(mattermost.rootPostId || "").trim();
  const lastSeenCreateAt = Number(mattermost.lastSeenCreateAt || 0);
  const notifiedAt = Number(mattermost.notifiedAt || 0);
  const allowedUsers = new Set(reviewerUserIds);
  const eligible = posts.filter((post) => {
    if (String(post?.root_id || "").trim() !== rootPostId) {
      return false;
    }
    if (!allowedUsers.has(String(post?.user_id || "").trim())) {
      return false;
    }
    const createdAt = Number(post?.create_at || 0);
    return createdAt > Math.max(lastSeenCreateAt, notifiedAt);
  });
  if (eligible.length === 0) {
    return null;
  }
  return eligible.at(-1);
}

export function normalizeOpenclawActionReviewdConfig(raw = {}) {
  const transport = asObject(raw.transport);
  return {
    socketPath:
      String(raw.socketPath || process.env.OPENCLAW_ACTION_REVIEWD_SOCKET_PATH || "").trim() ||
      DEFAULT_OPENCLAW_ACTION_REVIEWD_SOCKET_PATH,
    logPath:
      String(raw.logPath || process.env.OPENCLAW_ACTION_REVIEWD_LOG_PATH || "").trim() ||
      DEFAULT_OPENCLAW_ACTION_REVIEWD_LOG_PATH,
    storeDir:
      String(raw.storeDir || process.env.OPENCLAW_ACTION_REVIEWD_STORE_DIR || "").trim() ||
      DEFAULT_OPENCLAW_ACTION_REVIEWD_STORE_DIR,
    reviewdStateFile:
      String(raw.reviewdStateFile || process.env.OPENCLAW_ACTION_REVIEWD_STATE_FILE || "").trim() ||
      path.join(
        String(raw.storeDir || process.env.OPENCLAW_ACTION_REVIEWD_STORE_DIR || "").trim() ||
          DEFAULT_OPENCLAW_ACTION_REVIEWD_STORE_DIR,
        "reviewd-state.json",
      ),
    approvalTtlSec: toPositiveInteger(raw.approvalTtlSec, 900),
    pollIntervalMs: toPositiveInteger(raw.pollIntervalMs, 5000),
    transport:
      String(transport.kind || transport.type || "").trim().toLowerCase() === "mattermost-thread"
        ? {
            kind: "mattermost-thread",
            baseUrl:
              String(transport.baseUrl || process.env.ACTION_REVIEWD_MATTERMOST_BASE_URL || "").trim(),
            botToken:
              String(transport.botToken || process.env.ACTION_REVIEWD_MATTERMOST_BOT_TOKEN || "").trim(),
            channelId:
              String(transport.channelId || process.env.ACTION_REVIEWD_MATTERMOST_CHANNEL_ID || "").trim(),
            reviewerUserIds: normalizeStringArray(
              transport.reviewerUserIds ||
                String(process.env.ACTION_REVIEWD_MATTERMOST_REVIEWER_USER_IDS || "")
                  .split(",")
                  .map((item) => item.trim())
                  .filter(Boolean),
            ),
            reviewerUsernames: normalizeStringArray(
              transport.reviewerUsernames ||
                String(process.env.ACTION_REVIEWD_MATTERMOST_REVIEWER_USERNAMES || "")
                  .split(",")
                  .map((item) => item.trim())
                  .filter(Boolean),
            ),
            hostLabel: String(transport.hostLabel || process.env.ACTION_REVIEWD_HOST_LABEL || "").trim(),
          }
        : { kind: "" },
    gateway: normalizeGatewayApprovalConfig(raw.gateway || raw.gatewayRpc || {}),
    classifier: normalizeIntentClassifierConfig(raw.classifier),
    version: String(raw.version || "").trim() || undefined,
  };
}

export async function createOpenclawActionReviewdContext(config, logger = console) {
  const state = new ActionReviewState({
    dir: config.storeDir,
  });
  await state.init();
  const reviewState = new (await import("./reviewd-state.mjs")).ReviewdStateStore({
    filePath: config.reviewdStateFile,
  });
  await reviewState.init();
  const classifier = createOpenAiCompatibleIntentClassifier(config.classifier);
  return {
    config,
    logger,
    state,
    reviewState,
    classifier,
    gatewayApprovalResolver: createGatewayApprovalResolver(config.gateway),
    gatewayAgentInvoker: createGatewayAgentInvoker(config.gateway, logger),
  };
}

export function createOpenclawActionReviewdHandlers(context) {
  return {
    async status() {
      return {
        backend: "openclaw-action-reviewd",
        version: context.config.version,
        status: {
          approvalService: "active",
          transport: context.config.transport.kind || "disabled",
          classifier: context.config.classifier.kind || "heuristic",
          ...(await context.state.getStatus()),
        },
      };
    },

    async submitRequest(request) {
      return await context.state.submitOrCheckRequest({
        sessionKey: request?.sessionKey,
        toolName: request?.toolName,
        argsHash: request?.argsHash,
        capability: request?.capability,
        actionSummary: request?.actionSummary,
        reasonCode: request?.reasonCode,
        reason: request?.reason,
        source: request?.source,
        gateway: request?.gateway,
      });
    },

    async consumeApproval(request) {
      const approval = await context.state.consumeApproval({
        sessionKey: request?.sessionKey,
        toolName: request?.toolName,
        argsHash: request?.argsHash,
        actor: request?.actor || "plugin:openclaw-scanner",
      });
      return {
        status: approval ? "approved" : "none",
        approval,
      };
    },

    async consumeSessionNotes(request) {
      return {
        notes: await context.state.consumeSessionNotes(String(request?.sessionKey || "").trim()),
      };
    },

    async getSessionStatus(request) {
      return {
        request: await context.state.getSessionSummaryFresh(String(request?.sessionKey || "").trim()),
      };
    },

    async listPendingRequests() {
      return {
        requests: await context.state.listPendingRequestsFresh(),
      };
    },
  };
}

export async function runMattermostThreadReviewCycle(context) {
  const transport = context.config.transport;
  if (
    transport.kind !== "mattermost-thread" ||
    !transport.baseUrl ||
    !transport.botToken ||
    !transport.channelId
  ) {
    return;
  }

  const client = createMattermostClient({
    baseUrl: transport.baseUrl,
    botToken: transport.botToken,
  });
  const reviewerUserIds = await resolveReviewerUserIds(client, transport);
  if (reviewerUserIds.length === 0) {
    throw new Error("mattermost-thread transport requires at least one reviewer user");
  }

  const pendingRequests = await context.state.listPendingRequestsFresh();
  for (const request of pendingRequests) {
    await ensureMattermostRequestThread({
      client,
      request,
      transport,
      reviewState: context.reviewState,
    });
  }

  const posts = await listMattermostChannelPosts(client, transport.channelId, { perPage: 100 });
  for (const request of pendingRequests) {
    const stateEntry = context.reviewState.getRequest(request.requestId);
    if (!stateEntry?.mattermost?.rootPostId) {
      continue;
    }
    const reply = pickLatestThreadReply(posts, stateEntry, reviewerUserIds);
    if (!reply) {
      continue;
    }
    const classification = await classifyApprovalIntent({
      replyText: String(reply?.message || "").trim(),
      actionSummary: request.actionSummary,
      reason: request.reason,
      threadMessage: buildThreadReviewMessage(request, transport),
      classifier: context.classifier,
    });
    const actor = `reviewd:mattermost-thread:${String(reply?.user_id || "unknown").trim() || "unknown"}`;

    if (classification.decision === "yes") {
      await context.state.approveRequest(request.requestId, {
        ttlSec: context.config.approvalTtlSec,
        actor,
        noteMessage: buildApprovedSessionNote(request),
      });
    } else if (classification.decision === "no") {
      await context.state.denyRequest(request.requestId, {
        actor,
        noteMessage: buildDeniedSessionNote(request),
      });
    } else {
      await context.state.noteUnclearRequest(request.requestId, {
        actor,
        noteMessage: buildUnclearSessionNote(request),
      });
    }

    let continuation = stateEntry?.continuation;
    if (context.gatewayAgentInvoker) {
      const attemptedAt = Date.now();
      try {
        const response = await context.gatewayAgentInvoker.continueSession({
          sessionKey: request.sessionKey,
          message: buildContinuationMessage(request, classification.decision),
          idempotencyKey: `action-reviewd:${request.requestId}:${classification.decision}`,
          gateway: request.gateway,
        });
        continuation = {
          decision: classification.decision,
          attemptedAt,
          status: "ok",
          runId: response?.runId || null,
          summary: response?.summary || null,
        };
      } catch (error) {
        continuation = {
          decision: classification.decision,
          attemptedAt,
          status: "error",
          error: String(error),
        };
        context.logger.warn?.(
          `[openclaw-action-reviewd] failed to continue session ${request.sessionKey}: ${String(error)}`,
        );
      }
    }

    await createMattermostPost(client, {
      channelId: transport.channelId,
      rootId: stateEntry.mattermost.rootPostId,
      message: buildDecisionReplyMessage(classification.decision),
    });

    await context.reviewState.setRequest(request.requestId, {
      ...stateEntry,
      mattermost: {
        ...stateEntry.mattermost,
        lastSeenPostId: String(reply?.id || stateEntry.mattermost.lastSeenPostId || "").trim(),
        lastSeenCreateAt: Number(reply?.create_at || stateEntry.mattermost.lastSeenCreateAt || Date.now()),
        lastIntent: classification.decision,
      },
      continuation,
    });
  }

  const forwardedExecApprovals = posts
    .filter((post) => !String(post?.root_id || "").trim())
    .map((post) => parseForwardedExecApproval(post))
    .filter(Boolean);

  for (const approval of forwardedExecApprovals) {
    const existingEntry = context.reviewState.getRequest(approval.stateKey);
    const stateEntry =
      existingEntry?.mattermost?.rootPostId
        ? existingEntry
        : await context.reviewState.setRequest(approval.stateKey, {
        kind: "gateway-exec-approval",
        gatewayExec: {
          approvalId: approval.approvalId,
          command: approval.command,
          state: "pending",
        },
        mattermost: {
          channelId: approval.channelId,
          rootPostId: approval.rootPostId,
          notifiedAt: approval.createdAt,
          lastSeenPostId: approval.rootPostId,
          lastSeenCreateAt: approval.createdAt,
          lastIntent: "",
        },
        });

    if (stateEntry?.gatewayExec?.state === "approved" || stateEntry?.gatewayExec?.state === "denied") {
      continue;
    }

    const reply = pickLatestThreadReply(posts, stateEntry, reviewerUserIds);
    if (!reply) {
      continue;
    }

    const classification = await classifyApprovalIntent({
      replyText: String(reply?.message || "").trim(),
      actionSummary: approval.command ? `run shell command: ${approval.command}` : "run exec command",
      reason: "OpenClaw exec approval required",
      threadMessage: approval.threadMessage,
      classifier: context.classifier,
    });

    const nextState = {
      ...stateEntry,
      gatewayExec: {
        ...stateEntry.gatewayExec,
        approvalId: approval.approvalId,
        command: approval.command,
      },
      mattermost: {
        ...stateEntry.mattermost,
        lastSeenPostId: String(reply?.id || stateEntry.mattermost?.lastSeenPostId || "").trim(),
        lastSeenCreateAt: Number(reply?.create_at || stateEntry.mattermost?.lastSeenCreateAt || Date.now()),
        lastIntent: classification.decision,
      },
    };

    if (classification.decision === "yes" || classification.decision === "no") {
      if (!context.gatewayApprovalResolver) {
        throw new Error("gateway exec approval resolver is not configured");
      }
      const decision = classification.decision === "yes" ? "allow-once" : "deny";
      await context.gatewayApprovalResolver.resolveApproval(approval.approvalId, decision);
      await context.reviewState.setRequest(approval.stateKey, {
        ...nextState,
        gatewayExec: {
          ...nextState.gatewayExec,
          state: classification.decision === "yes" ? "approved" : "denied",
          decision,
          resolvedAt: Date.now(),
        },
      });
      continue;
    }

    await createMattermostPost(client, {
      channelId: transport.channelId,
      rootId: stateEntry.mattermost.rootPostId,
      message: buildGatewayExecUnclearReplyMessage(),
    });
    await context.reviewState.setRequest(approval.stateKey, nextState);
  }
}
