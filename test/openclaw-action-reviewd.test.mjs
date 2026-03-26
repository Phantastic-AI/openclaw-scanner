import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import plugin from "../index.mjs";
import {
  buildActionReviewdRequest,
  normalizeActionReviewdConfig,
  requestActionReviewd,
} from "../lib/action-reviewd.mjs";
import { createActionReviewdServer } from "../lib/action-reviewd-server.mjs";
import {
  createOpenclawActionReviewdContext,
  createOpenclawActionReviewdHandlers,
  normalizeOpenclawActionReviewdConfig,
  runMattermostThreadReviewCycle,
} from "../lib/openclaw-action-reviewd-service.mjs";

function registerPlugin(pluginConfig = {}, fullConfig = {}, runtimeOverrides = {}) {
  const hooks = new Map();
  const logs = [];
  const stateDir =
    runtimeOverrides.state?.resolveStateDir?.() ||
    fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-scanner-action-reviewd-"));
  const api = {
    pluginConfig,
    config: {
      gateway: {
        port: 18789,
        bind: "loopback",
        auth: { mode: "token", token: "test-gateway-token" },
        http: {
          endpoints: {
            responses: { enabled: true },
          },
        },
      },
      ...fullConfig,
    },
    runtime: {
      state: {
        resolveStateDir: () => stateDir,
      },
      ...runtimeOverrides,
    },
    logger: {
      info: (msg) => logs.push(["info", msg]),
      warn: (msg) => logs.push(["warn", msg]),
      error: (msg) => logs.push(["error", msg]),
    },
    registerCli() {},
    on: (name, handler) => {
      hooks.set(name, handler);
    },
  };
  plugin.register(api);
  return { hooks, logs, stateDir };
}

async function withActionReviewd(run, configOverrides = {}) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-action-reviewd-"));
  const config = normalizeOpenclawActionReviewdConfig({
    socketPath: path.join(tempDir, "ocs.sock"),
    logPath: path.join(tempDir, "actions.jsonl"),
    storeDir: path.join(tempDir, "store"),
    reviewdStateFile: path.join(tempDir, "reviewd-state.json"),
    ...configOverrides,
  });
  const context = await createOpenclawActionReviewdContext(config, console);
  const daemon = createActionReviewdServer({
    socketPath: config.socketPath,
    logPath: config.logPath,
    handlers: createOpenclawActionReviewdHandlers(context),
  });
  await daemon.listen();
  try {
    return await run({ tempDir, config, context, daemon });
  } finally {
    await daemon.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

test("action reviewd client round-trips status over a Unix socket", async () => {
  await withActionReviewd(async ({ config }) => {
    const response = await requestActionReviewd(
      normalizeActionReviewdConfig({
        actionReviewMode: "required",
        actionReviewSocketPath: config.socketPath,
      }),
      buildActionReviewdRequest("status"),
    );
    assert.equal(response.ok, true);
    assert.equal(response.backend, "openclaw-action-reviewd");
    assert.equal(response.status.approvalService, "active");
  });
});

test("action reviewd Mattermost thread cycle classifies yes replies and grants one approval", async () => {
  await withActionReviewd(async ({ context }) => {
    await context.state.submitOrCheckRequest({
      sessionKey: "session-mm-yes",
      toolName: "sessions_send",
      argsHash: "hash-yes",
      capability: "message_send",
      actionSummary: "send message: hello",
      reasonCode: "message_send_requires_approval",
      reason: "High-impact action requires explicit human approval.",
      source: "gateway_ask",
      gateway: {
        url: "ws://127.0.0.1:18789",
        token: "gateway-token-yes",
        timeoutMs: 12345,
      },
    });

    const originalFetch = global.fetch;
    const seenPosts = [];
    const continuations = [];
    global.fetch = async (url, init = {}) => {
      const parsed = new URL(url);
      if (parsed.pathname.endsWith("/api/v4/users/username/reviewer")) {
        return Response.json({ id: "reviewer-user" });
      }
      if (parsed.pathname.endsWith("/api/v4/posts") && init.method === "POST") {
        const payload = JSON.parse(init.body);
        seenPosts.push(payload);
        return Response.json({
          id: payload.root_id ? "decision-post-1" : "root-post-1",
          channel_id: payload.channel_id,
          root_id: payload.root_id || "",
          create_at: payload.root_id ? 2000 : 1000,
        });
      }
      if (parsed.pathname.includes("/api/v4/channels/channel-1/posts")) {
        return Response.json({
          order: ["root-post-1", "reply-post-1"],
          posts: {
            "root-post-1": {
              id: "root-post-1",
              channel_id: "channel-1",
              user_id: "reviewd-bot",
              message: "root",
              create_at: 1000,
            },
            "reply-post-1": {
              id: "reply-post-1",
              root_id: "root-post-1",
              channel_id: "channel-1",
              user_id: "reviewer-user",
              message: "do it",
              create_at: 2000,
            },
          },
        });
      }
      throw new Error(`unexpected fetch: ${String(url)}`);
    };

    try {
      context.config.transport = {
        kind: "mattermost-thread",
        baseUrl: "https://chat.example.test",
        botToken: "token",
        channelId: "channel-1",
        reviewerUserIds: [],
        reviewerUsernames: ["reviewer"],
        hostLabel: "dev-security",
      };
      context.classifier = async () => ({ decision: "yes", reason: "clear approval" });
      context.gatewayAgentInvoker = {
        continueSession: async (payload) => {
          continuations.push(payload);
          return { status: "ok", runId: "run-yes", summary: "completed" };
        },
      };
      await runMattermostThreadReviewCycle(context);
    } finally {
      global.fetch = originalFetch;
    }

    const status = await context.state.getSessionSummaryFresh("session-mm-yes");
    const notes = await context.state.consumeSessionNotes("session-mm-yes");
    const consumed = await context.state.consumeApproval({
      sessionKey: "session-mm-yes",
      toolName: "sessions_send",
      argsHash: "hash-yes",
      actor: "test",
    });

    assert.equal(status.state, "approved");
    assert.match(notes[0]?.message || "", /approved one pending action out of band/i);
    assert.equal(consumed.state, "used");
    assert.equal(seenPosts.length, 2);
    assert.match(seenPosts[1]?.message || "", /Approved/i);
    assert.equal(continuations.length, 1);
    assert.equal(continuations[0].sessionKey, "session-mm-yes");
    assert.equal(
      continuations[0].message,
      "An out-of-band reviewer approved exactly one pending action.\n" +
        "Approved action: send message: hello\n" +
        "Continue the same conversation and retry only that exact approved action now.",
    );
    assert.match(continuations[0].idempotencyKey || "", /^action-reviewd:/);
    assert.deepEqual(continuations[0].gateway, {
      url: "ws://127.0.0.1:18789",
      token: "gateway-token-yes",
      timeoutMs: 12345,
    });
  });
});

test("action reviewd Mattermost thread cycle classifies no replies and continues the session with a denial note", async () => {
  await withActionReviewd(async ({ context }) => {
    await context.state.submitOrCheckRequest({
      sessionKey: "session-mm-no",
      toolName: "sessions_send",
      argsHash: "hash-no",
      capability: "message_send",
      actionSummary: "send message: hello",
      reasonCode: "message_send_requires_approval",
      reason: "High-impact action requires explicit human approval.",
      source: "gateway_ask",
    });

    const originalFetch = global.fetch;
    const continuations = [];
    global.fetch = async (url, init = {}) => {
      const parsed = new URL(url);
      if (parsed.pathname.endsWith("/api/v4/posts") && init.method === "POST") {
        const payload = JSON.parse(init.body);
        return Response.json({
          id: payload.root_id ? "decision-post-no" : "root-post-no",
          channel_id: payload.channel_id,
          root_id: payload.root_id || "",
          create_at: payload.root_id ? 2000 : 1000,
        });
      }
      if (parsed.pathname.includes("/api/v4/channels/channel-1/posts")) {
        return Response.json({
          order: ["root-post-no", "reply-post-no"],
          posts: {
            "root-post-no": {
              id: "root-post-no",
              channel_id: "channel-1",
              user_id: "reviewd-bot",
              message: "root",
              create_at: 1000,
            },
            "reply-post-no": {
              id: "reply-post-no",
              root_id: "root-post-no",
              channel_id: "channel-1",
              user_id: "reviewer-user",
              message: "no, do not run that",
              create_at: 2000,
            },
          },
        });
      }
      throw new Error(`unexpected fetch: ${String(url)}`);
    };

    try {
      context.config.transport = {
        kind: "mattermost-thread",
        baseUrl: "https://chat.example.test",
        botToken: "token",
        channelId: "channel-1",
        reviewerUserIds: ["reviewer-user"],
        reviewerUsernames: [],
        hostLabel: "dev-security",
      };
      context.classifier = async () => ({ decision: "no", reason: "clear denial" });
      context.gatewayAgentInvoker = {
        continueSession: async (payload) => {
          continuations.push(payload);
          return { status: "ok", runId: "run-no", summary: "completed" };
        },
      };
      await runMattermostThreadReviewCycle(context);
    } finally {
      global.fetch = originalFetch;
    }

    const status = await context.state.getSessionSummaryFresh("session-mm-no");
    const notes = await context.state.consumeSessionNotes("session-mm-no");

    assert.equal(status.state, "denied");
    assert.match(notes[0]?.message || "", /denied one pending action out of band/i);
    assert.equal(continuations.length, 1);
    assert.equal(continuations[0].sessionKey, "session-mm-no");
    assert.equal(
      continuations[0].message,
      "An out-of-band reviewer denied exactly one pending action.\n" +
        "Denied action: send message: hello\n" +
        "Do not retry it.\n" +
        "Briefly explain that the action remains blocked, then continue the conversation.",
    );
    assert.match(continuations[0].idempotencyKey || "", /^action-reviewd:/);
  });
});

test("action reviewd Mattermost thread cycle keeps unclear replies pending", async () => {
  await withActionReviewd(async ({ context }) => {
    await context.state.submitOrCheckRequest({
      sessionKey: "session-mm-unclear",
      toolName: "sessions_send",
      argsHash: "hash-unclear",
      capability: "message_send",
      actionSummary: "send message: hello",
      reasonCode: "message_send_requires_approval",
      reason: "High-impact action requires explicit human approval.",
      source: "gateway_ask",
    });

    const originalFetch = global.fetch;
    const continuations = [];
    global.fetch = async (url, init = {}) => {
      const parsed = new URL(url);
      if (parsed.pathname.endsWith("/api/v4/posts") && init.method === "POST") {
        const payload = JSON.parse(init.body);
        return Response.json({
          id: payload.root_id ? "decision-post-2" : "root-post-2",
          channel_id: payload.channel_id,
          root_id: payload.root_id || "",
          create_at: payload.root_id ? 2000 : 1000,
        });
      }
      if (parsed.pathname.includes("/api/v4/channels/channel-1/posts")) {
        return Response.json({
          order: ["root-post-2", "reply-post-2"],
          posts: {
            "root-post-2": {
              id: "root-post-2",
              channel_id: "channel-1",
              user_id: "reviewd-bot",
              message: "root",
              create_at: 1000,
            },
            "reply-post-2": {
              id: "reply-post-2",
              root_id: "root-post-2",
              channel_id: "channel-1",
              user_id: "reviewer-user",
              message: "hmm maybe later",
              create_at: 2000,
            },
          },
        });
      }
      throw new Error(`unexpected fetch: ${String(url)}`);
    };

    try {
      context.config.transport = {
        kind: "mattermost-thread",
        baseUrl: "https://chat.example.test",
        botToken: "token",
        channelId: "channel-1",
        reviewerUserIds: ["reviewer-user"],
        reviewerUsernames: [],
        hostLabel: "dev-security",
      };
      context.classifier = async () => ({ decision: "unclear", reason: "ambiguous" });
      context.gatewayAgentInvoker = {
        continueSession: async (payload) => {
          continuations.push(payload);
          return { status: "ok", runId: "run-unclear", summary: "completed" };
        },
      };
      await runMattermostThreadReviewCycle(context);
    } finally {
      global.fetch = originalFetch;
    }

    const status = await context.state.getSessionSummaryFresh("session-mm-unclear");
    const notes = await context.state.consumeSessionNotes("session-mm-unclear");
    const consumed = await context.state.consumeApproval({
      sessionKey: "session-mm-unclear",
      toolName: "sessions_send",
      argsHash: "hash-unclear",
      actor: "test",
    });

    assert.equal(status.state, "pending");
    assert.match(notes[0]?.message || "", /still pending/i);
    assert.equal(consumed, undefined);
    assert.equal(continuations.length, 1);
    assert.equal(continuations[0].sessionKey, "session-mm-unclear");
    assert.equal(
      continuations[0].message,
      "An out-of-band reviewer reply was unclear, so one pending action is still awaiting approval.\n" +
        "Pending action: send message: hello\n" +
        "Do not retry it.\n" +
        "Briefly explain that approval is still pending, then continue the conversation.",
    );
    assert.match(continuations[0].idempotencyKey || "", /^action-reviewd:/);
  });
});

test("action reviewd resolves forwarded gateway exec approvals from Mattermost thread replies", async () => {
  await withActionReviewd(async ({ context }) => {
    const originalFetch = global.fetch;
    const resolved = [];
    global.fetch = async (url, init = {}) => {
      const parsed = new URL(url);
      if (parsed.pathname.endsWith("/api/v4/users/username/reviewer")) {
        return Response.json({ id: "reviewer-user" });
      }
      if (parsed.pathname.includes("/api/v4/channels/channel-1/posts")) {
        return Response.json({
          order: ["exec-root-1", "exec-reply-1"],
          posts: {
            "exec-root-1": {
              id: "exec-root-1",
              channel_id: "channel-1",
              user_id: "gateway-bot",
              message:
                "🔒 Exec approval required\n" +
                "ID: approval-123\n" +
                "Command: `git push --force origin main`\n" +
                "Host: dev-security\n" +
                "Reply with: /approve <id> allow-once|allow-always|deny",
              create_at: 1000,
            },
            "exec-reply-1": {
              id: "exec-reply-1",
              root_id: "exec-root-1",
              channel_id: "channel-1",
              user_id: "reviewer-user",
              message: "do it",
              create_at: 2000,
            },
          },
        });
      }
      if (parsed.pathname.endsWith("/api/v4/posts") && init.method === "POST") {
        const payload = JSON.parse(init.body);
        return Response.json({
          id: payload.root_id ? "decision-post-3" : "root-post-3",
          channel_id: payload.channel_id,
          root_id: payload.root_id || "",
          create_at: payload.root_id ? 3000 : 1000,
        });
      }
      throw new Error(`unexpected fetch: ${String(url)}`);
    };

    try {
      context.config.transport = {
        kind: "mattermost-thread",
        baseUrl: "https://chat.example.test",
        botToken: "token",
        channelId: "channel-1",
        reviewerUserIds: [],
        reviewerUsernames: ["reviewer"],
        hostLabel: "dev-security",
      };
      context.classifier = async () => ({ decision: "yes", reason: "clear approval" });
      context.gatewayApprovalResolver = {
        resolveApproval: async (approvalId, decision) => {
          resolved.push({ approvalId, decision });
          return { ok: true };
        },
      };
      await runMattermostThreadReviewCycle(context);
    } finally {
      global.fetch = originalFetch;
    }

    const state = context.reviewState.getRequest("gateway-exec:approval-123");
    assert.deepEqual(resolved, [{ approvalId: "approval-123", decision: "allow-once" }]);
    assert.equal(state.gatewayExec.state, "approved");
    assert.equal(state.gatewayExec.decision, "allow-once");
  });
});

test("action reviewd leaves forwarded gateway exec approvals pending on unclear replies", async () => {
  await withActionReviewd(async ({ context }) => {
    const originalFetch = global.fetch;
    const seenPosts = [];
    global.fetch = async (url, init = {}) => {
      const parsed = new URL(url);
      if (parsed.pathname.endsWith("/api/v4/users/username/reviewer")) {
        return Response.json({ id: "reviewer-user" });
      }
      if (parsed.pathname.includes("/api/v4/channels/channel-1/posts")) {
        return Response.json({
          order: ["exec-root-2", "exec-reply-2"],
          posts: {
            "exec-root-2": {
              id: "exec-root-2",
              channel_id: "channel-1",
              user_id: "gateway-bot",
              message:
                "🔒 Exec approval required\n" +
                "ID: approval-456\n" +
                "Command: `git push --force origin main`\n" +
                "Host: dev-security\n" +
                "Reply with: /approve <id> allow-once|allow-always|deny",
              create_at: 1000,
            },
            "exec-reply-2": {
              id: "exec-reply-2",
              root_id: "exec-root-2",
              channel_id: "channel-1",
              user_id: "reviewer-user",
              message: "need more context first",
              create_at: 2000,
            },
          },
        });
      }
      if (parsed.pathname.endsWith("/api/v4/posts") && init.method === "POST") {
        const payload = JSON.parse(init.body);
        seenPosts.push(payload);
        return Response.json({
          id: "decision-post-4",
          channel_id: payload.channel_id,
          root_id: payload.root_id || "",
          create_at: 3000,
        });
      }
      throw new Error(`unexpected fetch: ${String(url)}`);
    };

    try {
      context.config.transport = {
        kind: "mattermost-thread",
        baseUrl: "https://chat.example.test",
        botToken: "token",
        channelId: "channel-1",
        reviewerUserIds: ["reviewer-user"],
        reviewerUsernames: [],
        hostLabel: "dev-security",
      };
      context.classifier = async () => ({ decision: "unclear", reason: "ambiguous" });
      context.gatewayApprovalResolver = {
        resolveApproval: async () => {
          throw new Error("resolver should not be called for unclear replies");
        },
      };
      await runMattermostThreadReviewCycle(context);
    } finally {
      global.fetch = originalFetch;
    }

    const state = context.reviewState.getRequest("gateway-exec:approval-456");
    assert.equal(state.gatewayExec.state, "pending");
    assert.equal(state.mattermost.lastIntent, "unclear");
    assert.match(seenPosts[0]?.message || "", /still pending/i);
  });
});

test("plugin uses action reviewd to gate ask, surface notes, and allow once after approval", async () => {
  await withActionReviewd(async ({ config, context }) => {
    const { hooks } = registerPlugin({
      actionReviewMode: "required",
      actionReviewSocketPath: config.socketPath,
    });
    const beforeToolCall = hooks.get("before_tool_call");
    const beforePromptBuild = hooks.get("before_prompt_build");
    const beforeMessageWrite = hooks.get("before_message_write");

    const event = {
      toolName: "sessions_send",
      toolCallId: "call-1",
      params: {
        channel: "default",
        text: "hello from action-reviewd",
        timeoutSeconds: 0,
      },
    };
    const ctx = {
      sessionKey: "session-plugin-approve",
      agentId: "main",
    };

    const firstAttempt = await beforeToolCall(event, ctx);
    assert.equal(firstAttempt.block, true);
    assert.match(firstAttempt.blockReason, /held one action for out-of-band review before execution/i);
    assert.match(firstAttempt.blockReason, /A reviewer must approve or deny the exact pending action/i);
    assert.match(firstAttempt.blockReason, /Replying in this chat will not approve it/i);
    assert.doesNotMatch(firstAttempt.blockReason, /\/approve/i);

    const pendingPromptResult = await beforePromptBuild(
      {
        prompt: "continue",
        messages: [],
      },
      ctx,
    );
    assert.match(pendingPromptResult?.prependContext || "", /held one action for out-of-band review before execution/i);
    assert.match(pendingPromptResult?.prependContext || "", /Reply with the exact text below and nothing else/i);
    assert.doesNotMatch(pendingPromptResult?.prependContext || "", /\/approve/i);

    const pendingReply = beforeMessageWrite(
      {
        message: {
          role: "assistant",
          content: [{ type: "text", text: "Use /approve req-123 allow-once" }],
        },
      },
      ctx,
    );
    assert.match(pendingReply?.message?.content?.[0]?.text || "", /held one action for out-of-band review before execution/i);
    assert.doesNotMatch(pendingReply?.message?.content?.[0]?.text || "", /\/approve/i);

    const request = await context.state.getSessionSummaryFresh("session-plugin-approve");
    await context.state.approveRequest(request.requestId, {
      ttlSec: 900,
      actor: "test-reviewer",
      noteMessage: "OpenClaw Action Reviewd approved one pending action out of band. You may retry only the exact approved action once.",
    });

    const promptResult = await beforePromptBuild(
      {
        prompt: "continue",
        messages: [],
      },
      ctx,
    );
    assert.match(promptResult?.prependContext || "", /approved one pending action out of band/i);

    const secondAttempt = await beforeToolCall(
      {
        ...event,
        toolCallId: "call-2",
      },
      ctx,
    );
    assert.equal(secondAttempt, undefined);

    const thirdAttempt = await beforeToolCall(
      {
        ...event,
        toolCallId: "call-3",
      },
      ctx,
    );
    assert.equal(thirdAttempt.block, true);
    assert.match(thirdAttempt.blockReason, /held one action for out-of-band review before execution/i);
  });
});

test("plugin uses action reviewd denial notes and keeps the action blocked", async () => {
  await withActionReviewd(async ({ config, context }) => {
    const { hooks } = registerPlugin({
      actionReviewMode: "required",
      actionReviewSocketPath: config.socketPath,
    });
    const beforeToolCall = hooks.get("before_tool_call");
    const beforePromptBuild = hooks.get("before_prompt_build");

    const event = {
      toolName: "sessions_send",
      toolCallId: "call-deny-1",
      params: {
        channel: "default",
        text: "deny me",
        timeoutSeconds: 0,
      },
    };
    const ctx = {
      sessionKey: "session-plugin-deny",
      agentId: "main",
    };

    const firstAttempt = await beforeToolCall(event, ctx);
    assert.equal(firstAttempt.block, true);

    const request = await context.state.getSessionSummaryFresh("session-plugin-deny");
    await context.state.denyRequest(request.requestId, {
      actor: "test-reviewer",
      noteMessage: "OpenClaw Action Reviewd denied one pending action out of band. Do not retry that exact action unless a reviewer later approves it.",
    });

    const promptResult = await beforePromptBuild(
      {
        prompt: "continue",
        messages: [],
      },
      ctx,
    );
    assert.match(promptResult?.prependContext || "", /denied one pending action/i);

    const secondAttempt = await beforeToolCall(
      {
        ...event,
        toolCallId: "call-deny-2",
      },
      ctx,
    );
    assert.equal(secondAttempt.block, true);
    assert.match(secondAttempt.blockReason, /out-of-band reviewer denied it/i);
    assert.match(secondAttempt.blockReason, /The action has not run/i);
  });
});
