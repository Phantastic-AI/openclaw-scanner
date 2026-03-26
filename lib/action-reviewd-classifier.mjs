export const APPROVAL_INTENTS = Object.freeze(["yes", "no", "unclear"]);

const YES_PATTERNS = [
  /^(?:yes|y)\b/i,
  /\bdo it\b/i,
  /\bgo ahead\b/i,
  /\bapprove(?:d)?\b/i,
  /\brun it\b/i,
  /\bplease do\b/i,
  /\bok(?:ay)?(?:\s+do it)?\b/i,
  /\bsounds good\b/i,
  /\blooks good\b/i,
];

const NO_PATTERNS = [
  /^(?:no|n|nope)\b/i,
  /\bdo not\b/i,
  /\bdon't\b/i,
  /\bdeny\b/i,
  /\breject\b/i,
  /\bcancel\b/i,
  /\bnot now\b/i,
  /\bnever mind\b/i,
  /\bstop\b/i,
];

function normalizeIntent(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (APPROVAL_INTENTS.includes(normalized)) {
    return normalized;
  }
  if (YES_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return "yes";
  }
  if (NO_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return "no";
  }
  return "unclear";
}

function stripFence(text) {
  const trimmed = String(text || "").trim();
  if (!trimmed.startsWith("```")) {
    return trimmed;
  }
  return trimmed.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
}

function parseDecisionFromText(text) {
  const cleaned = stripFence(text);
  if (!cleaned) {
    return { decision: "unclear", reason: "empty classifier output" };
  }
  try {
    const parsed = JSON.parse(cleaned);
    return {
      decision: normalizeIntent(parsed?.decision),
      reason: String(parsed?.reason || "").trim(),
    };
  } catch {
    return {
      decision: normalizeIntent(cleaned),
      reason: "",
    };
  }
}

function firstContentText(payload) {
  if (Array.isArray(payload?.output)) {
    for (const item of payload.output) {
      const content = Array.isArray(item?.content) ? item.content : [];
      for (const part of content) {
        if (part?.type === "output_text" && typeof part.text === "string") {
          return part.text;
        }
        if (typeof part?.text === "string") {
          return part.text;
        }
      }
    }
  }
  return "";
}

export function normalizeIntentClassifierConfig(raw = {}) {
  const type = String(raw?.kind || raw?.type || raw?.provider || "").trim().toLowerCase();
  return {
    kind: type === "openai-compatible" || type === "openai" ? "openai-compatible" : "",
    baseUrl: String(raw?.baseUrl || process.env.ACTION_REVIEWD_INTENT_BASE_URL || "").trim(),
    apiKey: String(raw?.apiKey || process.env.ACTION_REVIEWD_INTENT_API_KEY || "").trim(),
    model: String(raw?.model || process.env.ACTION_REVIEWD_INTENT_MODEL || "").trim(),
    timeoutMs:
      Number.isFinite(Number(raw?.timeoutMs || process.env.ACTION_REVIEWD_INTENT_TIMEOUT_MS)) &&
      Number(raw?.timeoutMs || process.env.ACTION_REVIEWD_INTENT_TIMEOUT_MS) > 0
        ? Math.trunc(Number(raw?.timeoutMs || process.env.ACTION_REVIEWD_INTENT_TIMEOUT_MS))
        : 10000,
  };
}

export function createOpenAiCompatibleIntentClassifier(config = {}) {
  if (
    config.kind !== "openai-compatible" ||
    !config.baseUrl ||
    !config.apiKey ||
    !config.model
  ) {
    return undefined;
  }

  return async function classify({ replyText, actionSummary, reason, threadMessage }) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.timeoutMs);
    try {
      const response = await fetch(`${config.baseUrl.replace(/\/+$/, "")}/chat/completions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.apiKey}`,
          "Content-Type": "application/json",
        },
        signal: controller.signal,
        body: JSON.stringify({
          model: config.model,
          temperature: 0,
          messages: [
            {
              role: "system",
              content:
                "Classify a human reviewer reply for an approval workflow. " +
                'Return strict JSON with keys decision and reason. ' +
                'decision must be one of: "yes", "no", "unclear". ' +
                "Approve only when the latest reviewer reply clearly grants permission for the pending action. " +
                "Deny only when it clearly refuses or cancels the action. " +
                "Otherwise return unclear.",
            },
            {
              role: "user",
              content:
                `Pending action: ${String(actionSummary || "").trim() || "(unknown)"}\n` +
                `Risk reason: ${String(reason || "").trim() || "(none)"}\n` +
                `Review request: ${String(threadMessage || "").trim() || "(none)"}\n` +
                `Latest reviewer reply: ${String(replyText || "").trim() || "(empty)"}\n`,
            },
          ],
          response_format: {
            type: "json_object",
          },
        }),
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`intent classifier HTTP ${response.status}: ${text}`);
      }

      const payload = await response.json();
      const rawText =
        String(payload?.choices?.[0]?.message?.content || "").trim() || firstContentText(payload);
      return parseDecisionFromText(rawText);
    } finally {
      clearTimeout(timeout);
    }
  };
}

export async function classifyApprovalIntent({
  replyText,
  actionSummary,
  reason,
  threadMessage,
  classifier,
} = {}) {
  if (typeof classifier === "function") {
    try {
      const result = await classifier({
        replyText: String(replyText || ""),
        actionSummary: String(actionSummary || ""),
        reason: String(reason || ""),
        threadMessage: String(threadMessage || ""),
      });
      return {
        decision: normalizeIntent(result?.decision),
        reason: String(result?.reason || "").trim(),
      };
    } catch (error) {
      return {
        decision: normalizeIntent(replyText),
        reason: `classifier failed: ${String(error)}`,
      };
    }
  }

  return {
    decision: normalizeIntent(replyText),
    reason: "heuristic fallback",
  };
}
