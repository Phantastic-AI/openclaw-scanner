import { extractToolResultText, hashText, stableStringify } from "./text.mjs";

const EXTERNAL_READ_HINTS = [
  "browser",
  "search",
  "fetch",
  "http",
  "https",
  "request",
  "download",
  "crawl",
  "scrape",
  "mcp",
  "web",
  "read_url",
  "ocr",
  "transcribe",
  "import",
  "ingest",
];

const MESSAGE_SEND_HINTS = ["message", "email", "mail", "slack", "discord", "webhook", "notify"];
const DEPLOY_HINTS = [
  "deploy",
  "kubectl",
  "terraform",
  "helm",
  "systemctl",
  "service",
  "restart",
  "admin",
];
const WRITE_HINTS = [
  "write",
  "edit",
  "append",
  "save",
  "create",
  "touch",
  "mkdir",
  "rename",
  "move",
  "copy",
];
const DELETE_HINTS = ["delete", "unlink", "trash", "remove", "rm"];
const READ_HINTS = ["read", "cat", "open", "grep", "rg", "glob", "ls", "pwd", "stat"];
const SHELL_HINTS = ["exec", "shell", "bash", "sh", "terminal", "command", "run"];

const SECRET_PATH_PATTERNS = [
  /\.env(\.|$)/i,
  /(^|\/)\.ssh(\/|$)/i,
  /id_(rsa|ed25519)/i,
  /authorized_keys/i,
  /known_hosts/i,
  /\/etc\/shadow/i,
  /\/etc\/passwd/i,
  /\/proc\/self\/environ/i,
  /system[_-]?prompt/i,
  /openai[_-]?api[_-]?key/i,
  /anthropic[_-]?api[_-]?key/i,
];

const CONTROL_PLANE_PATH_PATTERNS = [
  /(^|\/)\.openclaw\/openclaw\.json$/i,
  /(^|\/)\.openclaw\/plugins\/openclaw-scanner(\/|$)/i,
];

const PROTECTED_PATH_PATTERNS = [...SECRET_PATH_PATTERNS, ...CONTROL_PLANE_PATH_PATTERNS];

const HARD_BLOCK_COMMAND_PATTERNS = [
  /\bcurl\b[\s\S]{0,200}\|\s*(bash|sh)\b/i,
  /\bwget\b[\s\S]{0,200}\|\s*(bash|sh)\b/i,
  /\bbase64\b[\s\S]{0,200}\|\s*(bash|sh)\b/i,
  /\beval\b/i,
  /\bpython(?:3)?\b[\s\S]{0,80}-c[\s\S]{0,200}\bexec\s*\(/i,
  /\brm\b\s+-rf\s+(\/($|\s)|~($|\s)|\*($|\s))/i,
  /\bsudo\b[\s\S]{0,40}\brm\b\s+-rf\b/i,
];

const APPROVAL_REQUIRED_COMMAND_PATTERNS = [
  /\bgh\b\s+pr\s+create\b/i,
  /\bscp\b/i,
  /\bssh\b/i,
  /\bkubectl\b/i,
  /\bterraform\b/i,
  /\bhelm\b/i,
  /\bdocker\b[\s\S]{0,40}\b(push|run|compose\s+(up|down))\b/i,
  /\bsystemctl\b/i,
  /\bcurl\b[\s\S]{0,80}-X\s+(POST|PUT|PATCH|DELETE)\b/i,
  /\binvoke-webrequest\b/i,
];

const BENIGN_SHELL_PATTERNS = [
  /^\s*(pwd|ls|stat|find|tree)\b/i,
  /^\s*(cat|head|tail|wc|cut|sort|uniq)\b/i,
  /^\s*(git\s+(status|diff|log|show|branch))\b/i,
  /^\s*(rg|grep)\b/i,
  /^\s*(pytest|npm\s+test|pnpm\s+test|yarn\s+test|uv\s+run\s+pytest)\b/i,
  /^\s*(node|python|python3)\s+(-v|--version)\b/i,
  /^\s*(whoami|date|uname)\b/i,
];

function normalizeToolName(toolName) {
  return String(toolName || "").trim().toLowerCase();
}

function collectCandidateStrings(value, parts, depth = 0) {
  if (value == null || depth > 5) {
    return;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed) {
      parts.push(trimmed);
    }
    return;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    parts.push(String(value));
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectCandidateStrings(item, parts, depth + 1);
    }
    return;
  }
  if (typeof value === "object") {
    for (const nested of Object.values(value)) {
      collectCandidateStrings(nested, parts, depth + 1);
    }
  }
}

function extractCandidateStrings(params) {
  const parts = [];
  collectCandidateStrings(params, parts, 0);
  return parts;
}

function extractPaths(params) {
  const candidates = extractCandidateStrings(params);
  return candidates.filter((value) => value.includes("/") || value.startsWith(".") || value.startsWith("~"));
}

function matchesAnyPattern(text, patterns) {
  return patterns.some((pattern) => pattern.test(text));
}

function tokenizeCommand(text) {
  return String(text || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

function classifyGitPushCommand(text) {
  const tokens = tokenizeCommand(text);
  if (tokens[0] !== "git" || tokens[1] !== "push") {
    return null;
  }

  const args = tokens.slice(2);
  if (
    args.some(
      (token) =>
        token === "-f" ||
        token === "--force" ||
        token === "--force-with-lease" ||
        token.startsWith("--force-with-lease="),
    )
  ) {
    return "force";
  }

  if (args.some((token) => token === "--all" || token === "--delete" || token === "--mirror" || token === "--prune")) {
    return "other";
  }

  return "routine";
}

function hasHint(toolName, hints) {
  return hints.some((hint) => toolName.includes(hint));
}

function maxTaint(a = "clean", b = "clean") {
  const rank = { clean: 0, warned: 1, quarantined: 2 };
  return (rank[b] || 0) > (rank[a] || 0) ? b : a;
}

export function buildArgsHash(params) {
  return `sha256:${hashText(stableStringify(params || {}))}`;
}

export function mergeTaintLevels(...taints) {
  return taints.reduce((current, next) => maxTaint(current, next), "clean");
}

export function extractParamText(params, maxChars = 4000) {
  return extractToolResultText(params, maxChars);
}

export function classifyEgressAction(toolName, params) {
  const normalizedToolName = normalizeToolName(toolName);
  const paramText = extractParamText(params, 4000);
  const normalizedParamText = paramText.toLowerCase();
  const paths = extractPaths(params);

  if (normalizedToolName === "sessions_send") {
    return {
      capability: "message_send",
      normalizedToolName,
      normalizedParams: params || {},
      paramText,
      normalizedParamText,
      paths,
    };
  }

  if (hasHint(normalizedToolName, EXTERNAL_READ_HINTS)) {
    return {
      capability: "read_only_external",
      normalizedToolName,
      normalizedParams: params || {},
      paramText,
      normalizedParamText,
      paths,
    };
  }

  if (hasHint(normalizedToolName, MESSAGE_SEND_HINTS)) {
    return {
      capability: "message_send",
      normalizedToolName,
      normalizedParams: params || {},
      paramText,
      normalizedParamText,
      paths,
    };
  }

  if (hasHint(normalizedToolName, DEPLOY_HINTS)) {
    return {
      capability: "deploy_or_admin",
      normalizedToolName,
      normalizedParams: params || {},
      paramText,
      normalizedParamText,
      paths,
    };
  }

  if (hasHint(normalizedToolName, DELETE_HINTS)) {
    return {
      capability: "delete_local",
      normalizedToolName,
      normalizedParams: params || {},
      paramText,
      normalizedParamText,
      paths,
    };
  }

  if (hasHint(normalizedToolName, WRITE_HINTS)) {
    return {
      capability: "write_local",
      normalizedToolName,
      normalizedParams: params || {},
      paramText,
      normalizedParamText,
      paths,
    };
  }

  if (hasHint(normalizedToolName, READ_HINTS)) {
    return {
      capability: "read_local",
      normalizedToolName,
      normalizedParams: params || {},
      paramText,
      normalizedParamText,
      paths,
    };
  }

  if (hasHint(normalizedToolName, SHELL_HINTS)) {
    return {
      capability: "shell_exec",
      normalizedToolName,
      normalizedParams: params || {},
      paramText,
      normalizedParamText,
      paths,
    };
  }

  if (/\bhttps?:\/\//i.test(paramText)) {
    return {
      capability: "network_outbound",
      normalizedToolName,
      normalizedParams: params || {},
      paramText,
      normalizedParamText,
      paths,
    };
  }

  return {
    capability: "unknown",
    normalizedToolName,
    normalizedParams: params || {},
    paramText,
    normalizedParamText,
    paths,
  };
}

export function evaluateDeterministicEgress({ toolName, params, sessionTaint = "clean" }) {
  const action = classifyEgressAction(toolName, params);
  const { capability, normalizedParamText, paths } = action;
  const gitPushKind = capability === "shell_exec" ? classifyGitPushCommand(normalizedParamText) : null;

  if (capability === "read_only_external") {
    return {
      ...action,
      finalAction: "allow",
      reasonCode: "read_only_external_ingress_candidate",
    };
  }

  if (
    capability === "read_local" &&
    paths.some((candidate) => PROTECTED_PATH_PATTERNS.some((pattern) => pattern.test(candidate)))
  ) {
    return {
      ...action,
      finalAction: "block",
      reasonCode: "protected_path_read",
      blockReason:
        "OpenClaw Scanner blocked this tool call because it targets a protected secret or control-plane path.",
    };
  }

  if (capability === "shell_exec" && matchesAnyPattern(normalizedParamText, HARD_BLOCK_COMMAND_PATTERNS)) {
    return {
      ...action,
      finalAction: "block",
      reasonCode: "dangerous_shell_payload",
      blockReason:
        "OpenClaw Scanner blocked this command because it matches a dangerous shell payload pattern.",
    };
  }

  if (
    capability === "write_local" &&
    paths.some((candidate) => PROTECTED_PATH_PATTERNS.some((pattern) => pattern.test(candidate)))
  ) {
    return {
      ...action,
      finalAction: "block",
      reasonCode: "protected_path_write",
      blockReason:
        "OpenClaw Scanner blocked this tool call because it targets a protected secret or control-plane path.",
    };
  }

  if (
    capability === "shell_exec" &&
    paths.some((candidate) => PROTECTED_PATH_PATTERNS.some((pattern) => pattern.test(candidate)))
  ) {
    return {
      ...action,
      finalAction: "block",
      reasonCode: "protected_path_shell_access",
      blockReason:
        "OpenClaw Scanner blocked this command because it appears to access protected secret or control-plane files.",
    };
  }

  if (sessionTaint === "quarantined" && ["shell_exec", "network_outbound", "message_send", "deploy_or_admin"].includes(capability)) {
    return {
      ...action,
      finalAction: "block",
      reasonCode: "quarantined_session_high_risk_action",
      blockReason:
        "OpenClaw Scanner blocked this action because the current session contains quarantined untrusted content.",
    };
  }

  if (capability === "shell_exec" && gitPushKind === "force") {
    return {
      ...action,
      finalAction: "ask",
      reasonCode: "high_impact_shell_command",
    };
  }

  if (capability === "shell_exec" && gitPushKind === "routine") {
    return {
      ...action,
      finalAction: "allow",
      reasonCode: "routine_git_push",
    };
  }

  if (capability === "shell_exec" && matchesAnyPattern(normalizedParamText, BENIGN_SHELL_PATTERNS)) {
    return {
      ...action,
      finalAction: "allow",
      reasonCode: "benign_shell_command",
    };
  }

  if (capability === "shell_exec" && matchesAnyPattern(normalizedParamText, APPROVAL_REQUIRED_COMMAND_PATTERNS)) {
    return {
      ...action,
      finalAction: "ask",
      reasonCode: "high_impact_shell_command",
    };
  }

  if (capability === "delete_local") {
    if (paths.some((candidate) => PROTECTED_PATH_PATTERNS.some((pattern) => pattern.test(candidate)))) {
      return {
        ...action,
        finalAction: "block",
        reasonCode: "protected_path_delete",
        blockReason:
          "OpenClaw Scanner blocked this delete because it targets a protected secret or control-plane path.",
      };
    }
    const touchesAbsoluteOrHomePath = paths.some(
      (candidate) => candidate.startsWith("/") || candidate.startsWith("~"),
    );
    if (touchesAbsoluteOrHomePath) {
      return {
        ...action,
        finalAction: "ask",
        reasonCode: "absolute_delete_path",
      };
    }
    return {
      ...action,
      finalAction: "allow",
      reasonCode: "workspace_delete",
    };
  }

  if (["message_send", "deploy_or_admin", "network_outbound"].includes(capability)) {
    return {
      ...action,
      finalAction: "ask",
      reasonCode: `${capability}_approval_required`,
    };
  }

  if (["read_local", "write_local"].includes(capability)) {
    return {
      ...action,
      finalAction: "allow",
      reasonCode: `${capability}_local`,
    };
  }

  if (capability === "unknown") {
    return {
      ...action,
      finalAction: sessionTaint === "warned" ? "ask" : "review",
      reasonCode: sessionTaint === "warned" ? "warned_session_unknown_tool" : "unknown_tool_shape",
    };
  }

  if (capability === "shell_exec") {
    return {
      ...action,
      finalAction: "review",
      reasonCode: sessionTaint === "warned" ? "warned_session_shell_review" : "shell_review",
    };
  }

  return {
    ...action,
    finalAction: "allow",
    reasonCode: "default_allow",
  };
}
