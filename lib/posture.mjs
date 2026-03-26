const RUNTIME_TOOL_MARKERS = new Set([
  "*",
  "group:openclaw",
  "group:runtime",
  "exec",
  "exec_command",
  "bash",
  "process",
]);

export const EXEC_POSTURE_NORMAL = "normal";
export const EXEC_POSTURE_DEGRADED = "degraded_exec_posture";
export const EXEC_POSTURE_WARNING =
  "Exec-capable tools are enabled. OpenClaw Scanner cannot guarantee same-UID self-tamper resistance in this posture.";

function normalizeEntries(value) {
  return Array.isArray(value)
    ? value.map((entry) => String(entry || "").trim().toLowerCase()).filter(Boolean)
    : [];
}

function entriesMentionRuntime(entries = []) {
  return normalizeEntries(entries).some((entry) => RUNTIME_TOOL_MARKERS.has(entry));
}

function profileAllowsRuntime(profile) {
  const normalized = String(profile || "").trim().toLowerCase();
  if (!normalized || normalized === "full") {
    return true;
  }
  if (normalized === "coding") {
    return true;
  }
  if (normalized === "minimal" || normalized === "messaging") {
    return false;
  }
  return true;
}

function normalizePolicy(raw = {}, inherited = {}) {
  return {
    profile:
      String(raw?.profile || "").trim().toLowerCase() ||
      String(inherited?.profile || "").trim().toLowerCase() ||
      "full",
    allow: raw?.allow ?? inherited?.allow ?? [],
    deny: [...normalizeEntries(inherited?.deny), ...normalizeEntries(raw?.deny)],
  };
}

function evaluatePolicy(raw = {}, inherited = {}) {
  const policy = normalizePolicy(raw, inherited);
  let execCapable = profileAllowsRuntime(policy.profile);
  const allow = normalizeEntries(policy.allow);
  const deny = normalizeEntries(policy.deny);

  if (allow.length > 0) {
    execCapable = entriesMentionRuntime(allow);
  }
  if (deny.includes("*") || entriesMentionRuntime(deny)) {
    execCapable = false;
  }

  return {
    profile: policy.profile,
    allow,
    deny,
    execCapable,
  };
}

export function evaluateExecPosture(fullConfig = {}) {
  const globalPolicy = evaluatePolicy(fullConfig?.tools || {});
  const agents = Array.isArray(fullConfig?.agents?.list) ? fullConfig.agents.list : [];
  const agentPolicies = agents
    .map((agent) => {
      const agentId = String(agent?.id || "").trim();
      if (!agentId) {
        return undefined;
      }
      const resolved = evaluatePolicy(agent?.tools || {}, globalPolicy);
      return {
        agentId,
        ...resolved,
      };
    })
    .filter(Boolean);

  const execCapableAgents = agentPolicies.filter((entry) => entry.execCapable).map((entry) => entry.agentId);
  const configuredExecCapable = globalPolicy.execCapable || execCapableAgents.length > 0;

  return {
    posture: configuredExecCapable ? EXEC_POSTURE_DEGRADED : EXEC_POSTURE_NORMAL,
    reasonCode: configuredExecCapable
      ? "exec_capable_tools_configured"
      : "no_exec_capable_tools_detected",
    statusMessage: configuredExecCapable ? EXEC_POSTURE_WARNING : "No exec-capable tools detected in tool policy.",
    configuredExecCapable,
    observedExec: false,
    globalProfile: globalPolicy.profile,
    globalAllow: globalPolicy.allow,
    globalDeny: globalPolicy.deny,
    execCapableAgents,
  };
}

export function mergeObservedExecPosture(current = {}, observation = {}) {
  return {
    posture: EXEC_POSTURE_DEGRADED,
    reasonCode: observation.reasonCode || current.reasonCode || "exec_tool_observed",
    statusMessage: EXEC_POSTURE_WARNING,
    configuredExecCapable: current.configuredExecCapable === true,
    observedExec: true,
    globalProfile: current.globalProfile,
    globalAllow: current.globalAllow,
    globalDeny: current.globalDeny,
    execCapableAgents: Array.isArray(current.execCapableAgents) ? current.execCapableAgents : [],
    lastObservedToolName: observation.toolName || current.lastObservedToolName,
    lastObservedSessionKey: observation.sessionKey || current.lastObservedSessionKey,
    lastObservedAt: Number.isFinite(observation.observedAt) ? observation.observedAt : Date.now(),
  };
}
