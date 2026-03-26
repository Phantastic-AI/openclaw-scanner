# OpenClaw Scanner (OCS) Spec

Last updated: 2026-03-25

Canonical markdown: [OPENCLAW-SCANNER-SPEC.md](./OPENCLAW-SCANNER-SPEC.md)

## Summary

This plugin has one job: keep untrusted content out of model context unless it has been handled safely, and keep unsafe tool actions from running without scrutiny.

It does that with two flows:

- `Ingress Guard`: `stub -> review -> allow | warn | quarantine`
- `Egress Guard`: `check -> allow | ask | block`
- `Package Scan`: `detect install -> ClamAV file scan + OSV source scan -> clean | advisory | inconclusive | unavailable`

Default deployment is gateway-backed. The plugin uses OpenClaw's existing model stack through the gateway. PromptScanner is optional and fits behind a generic HTTP review adapter.

## Design Goal

Make the product smaller than the threat model.

The core should fit in four concepts:

1. `Artifact`
2. `ReviewResult`
3. `Approval`
4. two flows: ingress and egress

If a rule or feature cannot be explained in terms of those, it is probably excess complexity.

## Accepted Constraints

These constraints came out of earlier design review and are not optional:

- model review is allowed, including tool trust review, but it must fail closed
- artifact taint survives later local reads
- quarantine does not generate semantic summaries in v1
- review traffic and approval-control traffic must bypass the guard safely
- `ask` is a real approval state machine, not a vague intention
- cached review results must not replay across stronger taint contexts
- same-UID self-tamper resistance is not claimed when exec-capable tools are exposed

## Core Records

### Artifact

Represents any content-bearing thing the plugin may later re-read or reason about.

```json
{
  "artifactId": "artifact-123",
  "sessionKey": "agent:main:default",
  "sourceClass": "external",
  "taint": "warned",
  "pendingKey": "pending-123",
  "createdByTool": "web.fetch"
}
```

Fields:

- `artifactId`
- `sessionKey`
- `sourceClass`: `local | external | mixed | unknown`
- `taint`: `clean | warned | quarantined`
- `pendingKey`: optional pointer to pending raw content
- `createdByTool`: optional

Rules:

- `external` includes web and API output, uploads, pasted text, chat transcripts, email, and other user-supplied content
- if any input sourceClass is `external`, `mixed`, or `unknown`, the output sourceClass must be at least `mixed`
- strongest taint wins
- taint does not silently downgrade
- model `allow` must not turn `warned` or `quarantined` into `clean`
- reading a tainted artifact later keeps the taint unless an explicit taint-clearing policy exists

### ReviewResult

Represents the outcome of rules and optional model review.

```json
{
  "guard": "ingress",
  "reviewAction": "warn",
  "finalAction": "warn",
  "reasonCode": "agent_override_attempt",
  "decisionSource": "model",
  "reviewStatus": "complete",
  "failureCode": null,
  "policyVersion": "2026-03-17-security-plugin-minimal",
  "confidence": 0.78
}
```

Required fields:

- `guard`: `ingress | egress`
- `finalAction`
- `decisionSource`: `rule | model | hybrid | cache | fallback`
- `reviewStatus`: `not_requested | pending | complete | timeout | backend_error | schema_invalid | cache_hit`
- `policyVersion`

Recommended fields:

- `reviewAction`
- `reasonCode`
- `ruleId`
- `failureCode`
- `backend`
- `model`
- `confidence`

For ingress:

- `reviewAction` and `finalAction` use `allow | warn | quarantine`

For egress:

- `reviewAction` and `finalAction` use `allow | ask | block`

`confidence` is optional and never policy-critical.

### Approval

Represents permission to retry one previously blocked `ask` action.

```json
{
  "approvalId": "approval-123",
  "sessionKey": "agent:main:default",
  "toolName": "exec_command",
  "argsHash": "sha256:abc",
  "expiresAt": "2026-03-17T20:00:00Z",
  "singleUse": true
}
```

Rules:

- approval is bound to exact `sessionKey + toolName + argsHash`
- approval is single-use
- approval is consumed on successful execution
- replay, expiry, or argument mutation invalidates the approval

## Exec Posture

OCS tracks one explicit posture downgrade:

- `normal`
- `degraded_exec_posture`

Rules:

- if exec-capable tools are configured, posture is `degraded_exec_posture`
- if exec is later observed at runtime, posture stays `degraded_exec_posture`
- degraded posture does not disable ingress or egress enforcement
- degraded posture means OCS no longer claims same-UID self-tamper resistance
- sandboxed exec may only clear this posture with trusted runtime attestation; plugin-side heuristics are not sufficient proof

## Backend Model

### Default

- `trustReview.backend = gateway`
- `ingressReview.backend = gateway`
- `egressReview.backend = gateway`
- preferred model alias: `security-review`

If no dedicated review alias exists, fallback to inherited model is allowed only with a loud operational warning.

Stable config knob names that should remain user-visible:

- `persistMode`
- `warnMode`
- `headlessAskPolicy`

### Optional

- `http` backend for centralized review
- PromptScanner as one HTTP backend implementation
- `disabled` mode for rules-only operation

## Bypass Model

The plugin needs one internal bypass for:

- its own review calls
- its own approval-control operations

This bypass MUST be in-process or backed by an opaque unforgeable token. It MUST NOT be a plain static header or label that attacker-controlled content could imitate.

## Tool Trust Review

Tool trust is deliberately small.

Inputs:

- tool name
- normalized params
- built-in tool metadata
- admin overrides
- optional strong-model trust review

Outputs:

- `trusted_local`
- `untrusted_content_source`
- `unknown_needs_review`

Rules:

- model trust review is allowed
- failure, timeout, schema error, or uncertainty => `unknown_needs_review`
- trust review classifies tool-call shape only
- trust review never clears artifact taint

## Hook Ownership

| Hook | Primary responsibility |
| --- | --- |
| `before_tool_call` | classify tool trust, compute egress capability and grounding, apply deterministic egress rules, and consume matching approvals |
| `tool_result_persist` | decide raw vs stub persistence and write pending raw content when ingress review is required |
| `after_tool_call` | best-effort ingress review prefetch only; never relied on as an enforcement boundary |
| `before_prompt_build` | resolve pending ingress stubs and apply final `allow | warn | quarantine` replacement before the next model turn |
| `before_message_write` | final raw-write barrier if OpenClaw has alternate transcript write paths |

## Ingress Flow

### Purpose

Protect the next model turn from untrusted tool output and tainted artifact rereads.

### Flow

1. classify the tool result or artifact read as `trusted_local`, `untrusted_content_source`, or `unknown_needs_review`
2. combine that with any existing artifact taint
3. if the result is clean local content, persist raw
4. otherwise persist a stub and keep raw content in a pending store keyed by `sessionKey + toolCallId + invocationNonce`
5. prefetch review in `after_tool_call`
6. resolve in `before_prompt_build`
7. replace the stub with:
   - raw content for `allow`
   - canonical wrapped content for `warn`
   - stable placeholder for `quarantine`

### Persistence Rule

If content is not clean local content, raw content must not be persisted into model-visible transcript storage.

Pending-store reads must be atomic read-and-delete or version-checked so concurrent writes cannot cross-contaminate stubs.

If OpenClaw has another raw-write path outside `tool_result_persist`, the plugin must also use `before_message_write` as a final raw-write barrier.

### Warn Rule

Warn uses one canonical format:

- OpenClaw external-content wrapper with warning text disabled
- at most one aggregated turn-level hint

### Quarantine Rule

Quarantine means:

- no raw content reaches the next model turn
- no model-generated summary
- only a stable placeholder or deterministic metadata-only stub

The placeholder must be deterministic from `sessionKey + toolCallId + policyVersion`.

### Chunking Rule

Ingress review uses chunking.

Defaults:

- fixed-size overlapping chunks
- severity aggregation by max: `quarantine > warn > allow`

If there is truncated or unreviewed tail:

- mark `failureCode = truncated_unreviewed_tail`
- final action must be at least `warn`

## Egress Flow

### Purpose

Stop unsafe side effects before they run.

### Flow

1. normalize tool name and args
2. compute capability class:
   - `read_local`
   - `write_local`
   - `delete_local`
   - `secret_read`
   - `network_outbound`
   - `message_send`
   - `shell_exec`
   - `git_mutation`
   - `deploy_or_admin`
   - `destructive`
3. compute grounding from plugin-owned session history and artifact derivation
4. apply deterministic rules
5. if still ambiguous and high-risk, run review
6. decide `allow | ask | block`

Grounding must be plugin-owned. It must not rely solely on agent self-report.

### Ask Rule

OpenClaw gives this hook allow or block, so `ask` is implemented as:

1. create an `Approval`
2. return a structured block with approval metadata
3. allow one later retry only if the approval record matches exactly

Headless default:

- if interactivity cannot be proven, treat the session as headless
- headless `ask` => `block`

### Deterministic Defaults

- `secret_read` => `block`
- OCS control-plane reads, writes, deletes, and shell access => `block`
- obvious exfiltration => `block`
- `curl | bash` style payloads => `block`
- `network_outbound` that sends agent-composed or artifact-derived data to a remote system => `ask`
- `message_send` => `ask`
- `deploy_or_admin` => `ask`
- `destructive` => `ask`
- `git_mutation` => `ask`

Rules beat model review. A model must not override deterministic hard blocks.

Read-only fetch-style network tools are treated as ingress candidates, not side-effecting `network_outbound` egress actions.

Protected control-plane paths include at least:

- `~/.openclaw/openclaw.json`
- `~/.openclaw/plugins/openclaw-scanner/**`

`ask` remains an approval UX/state machine. It is not a same-UID security boundary once arbitrary local execution is available.

## Package Scanning

Package-producing actions are scanned in two layers:

1. ClamAV for file-level malware coverage
2. OSV source scanning for known vulnerable dependencies

Scope:

- JavaScript package installs such as `npm`, `pnpm`, `yarn`, and `bun`
- Python package installs such as `pip` and `uv pip`

OSV behavior:

- source scan runs against the install root after the action
- verdicts are `clean | advisory | inconclusive | unavailable`
- `required` mode may block package-install actions when `osv-scanner` is unavailable
- `inconclusive` means no supported lockfiles or manifests were detected; it is not the same as clean

Limits:

- OSV source scanning depends on supported lockfiles and manifests
- it catches known vulnerable dependency versions, not a fresh malicious package with no advisory yet
- it complements ClamAV; it does not replace future package-policy heuristics

## Hardening Sequence

The hardening order is deliberate.

### Stage 0: Current OCS

Today OCS owns:

- ingress review
- egress policy and approval UX
- control-plane path protection for its own local state
- ClamAV integration
- OSV source scanning

Today OCS does not claim:

- same-UID approval tamper resistance once exec-capable tools are exposed
- scanner isolation when scanners are invoked directly by the plugin process

### Stage 1: `openclaw-sec` Scan Broker

Stage 1 is the optional separate-UID scan broker described in:

- [OPENCLAW-SEC-BROKER-SPEC.md](./OPENCLAW-SEC-BROKER-SPEC.md)
- [OPENCLAW-SEC-BROKER-PLAN.md](./OPENCLAW-SEC-BROKER-PLAN.md)

What this stage adds:

- one separate-UID socket boundary for scan requests
- broker-owned scan logs
- `clamd` requests issued outside the `openclaw` UID
- bubblewrapped `osv-scanner` execution outside the `openclaw` UID
- one extension surface for future scanner backends

What this stage does not solve:

- approval integrity
- approval-log ownership
- same-UID tamper resistance for approval state

### Stage 2: Separate-UID Approval Control Plane

After the broker is deployed, the next meaningful hardening step is not "more UID checks."

It is:

- move approval ownership out of `openclaw`
- move approval logging out of `openclaw`
- require OCS to consume approval decisions from a separate-UID control plane

That is the point where approval integrity starts to become meaningful under exec-capable profiles.

## RFC: Artifact Taint Storage And Script Recheck

This section is future design guidance. It is not part of the current `0.6.x` enforcement contract.

### Problem

Current OCS tracks session taint well enough for ingress review, but it does not yet persist artifact-level provenance strongly enough to answer all of these questions:

- was this exact file ever scanned
- which scanner scanned it
- were the current bytes scanned or only an earlier version
- was this script written from tool output, downloaded, extracted, or installed
- is a later `bash script.sh` execution re-running content that has changed since the last scan

### Proposed Split

Use two taint stores, not one:

- session taint: in-memory, plugin-owned, ephemeral
- artifact taint: persisted, content-addressed, and eventually broker-owned

Session taint remains cheap conversational state such as `clean | warned | quarantined`.
Artifact taint becomes per-file or per-package state keyed by the actual bytes being executed or re-read.

### Proposed Artifact Ledger

Authoritative future home:

- broker-owned SQLite or JSONL store under `openclaw-sec`
- optional filesystem cache via xattrs

Proposed record shape:

```json
{
  "artifactId": "art-123",
  "canonicalPath": "/workspace/scripts/deploy.sh",
  "contentHash": "sha256:abc",
  "kind": "script",
  "source": "written",
  "derivedFrom": ["artifact-122"],
  "backends": {
    "ingressReview": "warn",
    "malwareScan": "clean",
    "packageSca": "not_applicable"
  },
  "state": "warn",
  "scannedAt": "2026-03-26T00:00:00Z"
}
```

Minimum fields:

- `canonicalPath`
- `contentHash`
- `kind`: `script | binary | archive | package_tree | text | unknown`
- `source`: `written | downloaded | extracted | installed | generated | unknown`
- `derivedFrom`
- per-backend state
- overall state

Per-backend states should be explicit, not boolean:

- `not_applicable`
- `pending`
- `clean`
- `warn`
- `blocked`
- `unavailable`
- `error`
- `stale`

### Filesystem And LSM Primitives

Linux primitives help, but they are not the source of truth by themselves.

Useful primitives:

- xattrs for cached per-file status such as `user.ocs.hash` or `user.ocs.taint`
- fanotify or inotify to invalidate stale scan results on write, rename, or exec
- IMA, EVM, or fs-verity for stronger integrity measurement
- LSM labels for future enforcement like "tainted content may not exec"

Those primitives complement the ledger. They do not replace provenance, multi-backend history, or user-space reporting.

### Script Write And Exec Correlation

Planned future model:

1. On `write_local`, inspect visible script-like content when available.
2. Record an observation keyed by canonical path plus content hash.
3. On `shell_exec`, detect launcher forms such as:
   - `bash foo.sh`
   - `sh foo.sh`
   - `python foo.py`
   - `node app.mjs`
   - `./tool`
4. Re-read the final file contents at execution time.
5. Re-hash and classify the actual bytes that will run.
6. Decide `allow | ask | block` from the final content, not just the command line.

Write-time inspection is early warning. Exec-time inspection is the real enforcement point.

### Exec-Time Recheck Decision Rules

Future intent:

- obvious secret theft, protected-path reads plus network egress, staged loaders, or hidden interpreter payloads => `block`
- ordinary offsite send of non-secret data => `ask`
- clearly local benign automation => `allow` or `review`

`quarantine` is ingress-only. Exec-time script decisions stay in the egress vocabulary: `allow | ask | block | review`.

### Cost And Context Limits

If a future exec-time script recheck cannot inspect enough of the file safely, it must not silently bless execution.

Future fallback order:

1. apply deterministic normalization and hard-block rules first
2. inspect the final script body directly when size is within policy limits
3. if the script is too large, chunk and classify with explicit truncation markers
4. if the review remains incomplete but the action has network, interpreter, or side-effect risk, degrade to at least `ask`
5. if required review cannot run at all for a high-risk launcher, `block`

The plugin must never convert "unscanned because too large or too expensive" into "clean".

## HTTP Review Adapter

The plugin owns the contract. Backends implement it.

### Ingress Request

```json
{
  "kind": "ingress_review",
  "text": "tool result text",
  "policyVersion": "2026-03-17-security-plugin-minimal",
  "artifact": {
    "sourceClass": "external",
    "taint": "warned"
  },
  "chunk": {
    "index": 1,
    "count": 3,
    "truncated": false,
    "unreviewedTail": false
  },
  "context": {
    "toolName": "web.fetch",
    "toolCallId": "call-123",
    "sessionKey": "agent:main:default"
  }
}
```

### Egress Request

```json
{
  "kind": "egress_review",
  "policyVersion": "2026-03-17-security-plugin-minimal",
  "context": {
    "toolName": "exec_command",
    "toolCallId": "call-456",
    "sessionKey": "agent:main:default",
    "capability": "shell_exec",
    "argsHash": "sha256:abc",
    "normalizedParams": {
      "command": "git push origin main",
      "cwd": "/workspace/repo"
    },
    "sourceSummary": {
      "sourceClass": "mixed",
      "taint": "warned"
    },
    "taintSummary": ["warned"],
    "grounding": {
      "explicitUserTurn": true,
      "derivedFromQuarantinedArtifact": false,
      "derivedFromArtifacts": ["artifact-123"]
    }
  }
}
```

Unknown response fields must be ignored.

### PromptScanner Mapping

PromptScanner fits here as an adapter.

Legacy mapping:

- `safe` -> ingress `allow`
- `injection` -> ingress `quarantine`

The plugin still owns final action, taint handling, and failure behavior.

## Cache Model

Keep caches small and explicit.

### Trust Review Cache

Keyed by:

- normalized tool signature
- backend
- model alias
- policy version
- trust-config hash

### Content Review Cache

Keyed by:

- guard type
- content hash
- taint at review time
- truncation status
- context discriminator for review-relevant source or tool shape
- backend
- model alias
- policy version

Cached review results must not replay into stronger taint contexts.

## Logging Rule

Raw quarantined content must not appear in info, debug, or error logs.

Operational logs should prefer IDs, hashes, reason codes, and failure codes over raw attacker-controlled text.

## Failure Policy

### Ingress

- backend failure => `quarantine`
- schema failure => `quarantine`
- pending content missing => `quarantine`
- truncated unreviewed tail => at least `warn`
- no automatic retries

### Egress

- deterministic hard block always wins
- ambiguous high-risk action with failed review => follow ask/block matrix
- headless uncertain `ask` => `block`

## The Small Story

This is the product in one paragraph:

- If tool output is not clearly clean local content, store a stub, review it, and only then decide whether to pass it through, wrap it, or quarantine it.
- If a tool action has meaningful side effects, check it before execution and either allow it, ask for approval, or block it.
- Anything created from dirty content stays dirty until explicitly cleared.
- The plugin uses OpenClaw's existing model stack by default, PromptScanner is just an optional backend, and package installs get both file-malware and known-vulnerability scanning.
