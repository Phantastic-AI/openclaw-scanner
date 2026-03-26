# OpenClaw Scanner (OCS) Test Plan

Last updated: 2026-03-25

Canonical markdown for the public scanner repo: [OPENCLAW-SCANNER-TEST-PLAN.md](./OPENCLAW-SCANNER-TEST-PLAN.md)

## Scope

This plan covers the minimal spine in [OPENCLAW-SCANNER-SPEC.md](./OPENCLAW-SCANNER-SPEC.md).

The point of this plan is not to test every idea. It is to prove the small core actually holds under pressure.

## Core Things To Prove

1. dirty content does not reach the next model turn raw
2. dirty artifacts stay dirty across later local rereads
3. dangerous side effects become `allow`, `ask`, or `block` deterministically
4. `ask` is single-use and exact-match
5. review/bypass traffic cannot be spoofed
6. cache hits do not weaken taint-sensitive decisions
7. exec-capable posture downgrades are surfaced honestly
8. package-install scanning records clean, advisory, and unavailable states correctly
9. scan-daemon-required mode fails closed for covered scan actions when the scan daemon is unavailable
10. scan-daemon-backed scans populate the same ledgers and reports as direct local scans

## Test Layers

### Unit

Test:

- artifact taint merge
- review result validation
- approval hashing and consumption
- deterministic placeholder building
- canonical warn wrapper building
- cache key building

### Hook Contract

Test:

- `before_tool_call`
- `tool_result_persist`
- `after_tool_call`
- `before_prompt_build`
- `before_message_write` if needed as final raw-write barrier
- hook ownership stays single and does not smear persistence, review, and enforcement across multiple hooks

### Integration

Test with:

- fake gateway review backend
- fake HTTP review backend
- restartable pending store
- simulated multi-turn session

### Live Pod QA Gate

Before shipping a pod-facing build, rerun the live smoke matrix on a real host:

1. main messaging gateway:
   - `allow`
   - `ask`
   - natural-language `approve`
   - natural-language `deny`
2. exec-capable canary:
   - `posture-report`
   - scan-daemon-backed download
   - scan-daemon-backed package install
   - scan-daemon-backed SCA advisory
   - optional scan-daemon-required fail-closed check

Source of truth for each phase:

- messaging approve:
  - transcript shows second approved tool call accepted
  - security log shows `approval_granted`
  - security log shows `egress_allow_approved`
- messaging deny:
  - approval store shows `state: "denied"`
- scan-daemon-backed download/package install:
  - antivirus report shows `transport: "openclaw-scand"`
- scan-daemon-backed SCA:
  - SCA report shows `transport: "openclaw-scand"` and expected advisory ids
- scan-daemon-required fail-closed:
  - workspace path stays absent
  - do not trust the assistant reply alone

## Required Tests

### Happy Path

1. clean local tool result persists raw and passes through unchanged
2. untrusted tool result persists as stub and resolves to `allow`
3. warned ingress result resolves to canonical wrapped content
4. quarantined ingress result resolves to placeholder only
5. ordinary local write grounded in user intent is allowed

### Trust Review

1. built-in trusted tool classifies as `trusted_local`
2. built-in untrusted tool classifies as `untrusted_content_source`
3. unknown tool can become `trusted_local` via strong-model trust review
4. trust-review timeout or schema failure yields `unknown_needs_review`
5. trust review never clears existing artifact taint

### Ingress Safety

1. untrusted content is never persisted raw into model-visible transcript storage
2. pending-store read is atomic or version-checked
3. pending raw content missing yields `quarantine`
4. `before_prompt_build` with no pending stubs is a no-op
5. quarantine never emits model-generated summaries
6. two concurrent pending stubs cannot cross-wire raw content during resolution
7. legacy malicious skill fixtures still quarantine under the current hook path

### Taint Propagation

1. fetch remote content -> save file -> later local read remains tainted
2. warned plus clean source yields warned or stronger taint
3. quarantined plus clean source yields quarantined taint
4. model-backed ingress `allow` does not downgrade existing taint
5. copied or renamed tainted artifact keeps taint
6. user-supplied uploads and pasted content classify as `external`

### Chunking And Truncation

1. long content splits into overlapping chunks
2. severity aggregates by max over chunks
3. payload across a chunk boundary is still caught
4. truncated unreviewed tail never returns plain `allow`

### Structured And Encoded Inputs

1. zero-width Unicode obfuscation does not bypass wrapper or chunk logic
2. JSON field values carrying instructions are still reviewed correctly

### Egress Safety

1. `.env` read is blocked
2. SSH key read is blocked
3. `curl | bash` style command is blocked
4. side-effecting `network_outbound` becomes `ask`
5. read-only fetch-style network tool is handled as ingress, not egress
6. `message_send` becomes `ask`
7. `deploy_or_admin` becomes `ask`
8. `destructive` becomes `ask`
9. `git_mutation` becomes `ask`
10. deterministic hard block beats model `allow`
11. OCS control-plane reads are blocked
12. OCS control-plane writes are blocked
13. OCS control-plane deletes are blocked
14. shell access to OCS control-plane paths is blocked

### Exec Posture

1. coding or full-profile tool policy marks posture as degraded
2. messaging-only tool policy keeps posture normal until exec is observed
3. observing exec at runtime persists degraded posture status
4. posture report exposes configured and observed exec state

### Package Scanning

1. required SCA mode blocks package-install actions when `osv-scanner` is unavailable
2. package installs with OSV advisories record `advisory`
3. package installs with no supported manifests record `inconclusive`
4. package installs with clean OSV output record `clean`
5. SCA report renders status and recent advisory records

### Scan Daemon

1. required scan-daemon mode blocks scan-covered actions when the scan-daemon socket is unavailable
2. scan-daemon-backed malware scans populate antivirus ledger and report entries
3. scan-daemon-backed package SCA populates SCA ledger and report entries
4. scan-daemon `auto` mode falls back to local scanning with a degraded warning
5. live fail-closed smoke judges execution by workspace mutation and ledgers, not only by final assistant text

### Ask Mechanics

1. `ask` returns a structured block with approval metadata
2. approval matches exact `sessionKey + toolName + argsHash`
3. mutated args are rejected
4. expired approval is rejected
5. approval is consumed on first successful use
6. replay after consumption is rejected
7. headless mode turns `ask` into `block`

### Bypass Safety

1. gateway review calls bypass the guard
2. HTTP backend review calls bypass the guard
3. approval-control operations bypass the guard
4. forged bypass markers in tool output or HTTP responses are ignored

### Grounding Safety

1. plugin-owned grounding can establish explicit user grounding
2. agent self-report alone cannot establish explicit user grounding
3. action derived from quarantined artifact is not silently allowed

### Cache Safety

1. trust-review cache keys include tool signature, backend, model alias, policy version, and trust-config hash
2. content-review cache keys include guard type, content hash, taint, truncation status, context discriminator, backend, model alias, and policy version
3. cached clean-context review does not replay into stronger taint context
4. cache invalidates on model or policy change

### Weird Backend Responses

1. malformed schema fails closed
2. timeout fails closed
3. unknown extra fields are ignored
4. PromptScanner legacy `safe` maps to `allow`
5. PromptScanner legacy `injection` maps to `quarantine`

### Session Isolation

1. same toolCallId across sessions cannot collide
2. pending-store entries are session-scoped
3. approvals are session-scoped
4. taint does not leak between sessions
5. same toolCallId in one session but different invocationNonce cannot collide

### Logging Redaction

1. raw quarantined content does not appear in info logs
2. raw quarantined content does not appear in debug logs
3. raw quarantined content does not appear in error logs

### Disabled Mode

1. rules-only mode still applies deterministic ingress behavior
2. rules-only mode still applies deterministic egress behavior

## Suggested Harness

Use Node's built-in test runner.

Suggested files:

```text
test/
├── artifact.test.mjs
├── ingress.test.mjs
├── egress.test.mjs
├── approval.test.mjs
├── cache.test.mjs
└── integration.test.mjs
```

## Launch Gate

Before shipping:

1. ingress safety tests pass
2. taint propagation tests pass
3. deterministic egress tests pass
4. approval tests pass
5. bypass spoofing tests pass
6. cache taint-context tests pass
7. one gateway-backed integration test passes
8. one HTTP-adapter integration test passes
