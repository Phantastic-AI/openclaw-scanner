# openclaw-sec Broker Plan

Last updated: 2026-03-25

Canonical markdown: [OPENCLAW-SEC-BROKER-PLAN.md](./OPENCLAW-SEC-BROKER-PLAN.md)

## Goal

Implement the `openclaw-sec` scan broker with the smallest credible cut:

- separate UID
- Unix socket API
- `clamd` integration
- bubblewrapped `osv-scanner`
- broker-owned logs
- smooth install and uninstall

## Phase 1: Protocol and Client

1. Add broker client support to OCS.
2. Add `scanBrokerMode` and `scanBrokerSocketPath`.
3. Add response normalization:
   - `malware_scan` -> antivirus ledger/status
   - `package_sca` -> SCA ledger/status
4. Add fallback behavior for `auto`.
5. Add fail-closed behavior for `required`.

Acceptance:

- OCS can call a fake broker over a Unix socket
- `auto` fallback warns loudly
- `required` blocks when broker is unavailable

## Phase 2: Broker Service

1. Create `openclaw-sec` service entrypoint.
2. Implement `status`.
3. Implement `malware_scan` using `clamd`.
4. Implement `package_sca` using `osv-scanner`.
5. Normalize all responses into bounded JSON.
6. Add structured JSONL logging.

Acceptance:

- broker handles fake and real requests
- broker never emits unbounded stack traces or raw attacker content to the client

## Phase 3: Bubblewrap

1. Add a bubblewrap launcher for `osv-scanner`.
2. Ensure no network.
3. Ensure read-only workspace bind.
4. Ensure no write access to OCS state or broker state.
5. Capture stdout/stderr and map them to structured broker responses.

Acceptance:

- `package_sca` still works through the broker
- sandboxed `osv-scanner` cannot write to host state dirs

## Phase 4: Ops Packaging

1. Add install script in ops repo.
2. Add uninstall script in ops repo.
3. Add systemd unit in ops repo.
4. Add tmpfiles or equivalent runtime-dir setup.
5. Add runbook docs.

Acceptance:

- install is idempotent
- reinstall is idempotent
- uninstall refuses unsafe removal unless forced

## Required Tests

### Unit

1. socket request parsing
2. socket response serialization
3. `clamd` response mapping
4. `osv-scanner` response mapping
5. bubblewrap argv generation
6. broker log record redaction
7. OCS broker client fallback behavior

### Integration

1. fake Unix socket broker from OCS
2. fake `clamd` socket inside broker tests
3. fake `osv-scanner` executable inside broker tests
4. `required` mode block when broker is missing
5. `auto` mode fallback with degraded warning

### Pod Smoke

1. install broker on a dev-security pod
2. verify `systemctl status openclaw-sec`
3. verify socket exists and permissions are correct
4. set OCS `scanBrokerMode=required`
5. run benign package install and confirm:
   - broker log entry exists
   - OCS antivirus report updates
   - OCS SCA report updates
6. stop the broker and confirm a covered action now blocks
7. restore the broker and confirm actions resume
8. run uninstall and confirm:
   - service gone
   - socket gone
   - uninstall refused if `required` mode was still active, unless forced

## Deterministic Smoke Strategy

Do not make smoke depend on live advisory churn.

For SCA smoke:

- use a fake `osv-scanner` binary in a temporary path for deterministic advisory and clean cases
- keep one optional health check for the real binary

For malware smoke:

- use a fake `clamd` socket in automated integration
- keep real `clamd` pod smoke separate

## Implementation Order

1. broker client in OCS
2. fake socket integration tests
3. broker daemon skeleton
4. `clamd` op
5. `osv-scanner` op
6. bubblewrap wrapper
7. broker logs
8. ops install script
9. ops uninstall script
10. dev-security smoke

## Rollout Order

1. ship broker in `auto` mode first
2. verify pod smoke
3. switch hardened pods to `required`
4. only then claim broker-backed scan isolation as part of the product story

## What Comes Next

After the broker is stable, the next security slice is not more scanners.

It is:

- move approval ownership and approval logging to a separate-UID control plane
- stop treating `openclaw`-owned JSON approval files as the authority
- make approval grant / deny / consume operations cross a separate-UID boundary

That is the change that materially improves approval integrity and closes the biggest remaining same-UID gap.
