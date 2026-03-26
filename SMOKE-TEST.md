# OpenClaw Scanner (OCS) Smoke Test

Last updated: 2026-03-25
Canonical spec: [OPENCLAW-SCANNER-SPEC.md](./OPENCLAW-SCANNER-SPEC.md)

This plugin has one repeatable pod smoke path with two phases:

- the live `messaging` gateway for `allow / ask / approve / deny`
- the coding-profile canary gateway for broker-backed download and package-install scans

For the lower-level scan-only canary notes, use [ANTIVIRUS-SMOKE-TEST.md](./ANTIVIRUS-SMOKE-TEST.md).

## What this smoke covers

Main messaging gateway:

- `allow`: a benign local tool call should pass
- `ask`: a high-impact outbound action should block and request approval
- `allow once`: the exact pending action should be allowed once after a natural-language approval reply
- `deny`: a natural-language refusal should keep the action from being retried

Exec-capable canary gateway:

- `posture-report`: exec-capable profile must report `degraded_exec_posture`
- `download`: broker-backed ClamAV path should record `clean`
- `package install`: broker-backed ClamAV path should record `clean`
- `package install`: broker-backed OSV path should record `advisory` for `minimist@0.0.8`
- optional `fail closed`: stopping `openclaw-sec` must stop the actual package install from mutating the workspace

## What this smoke does not prove

- hard shell-block coverage like `rm -rf`
- browser or web ingress
- sandboxed exec attestation
- perfect user-facing wording for blocked exec-package actions when the broker is down

## One-command smoke

```bash
./smoke/smoke_remote_scanner.sh 51.210.13.102
```

Optional session prefix:

```bash
./smoke/smoke_remote_scanner.sh 51.210.13.102 my-smoke
```

Include the negative broker-required check:

```bash
SMOKE_INCLUDE_BROKER_FAILCLOSED=1 ./smoke/smoke_remote_scanner.sh 51.210.13.102 my-smoke
```

## How to read the results

- `allow` should return a normal assistant answer after using `sessions_list`.
- `ask` should show the `sessions_send` attempt blocked for approval.
- `allow once` passes when:
  - the assistant says the send was delivered
  - the security log contains `approval_granted`
  - the security log contains `egress_allow_approved`
  - the ask-session transcript shows the second `sessions_send` call accepted
- `deny` passes when:
  - the assistant refuses to retry
  - the deny approval-store entry is `state: "denied"`
- the canary `posture-report` must show `degraded_exec_posture`
- the canary `antivirus-report` must show `transport: "openclaw-sec"` and `verdict: "clean"` for the download and package-install sessions
- the canary `sca-report` must show `transport: "openclaw-sec"` and `verdict: "advisory"` for the `minimist@0.0.8` package-install session
- the optional broker-required negative check passes only if the workspace check prints `MISSING`

Important caveat:

- on current OpenClaw builds, the negative exec-package phase can still end with the assistant guessing the package name even when OCS blocked the real tool result
- for that phase, the source of truth is:
  - workspace path remains absent
  - antivirus/SCA ledgers record `unavailable`
  - no new broker log record appears for the blocked action

## Live evidence notes for this pod

The `dev-security` pod currently uses:

- a live `messaging` gateway on `~/.openclaw`
- a coding-profile canary on `~/.openclaw-avsmoke` at `19011`

The strongest main-gateway approval proof is a `sessions_send` request to the same session:

- OpenClaw Scanner blocks it first as `ask`
- a natural-language `Yes, send it now.` grants the exact pending action once
- the tool then runs successfully on the same session via `sessions_send ... timeoutSeconds 0`
- the live transcript shows the accepted send result and the echoed inbound inter-session message

Concrete verified live prefix on `51.210.13.102` on March 25, 2026 UTC:

- `qa-062`

For `qa-062`, the smoke proved:

- main gateway `allow` passed
- main gateway natural-language `ask -> approve -> send once` passed
- main gateway natural-language `deny` passed and left a denied approval-store entry
- canary `posture-report` showed `degraded_exec_posture`
- canary download recorded broker-backed antivirus `clean`
- canary package install recorded broker-backed antivirus `clean`
- canary package install recorded broker-backed OSV `advisory`
- broker-required negative check left the workspace path absent even though the assistant reply still guessed the package name

## Troubleshooting

- The smoke harness sets `OPENCLAW_GATEWAY_PORT=19011` for the canary. Do not drop that env or the CLI may drift back to the main `18789` gateway.
- If `gateway call ...` returns websocket `1006`, the gateway usually was not fully ready yet after restart. Rerun after `gateway call status --timeout 30000 --json` succeeds.
- If approval review fails with `401 Unauthorized`, check whether the systemd env token and `openclaw.json` token differ. The plugin now prefers the configured gateway auth token for local HTTP review and logs a mismatch warning.
- The current pod has broken Mattermost auth. `message` tool behavior is noisy here. Prefer `sessions_send` for repeatable messaging smoke on this stack.
- `openclaw gateway restart` from an arbitrary SSH shell is not authoritative on this host. For the main gateway, restart the real user service with `sudo -u openclaw XDG_RUNTIME_DIR=/run/user/999 systemctl --user restart openclaw-gateway.service`.
- The canary is a separate background process, not the main user systemd unit. If you cycle it manually, preserve:
  - `OPENCLAW_STATE_DIR=/home/openclaw/.openclaw-avsmoke`
  - `OPENCLAW_CONFIG_PATH=/home/openclaw/.openclaw-avsmoke/openclaw.json`
  - `OPENCLAW_GATEWAY_PORT=19011`
