# OpenClaw Scanner (OCS)

[![npm version](https://img.shields.io/npm/v/openclaw-scanner)](https://www.npmjs.com/package/openclaw-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`openclaw-scanner` protects OpenClaw agents from prompt injection and unsafe tool use by checking both what comes back from tools and what the model is about to do next. It also scans downloaded files and installed packages for malware and known vulnerabilities.

The plugin works on its own. If you want stronger isolation, add the optional `openclaw-scand` companion daemon: it runs ClamAV and OSV-Scanner outside the main OpenClaw user, and uses [bubblewrap](https://github.com/containers/bubblewrap) to sandbox OSV-Scanner.

If you also want out-of-band approval for high-impact tool actions, this package ships `openclaw-action-reviewd`: a separate-UID approval service that owns pending action requests, polls a reviewer channel, and grants one-shot approvals outside the main OpenClaw process.

This package includes:

- **Ingress Guard**: review untrusted tool output before the next model turn
- **Egress Guard**: block obviously unsafe tool actions before they run
- **Antivirus Integration**: [ClamAV](https://www.clamav.net/)-backed file scanning for package installs, downloads, and archive extraction
- **Package SCA**: [OSV-Scanner](https://google.github.io/osv-scanner/) checks package installs for known vulnerable dependencies
- **Scan Daemon**: optional `openclaw-scand` companion daemon for isolated ClamAV and OSV scanning
- **Action Review Service**: optional `openclaw-action-reviewd` companion daemon for out-of-band approval of `ask` actions
- **Exec Posture Warning**: loud degraded-posture reporting when exec-capable tools are enabled

## Start Here

Install the plugin through OpenClaw:

```bash
openclaw plugins install openclaw-scanner
```

Want the isolated scanning setup too? This package also ships `openclaw-scand`, which runs ClamAV and OSV-Scanner outside the main OpenClaw user and sandboxes OSV-Scanner with bubblewrap.

Want out-of-band approval too? This package also ships `openclaw-action-reviewd`, which owns pending `ask` actions and consumes reviewer replies outside the main OpenClaw process. If you use it for exec-capable profiles, disable OpenClaw core `approvals.exec` forwarding on that same profile so there is only one approval authority.

Read next:

- plugin behavior and limits: [docs/OPENCLAW-SCANNER-SPEC.md](./docs/OPENCLAW-SCANNER-SPEC.md)
- plugin QA matrix: [docs/OPENCLAW-SCANNER-TEST-PLAN.md](./docs/OPENCLAW-SCANNER-TEST-PLAN.md)
- scan daemon design: [docs/OPENCLAW-SCAND-SPEC.md](./docs/OPENCLAW-SCAND-SPEC.md)
- live pod smoke: [docs/SMOKE-TEST.md](./docs/SMOKE-TEST.md)

Links:

- [openclaw-scanner repo](https://github.com/Phantastic-AI/openclaw-scanner) — source for this package
- [OpenClaw](https://github.com/openclaw/openclaw) — the agent runtime this plugin extends
- [ClamAV](https://www.clamav.net/) — open-source antivirus engine used for file scanning
- [MoltPod](https://moltpod.com/) — managed cloud hosting for OpenClaw agents

## Mental Model

### 1. Two Guards, Two Doors

```text
┌──────────────────────────────┐         ┌───────────────────────┐         ┌──────────────────────────────┐
│ Outside World                │         │ AI Agent / OpenClaw   │         │ Outside World                │
│ web pages, APIs, tool output │ ─────▶  │ your pod runtime      │ ─────▶  │ email, shell, git, deploys  │
└──────────────────────────────┘         └───────────────────────┘         └──────────────────────────────┘
               ▲                                         ▲                                         ▲
               │                                         │                                         │
        Ingress Guard                             decides what the                           Egress Guard
      "What's coming in?"                         agent actually sees                      "What's going out?"
      - prompt injection?                                                                   - safe to run?
      - hostile instructions?                                                                - secrets or exfil?
      - wrap or quarantine it?                                                               - needs approval?
```

### 2. Ingress Review For Untrusted Tool Output

```text
Agent calls browser tool
        │
        ▼
Gets webpage HTML back
        │
        ▼
Is this tool trusted or untrusted?
(browser = untrusted content source)
        │
        ▼
Ingress review scans the content
┌───────────────┬───────────────┬──────────────────────────┐
│ ALLOW         │ WARN          │ QUARANTINE               │
│ clean         │ suspicious    │ prompt injection         │
├───────────────┼───────────────┼──────────────────────────┤
│ raw content   │ wrapped as    │ replaced with            │
│ passes        │ untrusted     │ "[content quarantined]"  │
│ through       │ reference     │ the agent never sees it  │
│               │ material      │                          │
└───────────────┴───────────────┴──────────────────────────┘
```

### 3. Approval Loop For High-Impact Egress

```text
Agent wants to run: git push --force origin main
        │
        ▼
Egress guard (`policy.mjs`) => finalAction: "ask"
reasonCode: "high_impact_shell_command"
        │
        ▼
OpenClaw runtime only supports "allow" or "block"
so the first attempt becomes a BLOCK with a structured reason
        │
        ▼
Agent tells the user:
"Security requires approval for this action: force push"
        │
        ▼
User replies: "Do it"
        │
        ▼
Approval-intent review records approval for that exact action
        │
        ▼
Agent retries git push --force origin main
        │
        ▼
Egress guard finds the stored approval and ALLOWS it once
```

PromptScanner is optional. The default path is gateway-backed review using the models already configured on the OpenClaw install.
Gateway review now prefers an internal subagent transport and only falls back to gateway HTTP review when loopback + token auth + explicit review endpoints are safely configured.
If you do not set `trustModel`, `ingressModel`, `egressModel`, or `approvalIntentModel`, the plugin now inherits the pod's configured primary agent model. `approvalIntentModel` falls back to `egressModel` first when you keep approval inside OCS.

## Limitations

- OpenClaw's `before_tool_call` hook only supports allow or block
- so plugin-grade `ask` still appears as a block on the first attempt
- the interactive approval loop now happens on the next turn: the plugin reviews the user's latest reply with `approvalIntentModel` and allows the exact pending action once if the user clearly approved it
- if you enable `openclaw-action-reviewd`, `ask` moves out of the chat turn and into a separate approval service; the user reply in the main session is no longer the approval authority
- if you enable `openclaw-action-reviewd` for exec-capable profiles, disable OpenClaw core `approvals.exec` forwarding on that same profile; otherwise the agent can receive conflicting approval instructions
- if exec-capable tools are exposed, OCS reports `degraded_exec_posture`; ingress and egress still work, but same-UID self-tamper resistance is no longer a credible claim
- live messaging-pod smoke is documented in [docs/SMOKE-TEST.md](./docs/SMOKE-TEST.md)
- exec-capable canary smoke for scan-daemon-backed download and package-install coverage is documented in [docs/ANTIVIRUS-SMOKE-TEST.md](./docs/ANTIVIRUS-SMOKE-TEST.md)
- routine `git push` is allowed; `git push --force`, `git push -f`, and `git push --force-with-lease` require approval

## Backends

### Default

Use OpenClaw's gateway and review models already configured in the install:

- `trustBackend = gateway`
- `ingressBackend = gateway`
- `egressBackend = gateway`
- optionally set `approvalIntentModel` to a smaller or cheaper model for approval-intent classification

### Optional

Ingress review can use PromptScanner instead:

- `ingressBackend = promptscanner`
- set `apiUrl`, `apiKey`, and `callerId`

## Example Config

Minimal gateway-backed config:

```json
{
  "plugins": {
    "entries": {
      "openclaw-scanner": {
        "enabled": true,
        "config": {
          "gatewayReviewTransport": "auto"
        }
      }
    }
  }
}
```

That example relies on the built-in defaults:

- `ingressBackend` defaults to `gateway`, or `promptscanner` if both `apiUrl` and `apiKey` are set
- `egressBackend` defaults to `gateway`
- `trustBackend` defaults to `gateway`
- `gatewayReviewTransport` defaults to `auto`
- `trustModel`, `ingressModel`, and `egressModel` default to the pod's primary agent model
- `approvalIntentModel` defaults to `egressModel`, then the pod's primary agent model

Optional PromptScanner ingress config:

```json
{
  "plugins": {
    "entries": {
      "openclaw-scanner": {
        "enabled": true,
        "config": {
          "ingressBackend": "promptscanner",
          "egressBackend": "gateway",
          "trustBackend": "gateway",
          "apiUrl": "https://promptscanner.moltpod.com",
          "apiKey": "${PROMPTSCANNER_API_KEY}",
          "callerId": "pod-a-openclaw",
          "podId": "moltpod-prod-a"
        }
      }
    }
  }
}
```

## Key Config Fields

Default resolution:

- `ingressBackend`: defaults to `gateway`, or `promptscanner` when `apiUrl` and `apiKey` are both set
- `egressBackend`: defaults to `gateway`
- `trustBackend`: defaults to `gateway`
- `gatewayReviewTransport`: defaults to `auto`
- `trustModel`, `ingressModel`, `egressModel`: default to the pod's primary agent model
- `approvalIntentModel`: defaults to `egressModel`, then the pod's primary agent model
- `persistMode`: defaults to `stub`
- `warnMode`: defaults to `wrap`
- `headlessAskPolicy`: defaults to `block`

- `ingressBackend`: `gateway | promptscanner | disabled`
- `egressBackend`: `gateway | disabled`
- `trustBackend`: `gateway | disabled`
- `ingressModel`
- `egressModel`
- `trustModel`
  - defaults to the pod's configured primary model
- `approvalIntentModel`
  - defaults to `egressModel`, then the pod's configured primary model
- `gatewayBaseUrl`
- `gatewayToken`
- `gatewayReviewTransport`: `auto | subagent | http`
- `approvalTtlSec`
- `apiUrl`, `apiKey`, `callerId` for PromptScanner ingress
- `knownTrustedTools`
- `knownUntrustedTools`
- `reviewCacheTtlSec`
- `trustCacheTtlSec`
- `maxContentChars`
- `antivirusMode`: `auto | disabled | required`
- `antivirusWarnUnavailable`
- `antivirusSocketPath`
- `antivirusClamdConfigPath`
- `antivirusScanTimeoutMs`
- `scaMode`: `auto | disabled | required`
- `scanBrokerMode`: `auto | disabled | required`
- `scanBrokerSocketPath`
- `scaWarnUnavailable`
- `scaWarnDetected`
- `scaWarnInconclusive`
- `osvScannerPath`
- `scaScanTimeoutMs`

## Exec Posture

OCS now records a posture downgrade whenever exec-capable tools are configured or observed:

- `normal`
- `degraded_exec_posture`

This is an honesty feature, not a panic switch. OCS still enforces ingress review, egress policy, approvals, ClamAV, and OSV scanning in degraded posture.

What changes in degraded posture:

- OCS emits a loud warning at startup
- OCS persists posture state to `~/.openclaw/plugins/openclaw-scanner/posture-status.json`
- OCS exposes that state through `openclaw ocs posture-report`

What it means:

- OCS can block tool-mediated access to its own control-plane files
- OCS cannot claim same-UID self-tamper resistance once arbitrary local execution is available
- sandboxed exec should only be treated as stronger than degraded posture when the runtime provides trusted isolation attestation

Protected control-plane paths include:

- `~/.openclaw/openclaw.json`
- `~/.openclaw/plugins/openclaw-scanner/**`

## Antivirus Integration (ClamAV)

OCS integrates with [ClamAV](https://www.clamav.net/), the open-source antivirus engine, to audit file-producing shell actions and record whether antivirus coverage was active when they ran. ClamAV provides signature-based malware detection for files introduced by agent tool calls.

What it detects:

- `git clone`
- package installs like `npm install`, `pnpm install`, `yarn install`, `bun install`
- Python package installs like `pip install` and `uv pip install`
- `cargo install`
- `go get` / `go install`
- `curl` / `wget` downloads
- archive extraction like `tar` and `unzip`

Default behavior:

- `antivirusMode = auto`
- if `clamd` is reachable and `clamonacc` is active for the target path, OCS records `Antivirus: active (on-access scanning enabled)`
- if `clamd` is reachable but on-access coverage is not configured, OCS runs a triggered scan through the `clamd` socket and records `Antivirus: active (triggered scans via clamd)`
- if no usable daemon is available, OCS records `Antivirus: unavailable - files were not scanned` and injects an antivirus warning unless `antivirusWarnUnavailable = false`

### How ClamAV integration works

1. OCS detects the [ClamAV daemon (`clamd`)](https://docs.clamav.net/manual/Usage/Scanning.html#clamd) via its Unix socket (default: `/run/clamav/clamd.ctl`)
2. When a file-producing action runs, OCS checks if [`clamonacc`](https://docs.clamav.net/manual/OnAccess.html) (on-access scanning via fanotify) is active for the target path
3. If on-access scanning is not configured, OCS falls back to triggered scans through the `clamd` socket
4. Scan verdicts (`clean`, `infected`, `unavailable`) are recorded in the antivirus ledger

### ClamAV setup for pod hosts

```bash
# Install ClamAV
sudo apt-get install -y clamav clamav-daemon

# Wait for signature database download, then start
sudo systemctl restart clamav-daemon
sudo systemctl status clamav-daemon

# Verify the socket exists
ls -la /run/clamav/clamd.ctl
```

For managed [MoltPod](https://moltpod.com/) deployments, ClamAV is pre-configured on pod hosts.

### Deliberate v1 scope

- OCS auto-detects `clamd`; it does not fall back to spawning standalone `clamscan`
- low-memory installs without a daemon should either accept the unavailable warning or disable it explicitly
- host-level fanotify / [`clamonacc`](https://docs.clamav.net/manual/OnAccess.html) remains the recommended managed-pod setup for before-access enforcement; OCS treats that as a health/coverage signal, not as a replacement for host configuration
- see the [ClamAV documentation](https://docs.clamav.net/) for full configuration reference

Antivirus state is written to:

- `~/.openclaw/plugins/openclaw-scanner/antivirus-status.json`
- `~/.openclaw/plugins/openclaw-scanner/antivirus-ledger.json`

Print the latest antivirus records with:

```bash
node scripts/print_antivirus_report.mjs --state-dir ~/.openclaw/plugins/openclaw-scanner
```

Or, on OpenClaw builds that expose plugin CLI registration:

```bash
openclaw ocs antivirus-report
openclaw ocs antivirus-report --json --limit 50
```

## Package Vulnerability Scanning (OSV-Scanner)

OCS now runs a second package-focused pass after JavaScript and Python package installs:

- `npm`, `pnpm`, `yarn`, `bun`
- `pip`, `uv pip`

Default behavior:

- `scaMode = auto`
- OCS invokes `osv-scanner scan source -r <install-root> --format json`
- verdicts are recorded as `clean`, `advisory`, `inconclusive`, or `unavailable`
- `required` mode blocks package-install actions if `osv-scanner` is unavailable

Important limits:

- OSV source scanning depends on supported lockfiles and manifests
- `inconclusive` does not mean clean
- OSV catches known vulnerable dependency versions, not a fresh malicious package with no advisory yet

SCA state is written to:

- `~/.openclaw/plugins/openclaw-scanner/sca-status.json`
- `~/.openclaw/plugins/openclaw-scanner/sca-ledger.json`

Print the latest SCA records with the OpenClaw CLI:

```bash
openclaw ocs sca-report
openclaw ocs sca-report --json --limit 50
```

Print current exec posture with:

```bash
openclaw ocs posture-report
openclaw ocs posture-report --json
```

## Scan Daemon (`openclaw-scand`)

OCS can optionally hand malware scanning and package SCA to a separate-UID local scan daemon:

- `scanBrokerMode = auto | required | disabled`
- `scanBrokerSocketPath = /run/openclaw-scand/ocs.sock`

Mode behavior:

- `disabled`: use direct local scanner execution only
- `auto`: prefer the scan daemon, then fall back to direct local scanning with a degraded warning
- `required`: covered scan actions fail closed if the scan daemon is unavailable

The scan daemon improves scanner isolation. It does not move approval ownership out of `openclaw`.

The `openclaw-scand` helper binary is packaged with the npm release for ops and deployment flows. A normal `openclaw plugins install openclaw-scanner` install does not require operators to run it directly.

The public config keys still use `scanBrokerMode` and `scanBrokerSocketPath` for compatibility. The component itself is the `openclaw-scand` scan daemon.

## Action Review Service (`openclaw-action-reviewd`)

OCS can optionally hand `ask` approval ownership to a separate-UID local review service:

- `actionReviewMode = auto | required | disabled`
- `actionReviewSocketPath = /run/openclaw-action-reviewd/ocs.sock`

When enabled, `openclaw-action-reviewd` owns:

- pending action requests
- one-shot approval grants
- denial records
- reviewer-channel polling and intent classification

For exec-capable profiles, `openclaw-action-reviewd` must be the only approval authority. Disable OpenClaw core `approvals.exec` forwarding on the same profile before you turn it on, or the model can surface conflicting approval instructions from two different systems.

This is the slice that starts to improve approval integrity under exec-capable profiles. The plugin still decides whether an action is `allow`, `ask`, or `block`, but the approval itself no longer lives in `openclaw`-owned JSON when `actionReviewMode=required`.

## Hardening Order

The current hardening stages are:

- base OCS inside the OpenClaw hook boundary
- optional `openclaw-scand` scan daemon for a separate-UID scan boundary

The next slice after the scan daemon is a separate-UID approval control plane so approval state stops being `openclaw`-owned JSON.

## RFC: Artifact Taint And Script Recheck

This section is roadmap, not current release behavior.

What we want next:

- keep session taint in memory for ingress
- add a persisted artifact ledger for files, scripts, downloads, archives, and package trees
- key artifact state by canonical path plus content hash
- track per-backend results like `malwareScan`, `packageSca`, and future script review
- re-check script contents at execution time, not just when the file was first written

Why:

- write-time inspection is useful but not final, because the file can change later
- `bash script.sh` or `python script.py` should be judged on the final bytes that will run
- a previous clean result must become stale when the content changes

Proposed storage model:

- session taint stays in OCS memory
- artifact taint moves toward a daemon-owned ledger under `openclaw-scand`
- xattrs, fanotify, IMA, fs-verity, or LSM labels are useful helpers later, but not the source of truth by themselves

Proposed future exec-time behavior:

- script-like launcher detected
- final file contents re-read and re-hashed
- hard malicious or protected-data exfil patterns => `block`
- ordinary offsite send of non-secret data => `ask`
- benign local automation => `allow` or `review`

Important future fallback rule:

- if exec-time script review is too large, too expensive, or incomplete, OCS must not silently treat it as clean
- deterministic rules still run first
- incomplete high-risk review degrades to at least `ask`
- required review that cannot run for a high-risk launcher should `block`

## Logging

The plugin emits structured log lines with an `[openclaw-scanner]` prefix for:

- ingress stubbing
- egress allow / block / approval-required decisions
- approval granted / denied / unclear decisions
- reviewed ingress outcomes
- backend failures

## Review Ledger

For ingress decisions, the plugin now saves a lightweight review ledger at:

- `~/.openclaw/plugins/openclaw-scanner/review-ledger.json`

Each record keeps:

- the source pointer: `sessionKey`, `toolCallId`, `toolName`, and transcript locator when resolvable
- `pendingKey` and `rawHash`
- the structured review response
- review token usage when the backend path exposes it, including subagent-backed gateway review

It does not persist the raw reviewed tool-result body in the ledger.

Print the latest records with:

```bash
node scripts/print_review_ledger.mjs --state-dir ~/.openclaw/plugins/openclaw-scanner
```

Or through the OpenClaw CLI when the plugin is installed:

```bash
openclaw ocs report
openclaw ocs report --json --limit 50
```

## Tests

Run:

```bash
npm test
```

Live pod messaging and scan-daemon smoke are documented in [docs/SMOKE-TEST.md](./docs/SMOKE-TEST.md).

Exec-capable canary scan smoke is documented in [docs/ANTIVIRUS-SMOKE-TEST.md](./docs/ANTIVIRUS-SMOKE-TEST.md).

Important live QA note:

- scan-daemon-required fail-closed can block the real exec/package-install side effect while the assistant still guesses a package name from the user request
- for that phase, use workspace mutation, antivirus/SCA ledgers, and daemon logs as the source of truth
