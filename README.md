# OpenClaw Scanner (OCS)

[![npm version](https://img.shields.io/npm/v/openclaw-scanner)](https://www.npmjs.com/package/openclaw-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`openclaw-scanner` is the security plugin for OpenClaw. It reviews untrusted tool output before the model sees it, enforces policy on risky tool actions before they run, and records whether files and packages were scanned by antivirus and package-security tools. Today that means ClamAV and OSV-Scanner, but the scanner surface is intended to grow. Coverage is per-call, not periodic.

Three deployment tiers, in order of hardening:

| Tier | Components | When to use |
|------|-----------|-------------|
| Plugin only | `openclaw-scanner` | Chat-first or low-risk tool profiles |
| Plugin + scan daemon | + `openclaw-scand` | Pods that download files or install packages — **recommended** |
| Plugin + scan daemon + action review | + `openclaw-action-reviewd` | Exec-capable or high-impact tool profiles — **recommended** |

The second and third tiers require running helper services. Both binaries ship inside the npm package, but each must run as a dedicated OS service under a separate UID, expose a Unix socket to the plugin, and stay running independently of the OpenClaw process. Installing the npm package does not create those services, and it does not install the supplementary scanner packages those services rely on.

**`openclaw-scand`** is the scan daemon. It runs ClamAV malware scanning and OSV-Scanner — an open-source package vulnerability scanner from Google — under a UID separate from the main OpenClaw user, and wraps OSV-Scanner in a [bubblewrap](https://github.com/containers/bubblewrap) sandbox for additional isolation.

**`openclaw-action-reviewd`** is the action review service. It takes ownership of `ask`-level approvals, polls a reviewer channel, classifies intent, and issues one-shot grants — all outside the main OpenClaw process and under its own UID.

This package includes:

- **Ingress Guard** — reviews untrusted tool output before the next model turn
- **Egress Guard** — blocks unsafe tool actions before they execute
- **Antivirus Integration** — [ClamAV](https://www.clamav.net/)-backed scanning for package installs, downloads, and archive extraction
- **Package Vulnerability Scanning** — [OSV-Scanner](https://google.github.io/osv-scanner/) checks JavaScript and Python package installs against the open-source vulnerability advisory database
- **Scan Daemon** — optional `openclaw-scand` companion for isolated ClamAV and OSV scanning under a separate UID
- **Action Review Service** — optional `openclaw-action-reviewd` companion for out-of-band approval of `ask` actions under a separate UID
- **Exec Posture Reporting** — records `degraded_exec_posture` when exec-capable tools are active, so operators know same-UID tamper resistance is no longer a credible claim

## Start Here

Install the plugin through OpenClaw:

```bash
openclaw plugins install openclaw-scanner
```

That gives you the plugin and both helper binaries. It does not create system services, and it does not install ClamAV or OSV-Scanner for you. Choose a deployment level:

**Plugin only** — good starting point for low-risk profiles. No additional setup required.

**Add the scan daemon** — recommended for pods that download files or install packages. Run `openclaw-scand` as a systemd service or equivalent under a dedicated UID. See [Scan Daemon](#scan-daemon-openclaw-scand) for enablement.

**Add the action review service** — recommended for exec-capable or other high-impact profiles. Run `openclaw-action-reviewd` as a separate service under its own UID. See [Action Review Service](#action-review-service-openclaw-action-reviewd) for enablement.

If you enable `openclaw-action-reviewd` for exec-capable profiles, disable OpenClaw core `approvals.exec` forwarding on that same profile so there is only one approval authority.

Email [team@moltpod.com](mailto:team@moltpod.com) if you need help getting this set up.

Read next:

- plugin behavior and limits: [docs/OPENCLAW-SCANNER-SPEC.md](./docs/OPENCLAW-SCANNER-SPEC.md)
- plugin QA matrix: [docs/OPENCLAW-SCANNER-TEST-PLAN.md](./docs/OPENCLAW-SCANNER-TEST-PLAN.md)
- scan daemon design: [docs/OPENCLAW-SCAND-SPEC.md](./docs/OPENCLAW-SCAND-SPEC.md)
- live pod smoke: [docs/SMOKE-TEST.md](./docs/SMOKE-TEST.md)

Links:

- [OpenClaw](https://github.com/openclaw/openclaw) — the agent runtime this plugin extends
- [ClamAV](https://www.clamav.net/) — open-source antivirus engine used for file scanning
- [OSV-Scanner](https://google.github.io/osv-scanner/) — open-source package vulnerability scanner used for SCA
- [bubblewrap](https://github.com/containers/bubblewrap) — unprivileged Linux sandbox used to isolate OSV-Scanner
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

The `promptscanner` backend is a generic hook for any external prompt-scanning API you already operate — your own service or a third party's. It is not a named product and OCS does not bundle or require one. If you do not run a dedicated prompt-scanning layer, the gateway backend handles ingress review through the models already configured on your OpenClaw install and nothing else is needed.
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

To route ingress review through an external prompt-scanning API:

- `ingressBackend = promptscanner`
- set `apiUrl`, `apiKey`, and `callerId`

The `promptscanner` backend name identifies the hook type, not a required product. Point it at any HTTP endpoint that accepts OCS's ingress review format.

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

OCS tracks two posture states and is honest about which one applies:

- `normal`
- `degraded_exec_posture`

- `normal` means no exec-capable tools are configured or observed
- `degraded_exec_posture` means exec-capable tools are active

This is an honesty feature, not a panic switch. In degraded posture, OCS still enforces ingress review, egress policy, approvals, ClamAV scanning, and OSV-Scanner checks. What it cannot credibly claim is that a same-UID agent cannot reach its own control-plane files.

**What changes in degraded posture:**

- OCS emits a loud warning at startup
- OCS persists posture state to `~/.openclaw/plugins/openclaw-scanner/posture-status.json`
- OCS exposes that state through `openclaw ocs posture-report`

**What it means in practice:**

- OCS can block tool-mediated access to its own control-plane files
- OCS cannot claim same-UID self-tamper resistance once arbitrary local execution is available
- sandboxed exec should only be treated as stronger than degraded posture when the runtime provides trusted isolation attestation

Protected control-plane paths:

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

The scan daemon runs ClamAV malware scanning and OSV-Scanner — an open-source package vulnerability scanner — under a UID separate from the main OpenClaw process. This removes scanning from the OpenClaw trust boundary without requiring a remote service.

Recommended for any pod that downloads files or installs packages, and as part of the hardening baseline for exec-capable profiles.

### Enabling `openclaw-scand` on a self-hosted machine

The binary ships inside the npm package. You still need to create the system service manually.

### Supplementary packages you also need

`openclaw-scand` orchestrates two scanners. It does not bundle or install them:

- **ClamAV / `clamd`** for malware scanning
- **OSV-Scanner** for package vulnerability scanning

On a Debian or Ubuntu host, a practical self-hosted setup looks like this:

```bash
# ClamAV daemon
sudo apt-get update
sudo apt-get install -y clamav clamav-daemon
sudo systemctl enable --now clamav-daemon

# OSV-Scanner
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
sudo install -m 0755 "$HOME/go/bin/osv-scanner" /usr/local/bin/osv-scanner
```

If `clamd` or `osv-scanner` is missing:

- scan coverage becomes unavailable or degraded
- `required` mode will fail closed for covered actions
- `auto` mode will fall back with a warning

1. Install the package where the helper binary will be available:

   ```bash
   npm install -g openclaw-scanner
   ```

2. Create a dedicated user and service for `openclaw-scand`.

3. Expose its Unix socket at `/run/openclaw-scand/ocs.sock`, or set `scanBrokerSocketPath` explicitly if you use a different path.

4. Set `scanBrokerMode=required` if you want covered scan actions to fail closed when the daemon is unavailable. Use `auto` if you want a degraded fallback to direct local scanning.

### Config keys

- `scanBrokerMode`: `auto | required | disabled`
- `scanBrokerSocketPath`: default `/run/openclaw-scand/ocs.sock`

| Mode | Behavior |
|------|----------|
| `disabled` | Direct local scanner execution only |
| `auto` | Prefer the daemon; fall back to direct scanning with a degraded warning |
| `required` | Fail closed if the daemon is unavailable |

The scan daemon improves scanner isolation. It does not move approval ownership out of the OpenClaw process — that is the job of the action review service.

The public config keys still use `scanBrokerMode` and `scanBrokerSocketPath` for compatibility. The component itself is the `openclaw-scand` scan daemon.

## Action Review Service (`openclaw-action-reviewd`)

The action review service takes ownership of `ask`-level approvals and processes them outside the main OpenClaw process, under a separate UID. It polls a reviewer channel, classifies intent, and issues one-shot grants. Approvals are no longer tied to the agent's chat turn.

Recommended for exec-capable profiles and any profile where high-impact tool actions require an out-of-band approval path. For simpler chat-first deployments, the plugin's in-process approval loop is sufficient.

### Enabling `openclaw-action-reviewd` on a self-hosted machine

The binary ships inside the npm package. You still need to create the system service manually.

1. Install the package where the helper binary will be available:

   ```bash
   npm install -g openclaw-scanner
   ```

2. Create a dedicated user and service for `openclaw-action-reviewd`, with access to your reviewer channel credentials and gateway config.

3. Expose its Unix socket at `/run/openclaw-action-reviewd/ocs.sock`, or set `actionReviewSocketPath` explicitly if you use a different path.

4. Set `actionReviewMode=required` if you want `ask` actions to fail closed when the review service is unavailable. Use `auto` if you want a degraded fallback to the plugin's in-process approval loop.

When enabled, `openclaw-action-reviewd` owns:

- pending action requests
- one-shot approval grants
- denial records
- reviewer-channel polling and intent classification

For exec-capable profiles, `openclaw-action-reviewd` must be the only approval authority. Disable OpenClaw core `approvals.exec` forwarding on the same profile before you turn it on, or the model can surface conflicting approval instructions from two different systems.

### Config keys

- `actionReviewMode`: `auto | required | disabled`
- `actionReviewSocketPath`: default `/run/openclaw-action-reviewd/ocs.sock`

| Mode | Behavior |
|------|----------|
| `disabled` | Approvals handled by the plugin's in-process loop |
| `auto` | Use the review service if available; fall back to in-process approval with a degraded warning |
| `required` | Fail closed if the review service is unavailable |

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
