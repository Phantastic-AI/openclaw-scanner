# OCS Antivirus And Package-Scan Smoke Test

Last updated: 2026-03-25
Canonical spec: [OPENCLAW-SCANNER-SPEC.md](./OPENCLAW-SCANNER-SPEC.md)

This protocol verifies the exec-capable canary path on a real pod host:

- scan-daemon-backed ClamAV download scanning
- scan-daemon-backed ClamAV package-install scanning
- scan-daemon-backed OSV package SCA
- optional scan-daemon-required fail-closed behavior

It uses a coding-profile canary because messaging-profile pods do not expose `exec`.

## What this smoke proves

- file-producing shell actions are detected by OCS
- `openclaw-scand` is the transport for scan-backed exec actions
- OCS records `clean` with `protection=triggered` when `clamd` is reachable
- OCS records `advisory` for a known vulnerable npm dependency through OSV
- scan-daemon-required mode can stop the real package-install side effect even if the assistant reply is misleading

## What this smoke does not prove

- fanotify / `clamonacc` on-access enforcement
- malware quarantine behavior
- perfect user-visible inline warning delivery on every deployed OpenClaw build
- malicious-package heuristics beyond ClamAV and OSV

## Canary Setup

Use an isolated state dir on the pod host so the smoke does not disturb the live messaging gateway.

Recommended canary state:

- `OPENCLAW_STATE_DIR=/home/openclaw/.openclaw-avsmoke`
- `OPENCLAW_CONFIG_PATH=/home/openclaw/.openclaw-avsmoke/openclaw.json`
- `OPENCLAW_GATEWAY_PORT=19011`
- `tools.profile = "coding"`
- no channel plugins
- OCS enabled from `/home/openclaw/.openclaw-avsmoke/extensions/openclaw-scanner`
- loopback gateway on a separate port such as `19011`

## Preferred Smoke Command

From the ops repo on the controller host:

```bash
SMOKE_INCLUDE_SCAN_DAEMON_FAILCLOSED=1 ./smoke/smoke_remote_scanner.sh 51.210.13.102 qa-062
```

Expected evidence:

- `posture-report` shows `degraded_exec_posture`
- the download session writes `scand-download/example.html`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-status.json` reports:
  - `status: "active"`
  - `protection: "triggered"`
  - `transport: "openclaw-scand"`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-ledger.json` contains a download record with:
  - `verdict: "clean"`
  - `protection: "triggered"`
  - `transport: "openclaw-scand"`
- the package-install session writes `scand-npm/package-lock.json`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-ledger.json` contains a package-install record with:
  - `verdict: "clean"`
  - `transport: "openclaw-scand"`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/sca-ledger.json` contains a package-install record with:
  - `verdict: "advisory"`
  - `transport: "openclaw-scand"`
  - advisory ids `GHSA-vh95-rmgr-6w4m` and `GHSA-xvch-5gv4-984h`
- `/var/log/openclaw-scand/scans.jsonl` contains one `malware_scan` record and one `package_sca` record for the package-install session
- with `SMOKE_INCLUDE_SCAN_DAEMON_FAILCLOSED=1`, the negative phase passes only if:
  - the workspace check prints `MISSING`
  - the scan-daemon log does not get a new record for the blocked action

## Reporting Commands

Repo-local report script:

```bash
node scripts/print_antivirus_report.mjs --state-dir ~/.openclaw/plugins/openclaw-scanner
```

Live canary report on the pod host:

```bash
env OPENCLAW_STATE_DIR=/home/openclaw/.openclaw-avsmoke \
    OPENCLAW_CONFIG_PATH=/home/openclaw/.openclaw-avsmoke/openclaw.json \
    OPENCLAW_GATEWAY_PORT=19011 \
    node /home/openclaw/code/openclaw/dist/index.js ocs antivirus-report --json --limit 20

env OPENCLAW_STATE_DIR=/home/openclaw/.openclaw-avsmoke \
    OPENCLAW_CONFIG_PATH=/home/openclaw/.openclaw-avsmoke/openclaw.json \
    OPENCLAW_GATEWAY_PORT=19011 \
    node /home/openclaw/code/openclaw/dist/index.js ocs sca-report --json --limit 20

env OPENCLAW_STATE_DIR=/home/openclaw/.openclaw-avsmoke \
    OPENCLAW_CONFIG_PATH=/home/openclaw/.openclaw-avsmoke/openclaw.json \
    OPENCLAW_GATEWAY_PORT=19011 \
    node /home/openclaw/code/openclaw/dist/index.js ocs posture-report --json
```

## Verified Live Notes

Verified on `51.210.13.102` on March 25, 2026 UTC:

- the smoke used an isolated coding-profile canary gateway under `~/.openclaw-avsmoke`
- canary CLI needed `OPENCLAW_GATEWAY_PORT=19011`; without it, the CLI drifted back to the main `18789` gateway
- scan-daemon-backed download recorded antivirus `clean`
- scan-daemon-backed `npm install minimist@0.0.8 --ignore-scripts` recorded antivirus `clean` and SCA `advisory`
- scan-daemon-required negative check left the workspace path absent even though the assistant reply still guessed the package name

Verified on Vince pod `51.210.14.27` on March 22, 2026 UTC with OpenClaw `2026.3.14`:

- benign `npm install` egress review no longer blocks on truncated `/v1/responses` output because OCS falls back to `chatCompletions`
- no-ClamAV run recorded `status=unavailable`, `protection=unavailable`, and the warning text in the antivirus ledger/report while the final assistant reply still failed to surface that warning
- with-ClamAV run recorded `status=active`, `protection=triggered`, `verdict=clean`, and the final assistant reply correctly reported that no antivirus warning applied

## Known Compatibility Gaps On OpenClaw 2026.3.2

- plugin subagent review transport was not usable on the deployed pod build, so the canary used local loopback HTTP review instead
- plugin CLI registration for `openclaw ocs ...` was not exposed on the deployed pod build even though repo tests pass
- live `after_tool_call` payloads on this pod build did not carry reliable `sessionKey` / `toolCallId` attribution into the antivirus ledger
- Gemini did not reliably echo the unavailable-scan warning in the final assistant reply even when OCS injected warning context; the ledger and gateway log were the source of truth for the no-ClamAV canary

## Known Compatibility Gap On OpenClaw 2026.3.14

- on Vince's latest available `2026.3.14` build, no-ClamAV detection, ledger/report output, and benign egress review all work, but the final assistant reply still does not reliably surface the unavailable-scan warning even when OCS injects warning context before the next model turn
