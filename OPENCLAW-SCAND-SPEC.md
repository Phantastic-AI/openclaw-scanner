# openclaw-scand Daemon Spec

Last updated: 2026-03-25

Canonical markdown: [OPENCLAW-SCAND-SPEC.md](./OPENCLAW-SCAND-SPEC.md)

## Status

This document specifies the next hardened scan boundary for OpenClaw Scanner (OCS).

It is intentionally scoped to scanning only:

- malware scanning
- package vulnerability scanning
- daemon-owned scan logs

It does not move approval state out of OCS yet.

## Goal

Create one stable host-local scan surface that OCS can call for all scan-producing actions.

That surface must:

- run outside the `openclaw` UID
- prefer a Unix socket boundary over direct local process execution
- support current backends:
  - `clamd`
  - `osv-scanner`
- support future backends:
  - OpenClaw Antivirus
  - other artifact or package scanners

## Non-Goals

This slice does not attempt to:

- move approvals out of OCS
- prove sandboxed exec
- replace `clamd`
- make logs cryptographically immutable
- introduce SELinux or AppArmor policy

## Security Model

### Current truth

Today OCS can honestly claim:

- ingress review and egress policy work inside the OpenClaw hook boundary
- OCS blocks tool-mediated access to its own control-plane files
- if exec-capable tools are exposed, OCS enters `degraded_exec_posture`

Today OCS cannot honestly claim:

- same-UID self-tamper resistance for approval state
- scanner isolation when `osv-scanner` is executed directly by OCS

### What this daemon changes

After `openclaw-scand` exists, OCS can additionally claim:

- scan execution crosses a separate-UID boundary
- scan logs are owned by a separate UID
- `osv-scanner` runs inside a daemon-controlled sandbox instead of directly under `openclaw`

After `openclaw-scand` exists, OCS still cannot claim:

- approval integrity across a fully compromised `openclaw` process

That is the next slice after the scan daemon.

## Component Split

### `openclaw`

Runs:

- OpenClaw
- OCS plugin
- normal agent tools

May do:

- request scans from the scan daemon

May not own:

- daemon logs
- daemon config
- daemon socket directory

### `openclaw-scand`

Runs:

- `openclaw-scand` scan daemon service

Owns:

- daemon socket
- daemon config
- daemon logs

Performs:

- `clamd` requests
- bubblewrapped `osv-scanner` runs
- response normalization
- daemon-level structured logging

### `clamd`

Remains:

- an external daemon backend

This spec does not replace it or wrap it.

### Future OpenClaw Antivirus

Will later become:

- another backend behind the same daemon API

## Scan Daemon Modes

The public config keys keep the existing `scanBroker*` names for compatibility.

OCS gets two new config knobs:

- `scanBrokerMode = auto | required | disabled`
- `scanBrokerSocketPath = /run/openclaw-scand/ocs.sock`

Semantics:

- `required`
  - all covered scan actions must use the scan daemon
  - no silent fallback
  - scan daemon unavailable => fail closed for scan-covered actions
- `auto`
  - prefer the scan daemon
  - if unavailable, fall back to current direct local scan path
  - emit a loud degraded warning
- `disabled`
  - use current direct local scan path only

## Covered Actions

The scan daemon handles:

- `malware_scan`
  - downloads
  - archive extraction
  - file-producing actions
  - package installs when file malware coverage is needed
- `package_sca`
  - JavaScript package installs
  - Python package installs

OCS remains responsible for detecting the action class.

## Socket Boundary

### Path

- `/run/openclaw-scand/ocs.sock`

### Ownership

- owner: `openclaw-scand`
- group: `openclaw`
- mode: `0660`

### Trust

The socket is a local host boundary, not a network API.

The scan daemon should use peer credential checks where available and only serve local clients.

## Protocol

Protocol is newline-delimited JSON over the Unix socket.

### Request

```json
{
  "version": 1,
  "requestId": "uuid",
  "op": "package_sca",
  "sessionKey": "agent:main:default",
  "toolCallId": "call-123",
  "actionKind": "package install",
  "roots": ["/workspace/project"]
}
```

### Response

```json
{
  "ok": true,
  "backend": "osv-scanner",
  "verdict": "advisory",
  "reasonCode": "known_vulnerable_dependency",
  "message": "OSV found known vulnerable dependencies.",
  "advisories": [],
  "errors": []
}
```

### Supported ops

- `status`
- `malware_scan`
- `package_sca`

### Failure contract

The scan daemon always returns a structured response.

If the scan daemon cannot perform the request, it returns:

- `ok: false`
- a concrete `reasonCode`
- a bounded `message`

## Backend Behavior

### Malware scan

Primary backend:

- `clamd`

Verdicts:

- `covered`
- `clean`
- `infected`
- `unavailable`
- `error`

### Package SCA

Primary backend:

- `osv-scanner`

Verdicts:

- `clean`
- `advisory`
- `inconclusive`
- `unavailable`
- `error`

Important limit:

- `osv-scanner` catches known vulnerable dependency versions
- it does not catch a fresh malicious package with no advisory yet

## Bubblewrap Profile

In this slice, only `osv-scanner` is bubblewrapped.

The scan daemon itself is not bubblewrapped.

Required `bwrap` properties:

- `--die-with-parent`
- read-only mount view of `/`
- tmpfs for `/tmp`
- dedicated working directory inside the sandbox

Current deployment note:

- `osv-scanner 2.3.5` hung after scan completion under the tighter `--unshare-all` profile on `dev-security`
- v1 therefore uses a read-only mount sandbox without full namespace unsharing
- revisit tighter namespace isolation once OSV exits cleanly under it

The sandbox must not have write access to:

- `~/.openclaw`
- daemon logs
- daemon config
- host secret paths

Known gap:

- `osv-scanner` still runs under the `openclaw-scand` service UID in this slice
- if we later want stronger parser isolation, we can add a dedicated scan worker UID behind the same scan-daemon API

## Logging

Daemon logs are written only by `openclaw-scand`.

### Path

- `/var/log/openclaw-scand/scans.jsonl`

### Record shape

Each record should contain:

- timestamp
- requestId
- op
- sessionKey
- toolCallId
- actionKind
- roots
- backend
- verdict
- reasonCode
- summary counts only

The daemon log must not store raw quarantined tool content.

## Install Model

The public scanner repo owns:

- daemon protocol
- daemon client
- daemon service source

The private ops repo owns:

- systemd unit
- install script
- uninstall script
- smoke scripts
- runbooks

This keeps the product surface public while keeping host mutation logic in ops.

## Install Flow

1. Create `openclaw-scand` system user.
2. Install daemon files to `/opt/openclaw-scand/current`.
3. Install `openclaw-scand.service`.
4. Create `/run/openclaw-scand`.
5. Create `/var/log/openclaw-scand`.
6. Install `bubblewrap`.
7. Ensure the scan daemon can reach `clamd` socket if present.
8. Start and enable the service.
9. Set OCS `scanBrokerMode=required` on hardened pods.

Install must be idempotent.

## Uninstall Flow

1. Refuse uninstall if OCS still uses `scanBrokerMode=required`, unless `--force`.
2. Stop and disable the service.
3. Remove the unit and runtime dir.
4. Optionally purge logs with an explicit flag.
5. Optionally remove the `openclaw-scand` user with an explicit flag.

Uninstall must be boring. No hidden migration or destructive cleanup by default.

## OCS Integration Rules

OCS remains the caller and policy owner.

OCS must:

- detect covered actions
- call the scan daemon when scan-daemon mode requires or prefers it
- normalize scan-daemon responses into existing OCS ledgers and warnings
- keep `degraded_exec_posture` honest

OCS must not:

- silently claim scan-daemon isolation when it is in `auto` fallback mode
- claim approval isolation after the scan daemon lands

## Deferred Work

After this scan daemon is complete, the next hardening slice is:

- move approval ownership and approval logging out of `openclaw` and into a separate-UID control plane
- make that control plane the authority for approval issuance and consumption, instead of shared JSON files owned by `openclaw`
- keep the scan daemon and approval control plane separable at the API level, even if they later share one daemon

This is not a generic "UID check."

It is the point where same-UID approval tamper resistance becomes meaningful.
