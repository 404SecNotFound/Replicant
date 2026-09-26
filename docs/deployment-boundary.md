# Deployment boundary: detection lab, not production SIEM

Replicant is a synthetic-telemetry generator for **detection engineering in a lab
or a pre-production detection pipeline**. It is not a production monitoring
component and must not be deployed as one. This boundary is part of the roadmap
2026-09 safety workstream (`docs/roadmap-2026-09.md`, item 3) and rides with the
destination-conditional synthetic marker.

## What that means in practice

- **Point it at a detection lab or a staging collector, not a live production SIEM
  ingestion pipeline.** Replicant injects fabricated, attack-shaped firewall logs.
  On a production collector those lines are indistinguishable from a real incident
  to anyone who has not been briefed: they page the on-call shift, skew dashboards,
  and pollute searchable history.

- **Every line on a non-loopback send is tagged by default.** Replicant stamps a
  `flexString1Label=ReplicantSynthetic` marker, carrying the run id, on every line
  it sends off loopback, so an analyst can filter lab data out of production views
  and de-conflict a "3am fake attack" against the run manifest. The marker is off
  for a loopback or file-only (`--to-file --no-send`) run, where the golden line
  is the format oracle and fidelity is what matters; a run that both sends live
  and writes a file marks both, so the file mirrors what went on the wire.
  `--no-marker` removes it and the override is logged on a live send.
  `flexString1` is a flex slot none of the three vendor profiles populate, so
  marking corrupts no field a detection reads.

- **Authorize the run out of band.** Before sending to any shared collector,
  agree with the SOC on the destination, technique, source and destination
  entities, and window. The run manifest records the executed values, and its
  `marker_attestation` line states the marking decision. Preserve it as the
  durable execution and audit record; a self-generated manifest is not proof of
  prior approval.

- **The safety invariants still bind.** One fail-closed egress to the operator's
  configured collector, synthetic entities only, log strings only (never real
  attacks or traffic), the events-per-second cap, and a manifest per run. See the
  safety model in the README and the non-negotiable safety rules in `CLAUDE.md`.

## Running the web UI where others can reach it

Added 2026-09-26 with the web-layer review (`docs/security-review-2026-09-26.md`).

- **Restrict destinations.** `replicant web --collector-allow 10.0.20.0/24:514`
  (CIDR plus an optional port, repeatable, IPv6 bracketed as
  `[2001:db8::/32]:6514`) limits where web callers may connect-test and send.
  Only IP literals match. Unset, any destination the host can reach is allowed
  and the server logs a warning at startup. The CLI and the Rich menu are not
  governed by it, so setting it turns the terminal tab off unless
  `--enable-terminal` is also given.
- **The terminal tab follows reachability.** It defaults on only for a loopback
  bind with no non-loopback `--allowed-host` and no `--collector-allow`. Behind a
  reverse proxy it is off unless `--enable-terminal` is passed. The terminal
  child runs with a minimal environment and `REPLICANT_WEB_CONFINED=1`.
- **Behind a proxy, name it.** `--forwarded-allow-ips` lists the proxy whose
  `X-Forwarded-For` is trusted. Unset, none is, whatever `FORWARDED_ALLOW_IPS`
  says.
- **TLS CA bundles for the web UI** go in `<config>/ca/` and are named by file
  name only. A path is refused.
- **Built-in ceilings.** Request bodies over 64 KiB are refused (413). One
  validation at a time, never beside a run (409). Ten connect tests per session
  per minute, thirty per server (429). Sixteen live event streams (429). The
  newest `--evidence-keep` (default 20) evidence packs are kept.

## The systemd unit's sandbox

`scripts/replicant-web.service` runs the server with:

| Setting | Why |
|---|---|
| `ProtectSystem=strict`, `ReadWritePaths=` `.config` `manifests` `out` | The checkout and its `.venv` are read-only, so the process cannot rewrite the code it runs. The three data directories are created by `ExecStartPre` if missing. |
| `ProtectHome=yes`, `PrivateTmp=yes`, `UMask=0077` | Config lives beside the checkout, not in a home directory. New files are owner-only. |
| `PrivateDevices=yes` | A private `/dev` that still provides `ptmx` and devpts for the terminal. Observed working, not assumed. |
| `ProtectKernelTunables/Modules/Logs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible` | Nothing here needs any of it. `ProcSubset=pid` is deliberately absent: it hides `/proc/net/route`, which the connect test reads to show the route. |
| `NoNewPrivileges`, empty `CapabilityBoundingSet`, `RestrictSUIDSGID`, `RestrictNamespaces`, `RestrictRealtime`, `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service` | No privileges to gain, none to keep. |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | IP for the collector and the listener, Unix for local IPC. |
| `MemoryMax=1536M`, `TasksMax=256` | Sized from the largest validation (REP-004 high, about 830 MB) plus the process and a terminal. Past it the kernel stops this unit, not the host. |

`scripts/verify-systemd-unit.sh` asserts these from inside the service's mount
namespace under a real systemd in CI (job `systemd-unit`), including opening a
terminal PTY. `systemd-analyze security` reports 1.2 for this unit; it reported
8.4 before.

## Why this is a boundary and not a suggestion

An enterprise will not, and should not, approve an unattested attack-log injector
near a production pipeline. Keeping Replicant on the lab side of the boundary,
with prior approval recorded through the operator's normal change process, the
marker on, and the manifest retained as the execution record, is what turns a
"fake attack incident" into an authorized, auditable, reversible test. It is the
hard precondition for any live operational pilot.
