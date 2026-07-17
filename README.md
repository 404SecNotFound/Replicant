# Replicant

Replicant generates safe, synthetic FortiGate firewall and network security
telemetry in CEF, streams it over syslog to a SIEM (LogRhythm first), and is
driven by a MITRE ATT&CK grounded technique catalog. A detection engineer picks a
technique from a menu and Replicant emits realistic firewall logs that exercise
the matching detection.

Replicant writes log strings. It never executes commands, never scans real hosts,
never resolves or contacts real C2, and never moves real data. Byte counts and
attack names are fields in a log line, nothing more.

## Safety and scope

Use Replicant only in environments you own or are authorized to test.

- The only network egress is to the operator-configured collector. With no
  collector configured, sends fail closed.
- All entities are synthetic. Default addresses use RFC1918 and IANA
  documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). DNS parent
  domains are non-resolvable synthetic names. A configuration that reaches outside
  those ranges is rejected at build time.
- Every run writes a manifest (seed, technique, params, entities, target, event
  count, start and end time in UTC+04:00) so telemetry lines up with detections.
- A configurable events-per-second cap protects the operator's own collector.

## Install

Python 3.11+ is required.

```
python3.12 -m venv .venv
./.venv/bin/pip install -e ".[dev]"
```

## How to run

Headless CLI (the menu and CLI share one Orchestrator; anything the menu can do,
`replicant run ...` can do):

```
replicant list
replicant connect --host 10.20.0.50 --port 514 --transport udp --test
replicant run REP-001 --intensity medium --duration 30m --seed 1337
replicant run REP-004 --intensity high --duration 15m --to-file ./out/dns.log --no-send
replicant menu        # interactive Rich menu
```

Phase 1 implements three techniques end to end:

| ID | Technique | FortiGate log | UC |
|----|-----------|---------------|-----|
| REP-001 | Periodic C2 callback (low-and-slow) | traffic:forward accept | UC-001 |
| REP-002 | Vertical port scan | traffic:forward deny | UC-002a |
| REP-004 | DNS tunneling / DNS exfil | dns:dns-query pass | UC-003 |

The remaining catalog entries appear in `replicant list` and are scheduled for
Phase 2. Signature IDs marked `[Unverified]` in the catalog and reference must be
confirmed against a live FortiOS build before customer use.

## Web UI (with embedded terminal)

Replicant also ships a browser UI that drives the same Orchestrator. It runs on a
random loopback port and opens automatically:

```
pip install -e ".[web]"       # FastAPI + uvicorn
(cd webui && npm install && npm run build)   # one-time frontend build
replicant web                 # prints http://127.0.0.1:<port>/?token=...
```

The page has two modes. The Dashboard configures a collector and sends a test
log, browses the technique catalog, and runs a technique with a live CEF event
stream, a progress bar, a Stop control, and the run manifest. The Terminal tab is
a real embedded TTY (xterm.js over a websocket PTY bridge) running the actual
`replicant menu`, so you can drop into the full interactive menu from the browser.

Safety: the server binds to loopback only, every API and websocket call requires a
per-session token carried in the URL, and a middleware rejects any request whose
Host header is not localhost (a DNS-rebinding guard). Web runs use the same
fail-closed Orchestrator, eps cap, and manifest as the CLI. The embedded terminal
requires a POSIX host (it uses a pseudo-terminal).

The frontend is React 18 + Vite + TypeScript + Tailwind with shadcn-style
components; source is in `webui/`.

## Architecture

Presentation (Rich menu + headless CLI) -> Orchestrator -> Scenario Engine +
Connection Manager -> Vendor Profile (FortiGate) + Syslog Emitter -> CEF
Serializer -> Transport. The Scenario Engine and CEF Serializer are
vendor-neutral. Adding a firewall is implementing the `VendorProfile` interface
plus a reference file. See `docs/blueprint.md`.

Determinism: the same seed plus technique plus params yields the same event
stream. Event times are `anchor_epoch + deterministic offset`, so `--to-file`
output is byte identical across runs with the same seed.

## Testing

```
./.venv/bin/pytest        # unit + golden + loopback tests
./.venv/bin/black --check replicant tests
./.venv/bin/ruff check replicant tests
./.venv/bin/mypy replicant
```

The CEF serializer plus FortiGate profile reproduce the seven constructed golden
sample lines in `docs/fortigate-cef-reference.md` byte for byte; that file is the
correctness oracle. A loopback UDP/TCP transport test confirms lines arrive intact
with no external collector.

## Prior art

Replicant is not the first synthetic log generator. Its design was shaped by, and
credits, [summved/log-generator](https://github.com/summved/log-generator)
(GPL-3.0, no code reused) and Cisco Talos EvidenceForge (MIT) as prior art. See
`docs/prior-art-and-licensing.md` and `NOTICE`.

## MITRE ATT&CK

This project uses MITRE ATT&CK. (c) 2026 The MITRE Corporation. This work is
reproduced and distributed with the permission of The MITRE Corporation. ATT&CK is
a registered trademark of The MITRE Corporation. Use does not imply endorsement.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
