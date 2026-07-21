# Changelog

All notable changes to Replicant are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Claims that have not been validated against a live vendor build or a real host are marked `[Unverified]`, and stay marked until they are.

## [Unreleased]

The `v0.1.0` tag was cut before these landed. Since the release has not been
published and nothing has consumed the tag, these are expected to fold into
`0.1.0` by re-cutting it at publication rather than shipping as `0.1.1`.

### Added

- **Continuous integration.** GitHub Actions across four jobs: Python on 3.11 and
  3.12, frontend on Node 18 and 20, shell linting, and the installer executed
  inside real `debian:12`, `rockylinux:9` and `ubuntu:22.04` containers with
  asserted outcomes. The installer job is a regression guard for the two defects
  found during pre-release validation, both of which are invisible to a dry run.
- **Frontend test suite.** vitest with jsdom and Testing Library, eight tests.
  The Python suite grew to 238.

### Fixed

- **Verification could report success for a command it never ran.** In
  `scripts/install.sh`, `verify_cmd` allocated its stderr capture file with an
  unchecked `mktemp`. Where mktemp failed (read-only or full `/tmp`, hardened
  container), the path was empty, the redirect could not open, the command never
  executed, and the function returned 0 regardless, printing a green `[ok]` for
  verification that had not happened. Temp allocation is now checked and fails
  closed.
- **Duplicated failure banner.** `set -E` propagates the `ERR` trap into
  command-substitution subshells, so an unguarded temp-file assignment printed
  six lines of failure output where three are specified.
- **`/api/catalog` reported every technique as implemented** from a hardcoded id
  set rather than from the engine, making the "not yet implemented" interface
  states unreachable and guaranteeing a wrong answer for any future technique
  added to the catalog without a planner.
- **CLI diagnostics went to stdout.** All nine error paths now write to stderr,
  so redirecting stdout no longer hides the reason a run refused.
- **`vendorLabel` returned functions for prototype keys.** `VENDOR_LABELS[id] ?? id`
  resolved `"constructor"` and `"toString"` through the prototype chain, so the
  `??` fallback never fired. Now an own-property check.

### Changed

- The events-per-second cap is documented as a **fixed-window average** rather
  than an instantaneous ceiling, at the limiter, in the README safety table, and
  below. It was previously stated only as "a cap", which reasonably reads as the
  stronger guarantee.

## [0.1.0] - 2026-07-21

First public release.

### Added

**Technique catalog.** Eleven techniques, `REP-001` through `REP-011`, each mapped one-to-one to a named detection use case and to MITRE ATT&CK:

| ID | Technique | Use case | ATT&CK |
|---|---|---|---|
| REP-001 | Periodic C2 callback (low-and-slow) | UC-001 | T1071, T1571 |
| REP-002 | Vertical port scan (one host, many ports) | UC-002a | T1046 |
| REP-003 | Horizontal sweep (one port, many hosts) | UC-002b | T1046, T1018 |
| REP-004 | DNS tunneling / DNS exfil | UC-003 | T1071.004, T1048.003 |
| REP-005 | Outbound exfil volume anomaly | UC-004 | T1041, T1048 |
| REP-006 | Destination fan-out burst | UC-005 | T1018, T1046 |
| REP-007 | Brute force and password spray | UC-006 | T1110, T1110.003, T1110.004 |
| REP-008 | Newly observed external destination per host | UC-007 | T1071, T1583 |
| REP-009 | IDS/IPS event-rate spike | UC-008 | T1595, T1190 |
| REP-010 | Denied outbound connection burst | UC-009 | T1071, T1090 |
| REP-011 | VPN geovelocity anomaly | UC-010 | T1078, T1133 |

**Vendor profiles.** Three, selectable with `--vendor {fortigate,paloalto,checkpoint}`, in the Rich menu (`[v]`), or in the web UI. One technique catalog and one scenario engine drive every vendor; only serialization differs. Each has a reference document with seven golden sample lines used as the correctness oracle, reproduced byte-for-byte by tests.

- **FortiGate (FortiOS).** Modeled first, field-for-field.
- **Palo Alto (PAN-OS)** and **Check Point (Log Exporter).** `[Unverified]` against live builds; the reference docs are grounded in vendor documentation and published samples, and say so.

**Scenario composition.** Three curated chains that compose the existing techniques into one deterministic multi-stage CEF timeline sharing a synthetic through-line:

- `SCEN-001` Perimeter intrusion to exfiltration (3 stages)
- `SCEN-002` Recon, first contact, DNS exfil (3 stages)
- `SCEN-003` External access to foothold (4 stages)

Each run writes an advisory document beside its manifest, mapping the chain to ATT&CK tactics, naming the cross-stage correlation key, and flagging tactics the catalog can exercise but this chain does not. The advisory is deterministic and derived from the composed events; no model generates it. It is coverage context only, and states so in its own header: you author the detection design.

**Three surfaces, one orchestrator.** Headless CLI (`replicant list|connect|run|scenario|web|menu`), a Rich terminal menu, and a browser UI with an embedded terminal. Anything the menu can do, the CLI can do headless.

**Transports.** UDP, TCP, and TLS syslog, with a loopback connectivity test.

**Safety model.** Five non-negotiable rules, verified behaviorally rather than only by inspection: single-collector egress that fails closed when no collector is configured; synthetic entities only (RFC1918 plus the documentation ranges, non-resolvable DNS parents); log strings only, with no command execution, scanning, or data movement; an events-per-second cap; and a manifest written for every run.

**Determinism.** Same seed plus technique plus parameters yields byte-identical output. Verified across 181,071-line scenario runs, advisories included.

**Linux installer.** `scripts/install.sh` handles prerequisites, virtualenv, package install, frontend build, and then verifies the result by loading the catalog, rendering CEF, and sending over loopback UDP. Flags: `--no-web`, `--dev`, `--yes`, `--dry-run`.

### Known limitations

- **Installer coverage.** Verified against live package repositories on Debian 12, Rocky 9, and Ubuntu 22.04 (where the correct behavior is a refusal). `[Unverified]` on AlmaLinux, on RHEL proper as distinct from Rocky, and on Arch and openSUSE, whose package mappings are carried over unexercised. The `sudo` elevation path, the interactive consent prompt, and the no-TTY refusal are also `[Unverified]`, because the container runs that validated everything else execute as root.
- **Ubuntu 22.04, Debian 11, and RHEL-family 8** ship Python below 3.11 and cannot be satisfied from their own repositories. The installer refuses on these with guidance rather than installing packages that would not help. Ubuntu 22.04 offers `python3.11` only as a release candidate (`3.11.0~rc1`), which the installer deliberately declines.
- **The events-per-second cap is a fixed-window cap,** not an instantaneous one. It counts to the cap, sleeps the remainder of the wall second, then resets, so events cluster at the head of each window. A sliding one-second window straddling a boundary was measured once at 59 against a cap of 50; the overall delivered rate held at 49.94/s. Treat the guarantee as a fixed-window average.
- **The web UI has no scenario surface.** Scenario composition is CLI and Rich menu only. Deferred by design, and covered by a test that asserts the absence so a later partial implementation is caught.
- **No frontend test runner.** The Python side is covered by 235 tests; the SPA has no vitest suite.
- **Signature IDs** for DNS `dns-query` (54803) and SSL-VPN tunnel-up (39947) are `[Unverified]` against a live FortiOS build and carry inline notes saying so. Confirm before customer use.

### Security

Replicant writes log text. It never executes commands, scans hosts, resolves or contacts real infrastructure, or moves real data. Attack names, signature labels, and byte counts are fields in a log line and nothing more.

Installing pulls packages from your distribution's repositories, PyPI, and npm. That is install-time egress and is separate from the runtime rule, which is unchanged: at run time the only network egress is the collector you configure.

### Attribution

This project uses MITRE ATT&CK. Copyright 2026 The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation. ATT&CK is a registered trademark of The MITRE Corporation. Use does not imply endorsement.

Licensed under the Apache License 2.0. Third-party notices are in [`NOTICE`](NOTICE).

[0.1.0]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.1.0
