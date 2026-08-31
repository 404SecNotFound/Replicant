Replicant generates safe, synthetic firewall telemetry in CEF, streams it over syslog to your SIEM, and ties every generated behavior to a named detection use case. You pick an ATT&CK-grounded technique from a menu; it emits realistic logs that exercise the matching detection.

It writes log text. It never executes commands, scans hosts, resolves or contacts real infrastructure, or moves real data.

## What is in it

**Eleven techniques**, `REP-001`..`REP-011`, each mapped one-to-one to a detection use case and to ATT&CK: periodic C2 callback, vertical port scan, horizontal sweep, DNS tunneling, outbound exfil volume anomaly, destination fan-out, brute force and password spray, newly observed destination, IDS/IPS rate spike, denied outbound burst, and VPN geovelocity.

**Three vendor profiles**, selectable with `--vendor`: FortiGate (FortiOS), Palo Alto (PAN-OS), and Check Point (Log Exporter). One catalog and one engine drive all three; only serialization differs. Each has a reference doc with seven golden sample lines that tests reproduce byte-for-byte.

**Scenario composition.** Three curated chains compose the techniques into a single deterministic multi-stage timeline sharing a synthetic through-line, with an advisory document mapping the chain to ATT&CK tactics, naming the cross-stage correlation key, and flagging tactics it does not cover. The advisory is derived from the composed events; no model writes it, and it says in its own header that you author the detection design.

**Three surfaces over one orchestrator.** Headless CLI, a Rich terminal menu, and a browser UI with an embedded terminal. Anything the menu does, the CLI does headless.

**Deterministic.** Same seed plus technique plus parameters gives byte-identical output, verified across 181,071-line runs including the advisories.

## Safety model

Five rules, verified behaviorally rather than by inspection: egress goes only to the collector you configure and fails closed when none is set; all entities are synthetic (RFC1918 plus the RFC 5737 documentation ranges; DNS parents from the reserved documentation domains and the non-resolvable `.invalid` TLD, neither of which Replicant ever resolves); log strings only, no execution or scanning; an events-per-second cap; a manifest for every run.

Installing pulls packages from your distribution, PyPI, and npm. That is install-time egress and is separate from the runtime rule, which does not loosen.

## Install

```bash
git clone https://github.com/404SecNotFound/Replicant.git
cd Replicant
./scripts/install.sh
```

The installer resolves prerequisites by asking your package manager what it would actually install, **before** it asks for sudo, and refuses with guidance rather than installing packages that would not help.

| Distribution | Status |
|---|---|
| Debian 12, Ubuntu 24.04+, Fedora | Full install including the web UI. Verified on Debian 12. |
| RHEL / Rocky / Alma 9 | CLI installs cleanly. Web UI needs Node 18+: run `sudo dnf module enable nodejs:20` first, or use `--no-web`. Verified on Rocky 9. |
| Ubuntu 22.04, Debian 11, RHEL 8 | Refused with guidance. These ship Python below 3.11, and Ubuntu 22.04 offers `python3.11` only as a release candidate. Verified on Ubuntu 22.04. |

## Known limitations

Read these before deploying it anywhere that matters.

- **Event times come from a fixed anchor, which is what makes runs byte-identical.** The syslog header is stamped at send time, so on a live send the two disagree. If your SIEM keys on receipt time the run looks normal; if it keys on the parsed event time, recent-window rules will not fire, which looks exactly like a broken detection. Pass `--anchor now` when sending live. Replicant warns you if you forget.
- The **Palo Alto and Check Point references are `[Unverified]`** against live builds. They are grounded in vendor documentation and published samples, and the docs say so. FortiGate is the one modeled field-for-field first.
- **Two FortiGate signature IDs are `[Unverified]`**: DNS `dns-query` 54803 and SSL-VPN tunnel-up 39947. Both carry inline notes. Confirm on a live FortiOS build before customer use.
- **Installer coverage is partial.** Verified against live repositories on Debian 12, Rocky 9, and Ubuntu 22.04. `[Unverified]` on AlmaLinux, RHEL proper as distinct from Rocky, Arch, and openSUSE. The `sudo` elevation path, the interactive consent prompt, and the no-TTY refusal are also `[Unverified]`, because the container runs that validated everything else execute as root.
- **The events-per-second cap is a fixed-window average**, not an instantaneous guarantee. It counts to the cap, sleeps out the wall second, then resets, so events cluster at the head of each window. A sliding one-second window straddling a boundary was measured once at 59 against a cap of 50; the overall rate held at 49.94/s.
- **The web UI has no scenario surface.** Scenario composition is CLI and menu only, by design.

## Verification

249 Python tests, 9 frontend tests, black, ruff, mypy across 32 source files, shellcheck, and the frontend build all green. CI additionally runs the installer inside real Debian, Rocky and Ubuntu containers and asserts the outcomes, including that a refusal installs zero packages. Golden CEF lines for all three vendors reproduce byte-for-byte. Loopback transport tests cover UDP, TCP, and TLS, so CI needs no external collector.

## Attribution

This project uses MITRE ATT&CK. Copyright 2026 The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation. ATT&CK is a registered trademark of The MITRE Corporation. Use does not imply endorsement.

Apache-2.0. Third-party notices in `NOTICE`.
