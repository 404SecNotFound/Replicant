# CLAUDE.md — Replicant

Persistent context for Claude Code working in this repository. Read this first, every session.

## What this project is

Replicant generates safe, synthetic firewall and network security telemetry in CEF, streams it over syslog to a SIEM (LogRhythm first), and is driven by a MITRE ATT&CK grounded technique catalog. A detection engineer picks a technique from a menu and Replicant emits realistic firewall logs that exercise the matching detection.

Full design is in `docs/blueprint.md`. The FortiGate log schema and golden sample lines are in `docs/fortigate-cef-reference.md`. Prior art and licensing constraints are in `docs/prior-art-and-licensing.md`. The technique catalog is `data/technique-catalog.yaml`.

## Non-negotiable safety rules

1. The only network egress is to the operator-configured collector. Never open a socket to anything else. If no collector is configured, sends must fail closed.
2. All entities are synthetic. Default IPs are RFC1918 and documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). DNS parents are non-resolvable synthetic names. No real domains, no real malware, no real C2.
3. No real attacks. Replicant writes log strings. It never executes commands, scans, or moves data. Attack names and byte counts are fields, nothing more.
4. Respect the events-per-second cap. Default configurable, protect the operator's own collector.
5. Every run writes a manifest (seed, technique, params, entities, target, counts, times).

## Licensing guardrails

- This project is Apache-2.0. Add the Apache header to new source files.
- You may reuse patterns from MIT and Apache-2.0 tools with attribution in NOTICE.
- Do NOT copy code from GPL-3.0, AGPL-3.0, or Elastic License 2.0 sources. Named ones to avoid: Endgame RTA, AttackGen, summved/log-generator, tcpreplay, elastic/detection-rules. Inspiration only.
- Keep the MITRE ATT&CK attribution notice in README and NOTICE (see blueprint section 20).

## Architecture (summary)

Presentation (Rich menu + headless CLI) -> Orchestrator -> Scenario Engine + Connection Manager -> Vendor Profile (FortiGate) + Syslog Emitter -> CEF Serializer -> Transport. The Scenario Engine and CEF Serializer are vendor-neutral. Adding a firewall is implementing the `VendorProfile` interface plus a reference file. See the diagram in `docs/blueprint.md` section 5, module list in section 6.

Key rule: no behavior lives only in the TUI. The menu and the CLI both call the Orchestrator. Anything the menu can do, `replicant run ...` can do headless.

## Coding standards

- Python 3.11+. Full type hints. Pydantic v2 models in `core/models.py`.
- Keep dependencies small: rich, typer or argparse, pydantic, PyYAML, numpy, stdlib socket and ssl, pytest. No scapy, no requests at runtime.
- Deterministic core. The Scenario Engine does no I/O and is seedable. Same seed plus technique plus params yields the same plan.
- Format with black, lint with ruff, type-check with mypy. Tests with pytest.
- Style for docs and comments: no em-dashes. Avoid marketing filler. Label unverified claims with [Inference] or [Unverified].

## CEF serialization (get this exact)

Header: `CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension`.
Escaping: header values escape `\` and `|`; extension values escape `\` and `=`; newlines encode as `\n`/`\r` in extension only. UTF-8. The syslog prefix is added by transport and is not part of the header.
FortiGate: Vendor `Fortinet`, Product `Fortigate` (lower-case g), Signature ID is last five digits of FortiOS `logid`, severity is reversed FortiOS level, non-standard fields prefixed `FTNTFGT`. The oracle for correctness is the seven golden sample lines in `docs/fortigate-cef-reference.md`.

## How to run (target CLI)

```
replicant list
replicant connect --host 10.20.0.50 --port 514 --transport udp --test
replicant run REP-001 --intensity medium --duration 30m --seed 1337
replicant run REP-004 --intensity high --to-file ./out/dns.log --no-send
```

## Phase plan

- Phase 1 (complete): pipeline plus three techniques (REP-001, REP-002, REP-004) end to end, loopback CI green. Scope is in `docs/phase1-kickoff-prompt.md`.
- Phase 1.5 (complete): web UI and embedded terminal over the same Orchestrator.
- Phase 2 (complete): full catalog (all eleven techniques REP-001..011), entity hardening, TLS transport, REP-008 warm-up baseline, manifests.
- Phase 3 (current): Palo Alto and Check Point profiles. Palo Alto (PAN-OS) profile done: `replicant/profiles/paloalto.py` + `docs/paloalto-cef-reference.md` (seven golden lines, all [Unverified]), selectable with `--vendor paloalto`. Check Point next.
- Phase 4: ATT&CK scenario composition (AI advisory only; humans author detection design).
- Phase 5: React web UI over the same core.

## Definition of done for any change

Tests pass (including CEF golden tests and loopback transport). Types clean. New source has the Apache header. Any new technique is a catalog entry with a unique `ndr_uc`. The safety rules above still hold.
