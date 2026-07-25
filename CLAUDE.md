# CLAUDE.md — Replicant

Persistent context for Claude Code working in this repository. Read this first, every session.

## What this project is

Replicant generates safe, synthetic firewall and network security telemetry in CEF, streams it over syslog to a SIEM (LogRhythm first), and is driven by a MITRE ATT&CK grounded technique catalog. A detection engineer picks a technique from a menu and Replicant emits realistic firewall logs that exercise the matching detection.

Full design is in `docs/blueprint.md`. The FortiGate log schema and golden sample lines are in `docs/fortigate-cef-reference.md`. Prior art and licensing constraints are in `docs/prior-art-and-licensing.md`. The technique catalog is `data/technique-catalog.yaml`.

## Non-negotiable safety rules

1. The only network egress is to the operator-configured collector. Never open a socket to anything else. If no collector is configured, sends must fail closed.
2. All entities are synthetic. Default IPs are RFC1918 and documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). DNS parents come from the IANA documentation domains and the reserved `.invalid` TLD (RFC 6761); note example.net does resolve, .invalid does not, and Replicant resolves neither. No real domains, no real malware, no real C2.
3. No real attacks. Replicant writes log strings. It never executes commands, scans, or moves data. Attack names and byte counts are fields, nothing more.
4. Respect the events-per-second cap. Default configurable, protect the operator's own collector.
5. Every run writes a manifest (seed, technique, params, entities, target, counts, times).

## Licensing guardrails

- This project is Apache-2.0. Add the Apache header to new source files.
- You may reuse patterns from MIT and Apache-2.0 tools with attribution in NOTICE.
- Do NOT copy code from GPL-3.0, AGPL-3.0, or Elastic License 2.0 sources. Named ones to avoid: Endgame RTA, AttackGen, summved/log-generator, tcpreplay, elastic/detection-rules. Inspiration only.
- Keep the MITRE ATT&CK attribution notice in README and NOTICE (see blueprint section 20).

## Architecture (summary)

Presentation (Rich menu + headless CLI + web UI) -> Orchestrator -> Scenario Engine + Connection Manager -> Vendor Profile (FortiGate, Palo Alto PAN-OS, or Check Point) + Syslog Emitter -> CEF Serializer -> Transport. The Scenario Engine and CEF Serializer are vendor-neutral. Adding a firewall is implementing the `VendorProfile` interface plus a reference file. See the diagram in `docs/blueprint.md` section 5, module list in section 6.

Key rule: no behavior lives only in the TUI. The menu and the CLI both call the Orchestrator. Anything the menu can do, `replicant run ...` can do headless.

## Coding standards

- Python 3.11+. Full type hints. Pydantic v2 models in `replicant/core/models.py`.
- Keep dependencies small: rich, typer or argparse, pydantic, PyYAML, numpy, stdlib socket and ssl, pytest. No scapy, no requests at runtime.
- Deterministic core. The Scenario Engine does no I/O and is seedable. Same seed plus technique plus params yields the same plan.
- Format with black, lint with ruff, type-check with mypy. Tests with pytest.
- Style for docs and comments: no em-dashes. Avoid marketing filler. Label unverified claims with [Inference] or [Unverified].

## CEF serialization (get this exact)

Header: `CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension`.
Escaping: header values escape `\` and `|`; extension values escape `\` and `=`; newlines encode as `\n`/`\r` in extension only. UTF-8. The syslog prefix is added by transport and is not part of the header.
FortiGate: Vendor `Fortinet`, Product `Fortigate` (lower-case g), Signature ID is last five digits of FortiOS `logid`, severity is reversed FortiOS level, non-standard fields prefixed `FTNTFGT`. The oracle for correctness is the eight golden sample lines in `docs/fortigate-cef-reference.md`.

## How to run

```
replicant list
replicant connect --host 10.20.0.50 --port 514 --transport udp --test
replicant run REP-001 --intensity medium --duration 30m --seed 1337
replicant run REP-004 --intensity high --to-file ./out/dns.log --no-send
replicant run REP-001 --vendor checkpoint --to-file ./out/cp.log --no-send

replicant scenario list
replicant scenario show SCEN-001              # dry preview, writes nothing
replicant scenario run SCEN-001 --seed 1337 --to-file ./out/s1.log --no-send

replicant menu                                # Rich TUI
replicant web --no-browser                    # loopback + per-session token
```

Output convention: command results go to stdout, operator-facing errors go to stderr.

## Phase plan

- Phase 1 (complete): pipeline plus three techniques (REP-001, REP-002, REP-004) end to end, loopback CI green. Scope is in `docs/phase1-kickoff-prompt.md`.
- Phase 1.5 (complete): web UI and embedded terminal over the same Orchestrator.
- Phase 2 (complete): first full catalog (REP-001..011), entity hardening, TLS transport, REP-008 warm-up baseline, manifests. The catalog is now 24 entries; see the v0.2.0 note below.
- Phase 3 (complete): Palo Alto and Check Point profiles both done. `replicant/profiles/paloalto.py` + `docs/paloalto-cef-reference.md` and `replicant/profiles/checkpoint.py` + `docs/checkpoint-cef-reference.md` (eight golden lines each, all [Unverified]). Vendor selectable with `--vendor {fortigate,paloalto,checkpoint}`, the Rich menu `[v]` picker, and the web UI selector (canonical id list in `settings.VENDORS`). Check Point emits string CEF severity (Unknown/Low/Medium/High/Very-High), so `CefHeader.severity` is `int | str`.
- Phase 4 (complete): ATT&CK scenario composition. Three curated chains (SCEN-001/002/003) in `data/scenario-catalog.yaml` compose techniques into one deterministic multi-stage timeline; each run writes a paired manifest and advisory. Driven from `replicant scenario list|show|run` and the Rich menu `[a]`. The advisory is coverage and correlation context only, derived from the composed events with no model involved; humans author the detection design. Web UI scenario support is deliberately deferred, and a test asserts its absence so a partial implementation is caught.

- v0.2.0 (catalog expansion): 11 techniques to 24 (REP-012..REP-024). Every new entry is anchored to a peer-reviewed paper with measured results. Design record and rejected ideas are in `docs/technique-catalog-expansion-research.md` and `docs/technique-catalog-expansion-research-round2.md`; the per-technique summary is in the CHANGELOG. Added the `dns:dns-response` render path on all three vendors (FortiGate signature 54802 is confirmed, the extension key names are [Unverified]) plus a `scanner_external` entity pool on 192.0.2.0/24 for inbound scanning.

  Two conventions this established, both load-bearing for new techniques:
  1. `benign_baseline` is a property to **generate**, not just document. A plan that emits only the malicious pattern lets any detection score perfectly. Bilot et al. (USENIX Sec 2025) is the argument; see the CHANGELOG.
  2. A technique that cannot be expressed honestly is not added. REP-016 was catalogued but left unbuildable until `dns:dns-response` existed, because a DGA entry with no NXDOMAIN in it is worse than no entry.

Next up, not started: group the catalog by MITRE tactic in the web UI left rail, then a Docs tab. At 24 entries the tactic grouping is close to a prerequisite for the menu staying usable, not a cosmetic improvement. The React web UI itself shipped in Phase 1.5; there is no separate later phase for it.

## Definition of done for any change

Tests pass (including CEF golden tests and loopback transport). Types clean. New source has the Apache header. Any new technique is a catalog entry with a unique `ndr_uc`. The safety rules above still hold.
