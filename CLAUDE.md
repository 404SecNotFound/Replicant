# CLAUDE.md — Replicant

Persistent context for Claude Code working in this repository. Read this first, every session.

## What this project is

Replicant generates safe, synthetic firewall and network security telemetry in CEF, streams it over syslog to a SIEM (LogRhythm first), and is driven by a MITRE ATT&CK grounded technique catalog. A detection engineer picks a technique from a menu and Replicant emits realistic firewall logs that exercise the matching detection.

Full design is in `docs/blueprint.md`. The FortiGate log schema and golden sample lines are in `docs/fortigate-cef-reference.md`. Prior art and licensing constraints are in `docs/prior-art-and-licensing.md`. The technique catalog is `replicant/data/technique-catalog.yaml`. Runtime data lives INSIDE the package so it ships in a wheel; see `replicant/resources.py`.

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

replicant run REP-001 --anchor now --pace plan            # real time: a 4h beacon takes 4h
replicant run REP-001 --anchor now --pace plan --speed 60  # same shape, 4h becomes 4m
replicant run REP-001 --anchor now --pace burst            # all at once, plan timeline ignored

replicant scenario list
replicant scenario show SCEN-001              # dry preview, writes nothing
replicant scenario run SCEN-001 --seed 1337 --to-file ./out/s1.log --no-send

replicant menu                                # Rich TUI
replicant web --no-browser                    # 127.0.0.1:9787, persistent token
replicant web --host 0.0.0.0 --no-browser     # reachable on the segment, terminal tab off
```

Output convention: command results go to stdout, operator-facing errors go to stderr.

## Phase plan

- Phase 1 (complete): pipeline plus three techniques (REP-001, REP-002, REP-004) end to end, loopback CI green. Scope is in `docs/phase1-kickoff-prompt.md`.
- Phase 1.5 (complete): web UI and embedded terminal over the same Orchestrator.
- Phase 2 (complete): first full catalog (REP-001..011), entity hardening, TLS transport, REP-008 warm-up baseline, manifests. The catalog is now 24 entries; see the v0.2.0 note below.
- Phase 3 (complete): Palo Alto and Check Point profiles both done. `replicant/profiles/paloalto.py` + `docs/paloalto-cef-reference.md` and `replicant/profiles/checkpoint.py` + `docs/checkpoint-cef-reference.md` (eight golden lines each, all [Unverified]). Vendor selectable with `--vendor {fortigate,paloalto,checkpoint}`, the Rich menu `[v]` picker, and the web UI selector (canonical id list in `settings.VENDORS`). Check Point emits string CEF severity (Unknown/Low/Medium/High/Very-High), so `CefHeader.severity` is `int | str`.
- Phase 4 (complete): ATT&CK scenario composition. Three curated chains (SCEN-001/002/003) in `replicant/data/scenario-catalog.yaml` compose techniques into one deterministic multi-stage timeline; each run writes a paired manifest and advisory. Driven from `replicant scenario list|show|run` and the Rich menu `[a]`. The advisory is coverage and correlation context only, derived from the composed events with no model involved; humans author the detection design. Web UI scenario support is deliberately deferred. The deferral is checked by a manual UAT row (`tasks/uat-plan.md`, CHAIN-16), not by a pytest test; do not describe it as one.

- v0.2.0 (catalog expansion): 11 techniques to 24 (REP-012..REP-024). Every new entry is anchored to a peer-reviewed paper with measured results. Design record and rejected ideas are in `docs/technique-catalog-expansion-research.md` and `docs/technique-catalog-expansion-research-round2.md`; the per-technique summary is in the CHANGELOG. Added the `dns:dns-response` render path on all three vendors (FortiGate signature 54802 is confirmed, the extension key names are [Unverified]) plus a `scanner_external` entity pool on 192.0.2.0/24 for inbound scanning.

  Two conventions this established, both load-bearing for new techniques:
  1. `benign_baseline` is a property to **generate**, not just document. A plan that emits only the malicious pattern lets any detection score perfectly. Bilot et al. (USENIX Sec 2025) is the argument; see the CHANGELOG.
  2. A technique that cannot be expressed honestly is not added. REP-016 was catalogued but left unbuildable until `dns:dns-response` existed, because a DGA entry with no NXDOMAIN in it is worse than no entry.

- v0.3.0 (web UI access and navigation, complete): the UI serves on fixed port **9787** and can bind an address the rest of the segment reaches, with a persistent token in `~/.config/replicant/web-token`, an httpOnly `SameSite=Strict` session cookie, a Host allowlist that follows the bind address, and the embedded terminal off by default once the bind is not loopback. The left rail is grouped by ATT&CK tactic with a filter box and log-type toggles, a Docs tab renders the vendor CEF references, and the event-time anchor is a visible control in the run form. `scripts/replicant-web.service` is verified under a real systemd by a CI job (`systemd-unit`), not by inspection. Spec and decisions: `tasks/webui-access-and-nav-spec.md`.

  Three things this established, worth keeping:
  1. **A control whose output cannot change is decoration.** The spec's vendor filter was dropped because all 24 techniques apply to all 3 vendors, so it could never exclude an entry. Same call as REP-016.
  2. **Run it in the environment it ships for.** The web token was being written to the systemd journal, which a review, the test suite and `systemd-analyze verify` were all silent about. A real systemd start found it in seconds.
  3. **Most defects here were labels, not logic**: a README describing a UI that had moved on, an installer check asserting a file existed rather than that the server ran, `cap 2000` beside an unthrottled rate. Each locally true and contextually false, which is the class tests catch worst.

- v0.3.1 (packaging): the 0.3.0 wheel installed but could not run. Runtime files now live inside the package and `replicant/resources.py` is the only thing that knows where they are. Anything resolving a repository-relative path is a defect. Guarded by `tests/test_packaging.py` and a `wheel` CI job.

- Light theme and responsive layout (complete): the UI follows `prefers-color-scheme` on first load and remembers an explicit toggle after that. The rule lives in `webui/src/lib/theme.ts`, and a pre-paint script in `webui/index.html` necessarily repeats it; `theme.test.ts` asserts the two agree. Below `lg` the fixed-viewport shell becomes a scrolling page and the rail becomes a disclosure. Palette and deviations: `docs/webui-reskin-design.md` sections 3 and 5.

  Two conventions worth keeping:
  1. **Measure contrast on the rendered page, not on the token table.** The tokens were verified; their *usage* was not, and the audit found four defects in the shipped **dark** theme, including `--text-4` used as body text at 2.78:1 against its own documented rule.
  2. **A grid or flex item needs `min-w-0` before `overflow-x-auto` inside it can work.** Default `min-width: auto` refuses to shrink below the content, so one long CEF line scrolled the whole page to 3452px at 375px wide.

- Plan-timed pacing (complete): the emit loop honours the plan's own per-event times.
  `--pace {burst,plan}` and `--speed N`, defaulting to plan when sending to a collector
  and burst for `--to-file`, with the same choice as a labelled radio group in the web
  run form. The arithmetic is pure and lives in `replicant/core/pacing.py`; the emit
  loop in `replicant/core/orchestrator.py` only does the waiting. `POST /api/plan`
  prices a run without starting it, which is what lets each option carry its own
  duration on screen.

  **Invariant to preserve: with `--pace plan` and `--anchor now`, an event is sent at
  the moment its own timestamp says it happened, at any speed.** `--speed` therefore
  rewrites event times as well as the schedule. Compressing only the schedule would
  reproduce the original defect at 1/60 scale.

  Three conventions this established:
  1. **`--rate` and `--pace` compose, they do not compete.** Rate is the flood guard and
     enters the schedule as a floor on spacing; pace sets the shape. Never conflate them
     in a UI, they answer different questions.
  2. **A rate cap enforced only against a schedule is not enforced.** Deadlines computed
     from a fixed baseline let late events fire back to back. The floor is measured
     against the previous *actual* send. Its catch-up check is measured against the
     *plan's* deadline, not the floored one: measuring both against the same value makes
     the floor mask the catch-up guard, and a stall then gets paid back by squeezing the
     gaps after it.
  3. **`eventtime` is integer epoch seconds**, so one second is the finest gap a plan can
     express and a hard ceiling on useful compression. Past the plan's own gap size every
     event collapses into the same second.

Next up, not started: a live-vendor pass to replace the `[Unverified]` markers on the Palo Alto and Check Point references with confirmed output, which needs real appliances. The React web UI itself shipped in Phase 1.5; there is no separate later phase for it.

Vendor licensing position (trademarks, the `[Constructed]` golden lines, the field-mapping tables, the CEF spec's terms) is settled in `docs/prior-art-and-licensing.md` section 3. **Standing constraint: never claim CEF certification, CEF compliance, or ArcSight validation.**

## Definition of done for any change

Tests pass (including CEF golden tests and loopback transport). Types clean. New source has the Apache header. Any new technique is a catalog entry with a unique `ndr_uc`. The safety rules above still hold.
