# CLAUDE.md: Replicant

Persistent context for Claude Code working in this repository. Read this first, every session.

## What this project is

Replicant generates safe, synthetic firewall and network security telemetry in CEF, streams it over syslog to a SIEM (LogRhythm first), and is driven by a MITRE ATT&CK grounded technique catalog. A detection engineer picks a technique from a menu and Replicant emits realistic firewall logs that exercise the matching detection.

Full design is in `docs/blueprint.md`. The FortiGate log schema and golden sample lines are in `docs/fortigate-cef-reference.md`. Prior art and licensing constraints are in `docs/prior-art-and-licensing.md`. The technique catalog is `replicant/data/technique-catalog.yaml`. Runtime data lives INSIDE the package so it ships in a wheel; see `replicant/resources.py`.

## Non-negotiable safety rules

1. The only network egress is to the operator-configured collector. Never open a socket to anything else. If no collector is configured, sends must fail closed.
2. All entities are synthetic. Default IPs are RFC1918 and documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). DNS parents come from the IANA documentation domains and the reserved `.invalid` TLD (RFC 6761); note example.net does resolve, .invalid does not, and Replicant resolves neither. No real domains, no real malware, no real C2.
3. No real attacks. Replicant writes log strings. It never executes commands, scans, or moves data. Attack names and byte counts are fields, nothing more.
4. Respect the events-per-second cap. Default configurable, protect the operator's own collector. The cap is applied by one process's emit loop, so **the supported scope is one sending run per host and it is enforced**, not assumed: a second run that would open a socket to a collector is refused (`replicant/core/sendlock.py`). Two hosts pointed at one collector are still two caps, and nothing on a single machine can see that.
5. Every run writes a manifest (seed, technique, params, entities, target, counts, times).
6. The synthetic marker is destination-conditional (roadmap 2026-09 item 3, `Orchestrator._resolve_marker`): ON by default for a non-loopback send (stamps `flexString1`, an unused flex slot, with the run id, so lab data stays separable on a shared collector), OFF for a loopback or file-only (`--to-file --no-send`) run where the golden line is the oracle, `--no-marker` to override with a logged warning. The manifest records the decision in `marker_attestation`. Replicant is a detection-lab tool, not a production SIEM component: see `docs/deployment-boundary.md`.

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

- Light theme and responsive layout (complete; the light theme was later REMOVED by the Factory redesign below). The responsive half survives: below `lg` the fixed-viewport shell becomes a scrolling page and the rail becomes a disclosure.

  Two conventions worth keeping:
  1. **Measure contrast on the rendered page, not on the token table.** The tokens were verified; their *usage* was not, and the audit found four defects in the shipped **dark** theme, including `--text-4` used as body text at 2.78:1 against its own documented rule.
  2. **A grid or flex item needs `min-w-0` before `overflow-x-auto` inside it can work.** Default `min-width: auto` refuses to shrink below the content, so one long CEF line scrolled the whole page to 3452px at 375px wide.

- Factory redesign (complete, v0.6.0): the web UI's visual system is the archived dark-era
  Factory design ("terminal war room at midnight"), dark-only. The design contract is
  `docs/webui-factory-design.md`; `docs/webui-reskin-design.md` is superseded and kept for its
  measured lessons. Fonts are Geist 400/500 and JetBrains Mono 400, both OFL 1.1, self-hosted
  with license texts beside the woff2 (they ship in the wheel). **Switzer was rejected on
  licensing**: the ITF Free Font License v2.0 prohibits distribution through a repository or
  publicly accessible server, and this is a public repo that publishes wheels.

  Rules that bind future UI changes (full list in the design doc):
  1. **Machine values take the mono voice; human sentences take Geist.** A human sentence in
     mono is a violation in either direction. Weight 400 everywhere, 500 at most once per screen.
  2. **A connected data series counts as ONE chromatic element, cap ~2 per card, and chromatic
     color (signal orange, metric green) never appears on buttons, nav, headings, or control
     states.** An active filter recesses to the canvas instead.
  3. **No readout renders that the stream cannot measure.** The approved mock's bytes tile does
     not ship because no byte counter exists; labels say emitted, never sent or delivered.
  4. **`cn()` must know every type-scale rung.** Stock tailwind-merge classifies unknown
     `text-*` classes as colors and silently deletes the size when a color follows in the same
     call; `utils.test.ts` pins every rung `tailwind.config.js` declares. Add a rung, register it.

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

- Duration across the catalog and scenarios (complete): `--duration` works on all 24
  techniques and on scenarios. Four builders ignored it (REP-005, REP-014, REP-019,
  REP-023) and are fixed; `tests/test_duration.py` asserts all 24 by parameter.
  `compose()` takes `duration_s` and runs two passes when given one, scaling stage
  offsets and per-stage windows.

  **The rule to apply to any new technique: `--duration` bounds the span, and where the
  interval between events IS the detection signal, preserve the interval and let the
  event count fall.** That is what separates it from `--speed`, which preserves the count
  and divides the intervals. Only duration produces a shorter window a rule can still
  fire on.

  Two conventions this established:
  1. **A technique pinned to an absolute window outranks the requested duration.** REP-005
     is off-hours and off-hours is 00:00-06:00, so a longer request is capped and a
     scenario containing it cannot compress below its whole-day alignment jump. Both are
     recorded in the manifest rather than silently returned.
  2. **A flag that works on most entries is worse than one that works on none**, because
     the operator learns to trust it. Catalog-wide behaviour needs a parametrized test
     over the whole catalog, not a test of one representative entry.

- Security review closeout and the second end-to-end review (complete): the 2026-08 security
  review is now **fully closed**. F-08 and F-14 were the last two and were both operator
  decisions rather than code problems; they shipped in v0.8.0, recorded below. Decision record
  and full status: `docs/security-review-2026-08-response.md`. A separately proposed
  17-technique expansion was triaged and **not implemented**; the decisions are in
  `docs/round3-expansion-triage.md`.

  Five conventions this established, all of them earned the hard way:

  1. **A guard must be run against the unfixed code and observed to fail.** A guard that has never
     failed is of unknown value. Two guards this session passed for the wrong reason until a
     positive control was run: revert the fix, confirm the test goes red, restore it.
  2. **A golden-line test that covers one verdict of a two-verdict field is not a test of that
     field.** The Check Point golden line for `event:system` is a failed login, and the test only
     ever fed it a failure, so a hardcoded `act=Reject` shipped on the only case the engine
     actually produces: success. Two of three vendors rendered every successful REP-018 login as a
     failure, in exactly the field a correlation rule reads.
  3. **A default is not fixed by labelling it.** PR #31 responded to a silent no-destination run
     with a labelled button and a warning banner and left `useState(false)` and `no_send=True`
     untouched, so the honest label described the wrong outcome accurately. Measured afterwards:
     CLI 200 datagrams, web 200, identical parameters. The send path was never broken, only its
     default.
  4. **Server state must be read from the server.** The run form's `running` flag is per-panel, so
     a reload showed an idle form while the server was hours into a run, and the button then failed
     with a 409 naming a hex id the operator could not resolve. Anything the server owns
     exclusively (the single-run lock, the active run) has to be askable.
  5. **A verdict must state what it does not prove.** `Send test log` showed a green `verified`
     against an unreachable collector across two lab sessions, because it was set from a UDP
     `sendto` succeeding, which only proves a route exists. The word is now gone from the codebase
     entirely. What replaced it is disclosure, not a probe: a measured UDP probe to the mistyped lab
     address returns no error at all, so it would not have caught the bug. Printing the source
     beside the destination does.

  One product rule came out of the same work: **every catalog entry states its objective**, one
  sentence on what running it is meant to establish. The UI used to generate "emits synthetic X
  telemetry that exercises Y", which is true of all 24 entries and so answers nothing. Guarded
  parametrized over the whole catalog, for the reason `--duration` established.

- v0.7.0 (catalog defects, complete): an external review of the technique catalog found three
  places where the emitted telemetry contradicted the catalog text a detection engineer reads
  before trusting it. REP-024's relay lag was a constant 1s at every preset (`int(ms) // 1000` on
  sub-second ranges), so the technique whose stated purpose is defeating fixed-window timing
  correlation emitted the fixed window. REP-002 ignored its own `window_s` preset and
  `--duration` entirely. REP-014's benign foil was separable on duration alone, the one feature
  it exists to make indistinguishable. Two ATT&CK mappings were wrong (REP-007's T1110.004,
  REP-012's T1029) and three tactic lists claimed a tactic none of their own techniques carry.
  Triage: `tasks/catalog-review-2026-08-plan.md`.

  **The finding behind the findings: no test asserted that the code does what the catalog text
  promises.** Every defect sat in the gap between a documented distribution and the emitted one.
  `tests/test_readme_catalog_sync.py` now fails CI when README and catalog disagree.

  Two conventions, both load-bearing:
  1. **The seed is part of the guard.** The review's own REP-013 test passed against the code
     containing the bug, because seed 1337 drew a host that never collided. The collision hits
     2% of seeds (4% at high). A guard whose seed avoids the defect has never failed.
  2. **A benign foil is a correctness requirement, not decoration.** Two of the three behavioural
     defects were foils a detection could separate for free. A trivially separable foil is worse
     than none, because it reports as coverage.

- v0.8.0 (security review fully closed, complete):

  **F-08, the eps cap is per process.** Decision: **documented and enforced single-process
  scope**, not a host-level lease. `replicant/core/sendlock.py` takes an advisory `flock` for any
  run that opens a socket to a collector; a second sending run on the host is refused and the
  message names the holding pid. `--no-send` and `--to-file` never acquire it. The lease was
  declined because expiry, clock drift and orphaned leases are worse failure modes than the one
  being fixed, and `flock` is released by the kernel on exit including `kill -9`. **Scope stated
  rather than implied: per host and per user, never across hosts.** Its guard spawns a real
  second process, because the finding is precisely that the cap was scoped to one process and an
  in-process re-entry would pass against code that locked nothing.

  **F-14, npm advisories.** Decision: **drop EOL Node 18.** Six advisories, one critical, to
  zero. vite 5 to 8, vitest 2 to 4. **The cost is real and is not hidden: Debian 12 and Ubuntu
  24.04 ship Node 18 and can no longer build the web UI from their own repositories** (use
  `--no-web`, or Node 20+ from NodeSource). CI covers `debian:12` with `--no-web` and added
  `debian:13` for the full-install case. **`jsdom` is pinned to 26 on purpose**: 30 requires Node
  22.22+, above the floor being declared, and a test-only dependency must not choose the
  supported platform.

  **The golden oracle was proving seven eighths of what it claimed.** All three vendor golden
  tests assert the reference holds eight lines, assert the fixtures match, then byte-compare
  `range(7)`. The eighth line of every vendor had never been compared to anything. It passes at
  `range(8)`, so it was a coverage hole rather than a live defect, and it is still the sharpest
  example of the rule this project keeps relearning: **a guard that proves less than its own name
  claims.** Found by an external roadmap proposal, triaged in `docs/10x-roadmap-triage.md`, of
  which roughly 13 person-weeks of 58 to 62 were adopted.

  **The test suite had no `conftest.py`**, so it read and wrote the operator's real
  `~/.config/replicant`: saved collector profile, persistent web token, and then the send lock.
  It is isolated per test now, which is what made the host-global lock testable at all. That
  surfaced as five failures, every one a true report about shared global state rather than a
  defect in the thing under test, which is why the fix was isolation and not a weaker lock.

Next up, not started: a live-vendor pass to replace the `[Unverified]` markers on the Palo Alto and Check Point references with confirmed output, which needs real appliances. The React web UI itself shipped in Phase 1.5; there is no separate later phase for it.

**The LogRhythm lab test has still never run**, so every timing and delivery claim in this
project is loopback-only. It also gates the adopted roadmap order: F2 (CI detection regression)
is a verification layer on a send path never once observed working end to end. **Per
`docs/roadmap-2026-09.md` this is now a hard launch gate:** external claims hold at "generates
vendor-accurate CEF, detection-unverified" until the first observed rule fire, and nothing that
adds surface ships before the pipe is proven.

**Identity (resolved 2026-09-01):** Replicant is an OSS detection-as-code tool for detection
engineers, CLI-first, web optional. Not a personal-lab script and not customer-delivery
consulting output. This settles the fork the shipped surface (React UI, installer matrix, three
vendor profiles, public wheels) had already made de facto, and it is why pip/container packaging
and vendor-honesty framing are table stakes rather than scope creep. Full record:
`docs/roadmap-2026-09.md`.

**Never `git add -A` in this checkout.** `replicant-backup-*/` and `replicant-rewrite/` are whole
git repositories living inside it, including a mirror and bundle of the pre-rewrite history.
Committing those to this public repo would undo the history scrub. Both are gitignored; stage
files by name.

Vendor licensing position (trademarks, the `[Constructed]` golden lines, the field-mapping tables, the CEF spec's terms) is settled in `docs/prior-art-and-licensing.md` section 3. **Standing constraint: never claim CEF certification, CEF compliance, or ArcSight validation.**

## Definition of done for any change

Tests pass (including CEF golden tests and loopback transport). Types clean. New source has the Apache header. Any new technique is a catalog entry with a unique `ndr_uc`. The safety rules above still hold.

Two testing rules this project has paid for more than once:

- **A new guard must be run against the unfixed code and observed to fail.** Not "it looks
  right", not "the suite is green": revert the fix, watch it go red, restore it. Include the seed
  and the preset in that check, because a guard whose inputs avoid the defect has never failed.
  If a positive control cannot be run at all, that is a reason not to merge yet, not a caveat to
  disclose in the PR body.
- **Tests must not touch host-global state.** `tests/conftest.py` points `REPLICANT_CONFIG_DIR` at
  a per-test directory. Anything reaching the real `~/.config/replicant` is a defect: it mutates
  the operator's machine, and it lets one test's leftovers decide another test's result.
