# Replicant — User Acceptance Test (UAT) Plan

Owner (QA lead): Claude Code (automated suites) + DJR/RZA (manual suites)
Status: **Revision 3** — Round 1 executed and signed **GO**; Round 2 (Phase 4 scenarios + Linux installer) authored, awaiting execution; Round 3 (live SIEM ingestion) authored, blocked on a lab
Authored: 2026-07-19 · Revised: 2026-07-29

**Revision history**
- **r1 (2026-07-19)** — Phases 1, 1.5, 2, 3. Suites A–E. Executed; automated verdict GO; Suites C/D still pending DJR.
- **r2 (2026-07-21)** — adds Suite F (Phase 4 scenario composition, PR #7) and Suite G (Linux installer, PR #8), plus TUI-07..09. Refreshes facts that went stale between the two rounds.
- **r3 (2026-07-29)** — adds Suite H (live SIEM ingestion) and requirements LR-1..LR-6. Moves live SIEM ingestion out of "Out of scope", where it had sat since r1 with no pass criteria attached. This is the oldest open item in the project and it predates v0.1.0; until now the plan gave a tester nothing to measure it against, so the result would have been an opinion rather than a record.

## 1. Purpose & scope

Validate that Replicant meets its stated requirements and non-negotiable safety rules across **every surface and every claim** before it is treated as production-ready. Round 1 was the quality gate on Phases 1, 1.5, 2, and 3. Round 2 extends that gate over Phase 4 scenario composition and the Linux install script, neither of which existed when this plan was first written.

**Product under test:** Round 3 targets `main` @ `f9894dc` (v0.3.1 plus the light theme and screenshot work). Round 2 was authored against `main` @ `0af51f7` (PR #8 merge); Round 1 ran against `main` @ `8fe3d31`. The delta into Round 3 is the v0.2.0 catalog expansion (11 → 24 techniques), the web UI access and navigation work, multi-vendor `[Unverified]` references, the v0.3.1 packaging fix, and the light theme.

**In scope — Round 1 (executed)**
- 11 techniques (REP-001..REP-011), each with a unique `ndr_uc`.
- 3 vendor profiles (FortiGate, Palo Alto, Check Point) on all 3 surfaces.
- 3 transports (UDP, TCP, TLS) + loopback connectivity test.
- CEF correctness against the golden-line oracles.
- 3 surfaces: headless CLI, Rich TUI menu, web UI (+ embedded terminal).
- Manifests, determinism, intensity/duration handling.
- The 5 non-negotiable safety rules.
- Quality gate (pytest / black / ruff / mypy / frontend build).

**In scope — Round 2 (new)**
- Phase 4 scenario composition: the 3 curated chains (SCEN-001/002/003), `replicant scenario list|show|run`, and the Rich menu `[a]` flow.
- The paired manifest + advisory artifacts every scenario run writes, and the advisory's coverage/correlation boundary.
- `scripts/install.sh` on a real Linux host: flags, consent and sudo scope, the distribution package mappings, and the self-verification step.
- The use-case detail panel shipped in PR #6, to the extent Suite D touches it.

**In scope — Round 3 (new)**
- **Live ingestion into a real LogRhythm deployment.** Every transport test in Rounds 1 and 2 used a loopback receiver, so nothing in this plan has ever proved that a real SIEM identifies the log source, parses the CEF, or fires on it.
- Event-time correctness on a live send: `--anchor now` versus the default fixed anchor, and the stale-anchor warning.
- MPE parsing fidelity against the field-mapping table in `docs/fortigate-cef-reference.md`, which is the oracle for what each field is supposed to become.
- Resolving the two `[Unverified]` FortiGate signature IDs (`dns:dns-query` 54803, SSL-VPN `tunnel-up` 39947) against a real parser.
- Whether the detection a technique targets actually fires on the malicious pattern **and stays quiet on the benign baseline**.

**Out of scope**
- **Authoring or tuning the LogRhythm AIE rules themselves.** Replicant exercises a detection; it does not write one. A rule that does not exist in the lab is a gap in the lab, not a defect in Replicant, and is recorded as such.
- SIEMs other than LogRhythm. The blueprint is explicit that LogRhythm is first; Splunk, Sentinel and Elastic are not covered here.
- Web UI scenario support. Deferred fast-follow per `docs/phase4-scenario-composition-design.md` §13; the SPA and `web/server.py` carry zero scenario surface today. CHAIN-16 asserts that absence rather than testing function.
- macOS and Windows installer support, container images, systemd units, and system-wide `/opt` deployment. All stated non-goals in `docs/linux-install-script-design.md` §9.
- Ad-hoc scenario chains from CLI arguments (curated catalog only) and the optional LLM advisor seam. Both deferred, §13.

## 2. Environment & entry criteria

Setup the executor runs once before Suite A/B:

```bash
git checkout main && git pull                 # UAT the shipping product
python3.12 -m venv .venv 2>/dev/null || true  # venv already exists
pip install -e ".[web]"                        # web extra for replicant web + API tests
(cd webui && npm install && npm run build)     # produce webui/dist so replicant web serves the SPA
mkdir -p out                                   # Suite F writes scenario CEF to ./out
```

**Entry criteria (all must hold before execution starts)**
- [ ] On `main` @ `0af51f7`, clean working tree.
- [ ] `.venv` tools runnable: pytest 9.1.1, black, ruff, mypy, Python 3.12.13. Record the exact versions at execution time.
- [ ] `webui/dist` built (else `replicant web` serves a build-me stub).
- [ ] No open PRs against `main` (confirmed 2026-07-21: PR #5, #6, #7, #8 all merged; list empty).
- [ ] `manifests/` snapshotted or emptied before Suite F, so CHAIN-03 can prove `scenario show` writes nothing.
- [ ] **No other session or process holds the working tree during Suite F.** CHAIN-03 and CHAIN-11 assert that nothing was written; a concurrent edit inside the measurement window produces a false FAIL. This happened during the 2026-07-21 run (see OBS-D).

**Suite G entry criteria (installer — additional, and currently unmet)**
- [ ] A disposable Linux VM with sudo and network access. Suite G changes system packages, so it must not run on a host anyone cares about.
- [ ] At minimum one host from each group: a distro shipping Python ≥ 3.11 (Debian 12, Ubuntu 24.04, Fedora) and one shipping < 3.11 (Ubuntu 22.04, RHEL/Rocky 9). The second group is what confirms or clears DEF-004.
- [ ] Ability to snapshot and roll back the VM between cases. INST-06/07/11/17 deliberately leave the host in a changed or failed state.
- [ ] **Status 2026-07-21: NOT MET.** No Linux host is available. Every Suite G case except INST-03 and INST-04 is BLOCKED. `scripts/install.sh` has never been executed on Linux.

**Suite H entry criteria (live SIEM — additional)**
- [ ] A LogRhythm deployment DJR controls and is authorised to send test data into. Suite H writes synthetic events into a real log store; they are indistinguishable from production data to anyone who did not run the test, so the destination must be a lab, not a customer or a shared production estate.
- [ ] A syslog log source configured for the sending host, and a FortiGate MPE policy available to it. FortiGate first: it is the only vendor whose golden lines are confirmed rather than `[Unverified]`.
- [ ] Network path from the Replicant host to the collector on the chosen port, and a way to observe arrival independent of the SIEM UI (a packet capture, or the collector's own counters). SIEM-11 needs this to prove the egress claim rather than infer it.
- [ ] At least one AIE rule or alarm in the lab that corresponds to a technique's `ndr_uc`. Without one, SIEM-08 and SIEM-09 cannot run and Round 3 stops at "parses correctly", which is a weaker claim than the one this suite exists to make.
- [ ] A marker to bound the test window (a note of the start time, or a dedicated log source), so events from this suite can be separated from whatever else the lab ingests.
- [ ] **Status 2026-07-29: NOT MET.** No live SIEM has been available at any point in this project. Every Suite H case is **BLOCKED**. Replicant has never sent a single event to a real SIEM.

## 3. Requirement traceability matrix (RTM)

| Req | Requirement (source) | Test case(s) | Owner |
|-----|----------------------|--------------|-------|
| SR-1 | Only egress is the operator-configured collector; fail closed if none (CLAUDE.md safety 1) | SAFE-01, CORE-07, CHAIN-11, INST-14, SIEM-11 | Both |
| SR-2 | All entities synthetic — RFC1918 + 192.0.2/24, 198.51.100/24, 203.0.113/24; non-resolvable DNS (safety 2) | SAFE-02, CORE-06, CHAIN-15, SIEM-12 | Both |
| SR-3 | No real attacks — writes log strings only (safety 3) | SAFE-03 | Claude |
| SR-4 | Respect eps cap, default 2000 (safety 4) | SAFE-04, CORE-08, CHAIN-14, SIEM-07 | Both |
| SR-5 | Every run writes a manifest (seed, technique, params, entities, target, counts, times) (safety 5) | SAFE-05, CORE-05, CHAIN-05, INST-16, SIEM-13 | Both |
| FR-1 | 11 techniques REP-001..011, each unique `ndr_uc` (phase 2) | CORE-01 | Claude |
| FR-2 | 3 vendors selectable on CLI, menu, web (phase 3) | CORE-04, TUI-03, UI-03, CHAIN-13 | Both |
| FR-3 | 3 transports UDP/TCP/TLS + loopback test (phase 2) | CORE-03 | Claude |
| FR-4 | CEF golden-line correctness per vendor (blueprint / *-cef-reference.md) | CORE-02 | Claude |
| FR-5 | Menu/CLI parity — anything the menu does, `replicant run` does headless (CLAUDE.md architecture) | CORE-09, TUI-05 | Both |
| FR-6 | Determinism — same seed+technique+params → same plan / byte-identical `--to-file` (CLAUDE.md standards) | CORE-05, CHAIN-06 | Claude |
| FR-7 | Web UI over the same Orchestrator (phase 1.5) | WEB-01..05, UI-01..06 | Both |
| FR-8 | Intensity presets low/medium/high + duration parsing (blueprint) | CORE-05, TUI-04, CHAIN-12 | Both |
| FR-9 | Scenario catalog composes multi-stage chains; `list`/`show`/`run` all reachable headless (phase 4) | CHAIN-01..04 | Claude |
| FR-10 | Every scenario run writes a paired manifest + advisory with matching stems (phase 4 design §7) | CHAIN-05, CHAIN-06 | Claude |
| FR-11 | Stage offsets, off-hours alignment, and correlation keys surfaced on both CLI and menu (phase 4) | CHAIN-07, CHAIN-08, TUI-07..09 | Both |
| FR-12 | Advisory is coverage/correlation only — humans author detection design (CLAUDE.md phase 4 boundary) | CHAIN-09, CHAIN-10, TUI-08 | Both |
| IN-1 | Installer fails closed and names the failing step on every error path (install design §7, exit codes §9) | INST-01, INST-02, INST-04, INST-17..19 | DJR |
| IN-2 | `sudo` used solely for package installs; consent explicit; declining leaves the host unchanged (§6) | INST-11, INST-12, INST-13 | DJR |
| IN-3 | Documented flags behave as documented; `--dry-run` changes nothing (§5) | INST-03, INST-05, INST-08..10 | DJR |
| IN-4 | Distro package mappings actually reach Python ≥ 3.11 and Node ≥ 18 — **known gap, see DEF-004** | INST-06, INST-07 | DJR |
| IN-5 | Verification proves a working install without leaving loopback or the repository (§6) | INST-14, INST-15, INST-16 | DJR |
| LR-1 | A real collector receives what Replicant sends, over the chosen transport, with no loss at the tested rate (blueprint: syslog to a SIEM, LogRhythm first) | SIEM-01, SIEM-07, SIEM-13 | DJR |
| LR-2 | A live SIEM identifies the log source and applies the intended vendor MPE policy without hand-tuning the parser | SIEM-02, SIEM-03 | DJR |
| LR-3 | Parsed fields match the vendor reference's field-mapping table; the `[Unverified]` signature IDs resolve or are corrected | SIEM-04, SIEM-10, SIEM-14 | DJR |
| LR-4 | Event time reaching the SIEM is correct for a live send (`--anchor now`), and a stale anchor warns before emitting (`STALE_ANCHOR_DAYS = 2`) | SIEM-05, SIEM-06 | DJR |
| LR-5 | Live sends respect the eps cap and do not overrun the collector (safety 4, on real infrastructure rather than loopback) | SIEM-07 | DJR |
| LR-6 | The targeted detection fires on the malicious pattern **and does not fire on the benign baseline** | SIEM-08, SIEM-09 | DJR |
| QG-1 | Full test suite green; the count is recorded per round, not fixed (Round 1: 179, Round 2: 235, Round 3: 526 Python + 89 frontend) | CORE-10 | Claude |
| QG-2 | black / ruff / mypy clean | CORE-11 | Claude |
| QG-3 | Frontend builds | WEB-00 | Claude |
| QG-4 | `shellcheck scripts/install.sh` clean | INST-00 | Claude |

## 4. Suite A — Automated core & CLI (Claude-driven)

Each case: run the command, capture output, record PASS/FAIL + evidence. Actual/Result columns filled during execution.

| ID | Req | Objective | Command / method | Expected | Result |
|----|-----|-----------|------------------|----------|--------|
| CORE-01 | FR-1 | All 11 techniques listed with unique ids/ndr_uc | `replicant list` | REP-001..011 shown; matches catalog table; no dup ndr_uc | |
| CORE-02 | FR-4 | CEF golden lines byte-for-byte, all 3 vendors | `pytest -k golden` (fortigate/paloalto/checkpoint golden files) | 27 golden assertions pass | |
| CORE-03 | FR-3 | UDP/TCP/TLS + loopback + fail-closed framing | `pytest tests/test_transport_loopback.py` | 8 pass incl. refused-TCP/TLS fail-closed | |
| CORE-04 | FR-2 | Each vendor renders correct CEF header to file | `replicant run REP-001 --vendor {fortigate,paloalto,checkpoint} --to-file <f> --no-send` x3 | Header vendor/product correct (Fortinet/Fortigate, Palo Alto Networks/PAN-OS, Check Point/…); no send attempted | |
| CORE-05 | FR-6, FR-8, SR-5 | Determinism + intensity + manifest | Run REP-004 seed 1337 medium `--to-file a.log --no-send`; repeat `--to-file b.log`; `diff a.log b.log`; inspect newest manifest | `a.log == b.log` byte-identical; manifest JSON has all required fields | |
| CORE-06 | SR-2 | Output entities are synthetic ranges only | Parse a `--to-file` output; extract src/dst IPs + any DNS names | Every IP in RFC1918/doc ranges; DNS names non-resolvable synthetic | |
| CORE-07 | SR-1 | Fail closed when send requested but no collector | `replicant run REP-001` with no `--host`/`--profile` and no `--to-file`/`--no-send` | Raises fail-closed RuntimeError; nothing emitted | |
| CORE-08 | SR-4 | eps cap honored / `--rate` override | Short run with `--rate 50 --to-file <f>`; check event_count vs elapsed in manifest | Rate not exceeded; cap default 2000 confirmed in `/api/config` and settings | |
| CORE-09 | FR-5 | CLI headless parity for a full run | `replicant run REP-007 --intensity high --seed 7 --to-file <f> --no-send` | Produces expected line volume; same as menu path would | |
| CORE-10 | QG-1 | Full suite green | `pytest` (note: the repo sets `addopts = "-q"`; do not pass `-q` again or `-qq` suppresses the summary line) | 235 passed | |
| CORE-11 | QG-2 | Lint/format/type clean | `black --check replicant tests`; `ruff check replicant tests`; `mypy replicant` | All clean | |

## 5. Suite B — Automated web / API (Claude-driven)

| ID | Req | Objective | Command / method | Expected | Result |
|----|-----|-----------|------------------|----------|--------|
| WEB-00 | QG-3 | Frontend builds | `(cd webui && npm run build)` | `tsc -b && vite build` succeed; `webui/dist` produced | |
| WEB-01 | FR-7 | API contract green | `pytest tests/test_web_api.py` | 16 passed | |
| WEB-02 | FR-7 | Server launches on loopback with token | `replicant web --no-browser` | Prints `http://127.0.0.1:<port>/?token=…`; bound to 127.0.0.1 only | |
| WEB-03 | FR-1/FR-7 | Catalog endpoint serves 11 techniques | `GET /api/health`, `GET /api/catalog` (with token) | health ok; catalog has 11 entries | |
| WEB-04 | FR-2/SR-4 | Config exposes vendors + real eps_cap | `GET /api/config` | `vendors=[fortigate,paloalto,checkpoint]`, `eps_cap=2000`, seed default | |
| WEB-05 | FR-7 | Run lifecycle via API | `POST /api/runs` (to loopback/file), `GET /api/runs/{id}`, SSE `…/events`, `POST …/stop` | Run starts, streams line/progress/done, stop works, manifest written | |
| WEB-06 | SR-1 | Host-header allowlist rejects non-localhost | Request with foreign Host header | Rejected by `_localhost_only` middleware | |

## 6. Suite C — Manual Rich TUI menu (DJR-driven)

Launch: `replicant menu`. Prompt shows `[1-11] technique  [a] scenario  [c] connection  [v] vendor  [s] seed  [q] quit`. The `[a]` key and TUI-07..09 are new in r2 (Phase 4).

| ID | Req | Objective | Steps | Expected | Result |
|----|-----|-----------|-------|----------|--------|
| TUI-01 | FR-7 | Menu renders technique table | Launch menu | 11 techniques in a numbered table; readable in the reskinned theme | |
| TUI-02 | FR-7 | Connection config `[c]` | Press `c`, enter host/port/transport | Collector set; no send until run | |
| TUI-03 | FR-2 | Vendor picker `[v]` | Press `v`, choose each vendor | Selection echoed; orchestrator rebuilt | |
| TUI-04 | FR-8 | Seed `[s]` + technique + intensity | Set seed, pick a technique, choose intensity | Run plan uses the chosen seed/intensity | |
| TUI-05 | FR-5 | Run a technique end to end | Pick REP-004, run to loopback or file | Lines emitted; manifest written; matches CLI behavior | |
| TUI-06 | — | Quit cleanly | Press `q` | Exits without traceback | |
| TUI-07 | FR-11 | Scenario picker `[a]` | Press `a` | Numbered picker lists SCEN-001/002/003 with names and stage counts; default `1`; selection accepted | |
| TUI-08 | FR-12 | Advisory renders before any emit decision | With **no** collector set, press `a`, pick SCEN-001 | Full advisory printed to the terminal first, then `no collector set; use [c] to connect, or run headless with 'replicant scenario run --to-file'`. Nothing emitted, no manifest written | |
| TUI-09 | FR-11 | Scenario run to a collector | Set a loopback collector via `[c]`, then `[a]` → SCEN-002 | Progress bar `emitting SCEN-002`; closes with event count, manifest path, advisory path; receiver sees the lines | |

## 7. Suite D — Manual web UI (DJR-driven)

Open the URL printed by `replicant web`. Emitter view = left rail (Connection + Catalog) / right (Run panel); Terminal tab = embedded `replicant menu`.

| ID | Req | Objective | Steps | Expected | Result |
|----|-----|-----------|-------|----------|--------|
| UI-01 | FR-7 | Emitter layout + theme | Load page | Header (logo, Emitter/Terminal tabs, collector status, theme toggle); reskin renders; theme toggle works light/dark | |
| UI-02 | FR-1 | Technique list + selection | Click techniques in the left rail | Selection arms the Run panel; first implemented technique auto-selected on load. NOTE: today click only selects — no detail panel yet (that is the next feature) | |
| UI-03 | FR-2 | Vendor selector | Change vendor radio in Connection card | Vendor switches; eps cap label shows real `config.eps_cap` | |
| UI-04 | FR-7 | Connection test | Enter collector, click Test | One benign line rendered/returned | |
| UI-05 | FR-7/SR-4 | Run + eps SignalReadout | Start a run | Progress + live eps waveform; count/total advance; stop works. WATCH: does the waveform cap/scale match a non-default eps_cap? (see DEF-002) | |
| UI-06 | FR-7 | Embedded terminal | Open Terminal tab | xterm connects to `replicant menu` over WS; interactive | |

## 8. Suite E — Safety rules (Claude-driven, explicit)

The five non-negotiables get their own dedicated validation, independent of functional cases.

| ID | Rule | Test | Expected | Result |
|----|------|------|----------|--------|
| SAFE-01 | SR-1 | Attempt to emit with no collector + no file (see CORE-07); inspect emitter binds to single peer | Fail-closed; single-peer only (`transport/syslog.py:20-23`) | |
| SAFE-02 | SR-2 | Static + runtime: entity ranges enforced (`entities/model.py:31-63`); scan real output | Out-of-range entity raises; output all-synthetic | |
| SAFE-03 | SR-3 | Confirm transport only ever receives a `str` (`cef/serializer.to_cef`→`SyslogEmitter.send(str)`); no exec/socket to non-collector | Only strings sent; no command execution path | |
| SAFE-04 | SR-4 | eps cap default 2000 enforced in emit loop (`orchestrator.py:187,219-224`); `--rate` override respected | Rate honored | |
| SAFE-05 | SR-5 | Every run writes a manifest with all fields (`audit/manifest.py`, `models.py:176-194`) | Manifest present + complete after each run above | |

## 9. Suite F — Scenario composition, Phase 4 (Claude-driven)

New in r2. Covers `docs/phase4-scenario-composition-design.md` as shipped in PR #7. Prefix is `CHAIN-` on purpose: `SCEN-001` is already a catalog scenario id, so a `SCEN-` test prefix would collide with the thing under test.

Note the CLI/menu asymmetry recorded as OBS-005: `scenario run` takes `--to-file` and `--intensity`, the menu path does not. That direction is compliant with the CLAUDE.md parity rule (anything the menu does, the CLI does), so it is not a defect.

| ID | Req | Objective | Command / method | Expected | Result |
|----|-----|-----------|------------------|----------|--------|
| CHAIN-01 | FR-9 | Catalog lists all three chains | `replicant scenario list` | SCEN-001/002/003 with name, stage count, tactic span | |
| CHAIN-02 | FR-9 | Bare verb defaults to `list` | `replicant scenario` | Identical output to CHAIN-01 (`action` defaults, `cli/app.py:276`) | |
| CHAIN-03 | FR-9 | `show` is a dry preview that writes nothing | Snapshot `manifests/`; `replicant scenario show SCEN-001`; re-snapshot | Advisory rendered to stdout; **no** manifest, **no** `.advisory.md`, no emit; `manifests/` byte-identical before and after | |
| CHAIN-04 | FR-9 | Unknown id fails cleanly | `replicant scenario show SCEN-999` | `unknown scenario` + hint to run `scenario list`; exit 1; no traceback | |
| CHAIN-05 | FR-10, SR-5 | Run writes a paired manifest + advisory | `replicant scenario run SCEN-001 --seed 1337 --to-file ./out/s1.log --no-send` | `manifests/SCEN-001-seed1337-<ts>.json` plus `…​<ts>.advisory.md` sharing the stem; 3 summary lines (events/stages, manifest, advisory) | |
| CHAIN-06 | FR-6, FR-10 | Determinism across identical runs | Run SCEN-002 seed 1337 to file twice; `diff` the CEF; diff the advisories | CEF byte-identical; advisory identical apart from timestamps | |
| CHAIN-07 | FR-11 | Off-hours alignment surfaces in the kill chain | `replicant scenario show SCEN-001`; read the kill-chain table | Exfil stage annotated `(+Nd aligned)`, from `align: next-off-hours` on the REP-005 stage. This is the one chain carrying it | |
| CHAIN-08 | FR-11 | Mixed correlation keys render per stage | `replicant scenario show SCEN-003` | Credential stages (REP-007) correlate on user; C2 stage (REP-001) correlates on host; both shown in the `correlate on` column | |
| CHAIN-09 | FR-12 | Advisory stays advisory-only | Read any generated `.advisory.md` | Boundary blockquote present verbatim; coverage and correlation prompts only; **no** rule logic, no AIE/Sigma/KQL syntax, no thresholds presented as a rule | |
| CHAIN-10 | FR-12 | Coverage and gaps both rendered | Same advisory | `## ATT&CK coverage` lists `Covered:` and a `Gaps` block naming techniques the catalog can exercise but this chain does not | |
| CHAIN-11 | SR-1 | Fail closed on the scenario path | `replicant scenario run SCEN-001` with no collector, no `--to-file`, no `--no-send` | `run refused`, exit 1, nothing emitted. Confirms the Round 1 fail-closed guarantee holds on the new surface | |
| CHAIN-12 | FR-8 | Intensity override reaches every stage | Run SCEN-002 three ways: no flag, `--intensity high`, `--intensity low`. Compare **per-stage** counts, not the total | Per-stage counts move in both directions. `--intensity low` is the decisive case: it must force stage 2 (catalog `high`, 180000 events) *down*, proving a true override rather than a raised floor. Do not judge on total count: stage 2 dwarfs the others, so `high` moves the total only +1.7% (see OBS-B) | |
| CHAIN-13 | FR-2 | Vendor selection applies to scenarios | `scenario run SCEN-001 --vendor checkpoint --to-file f --no-send` | Every line renders `CEF:0\|Check Point\|…`; repeat for `paloalto` | |
| CHAIN-14 | SR-4 | eps cap governs the whole chain | `scenario run SCEN-003 --rate 50` to a loopback receiver | Delivered rate ≤ 50/s measured across the full chain, not reset per stage | |
| CHAIN-15 | SR-2 | Entities synthetic across every stage | Scan a full scenario `--to-file` output | All IPs in RFC1918/documentation ranges; usernames and DNS names synthetic. Multi-stage chains reuse entities across techniques, so this is not covered by CORE-06 | |
| CHAIN-16 | — | Web UI scenario surface absent, no regression | With the server running, request `/api/scenarios`, `/api/scenarios/SCEN-001`, `/api/scenario/list`, `/api/runs/scenario`, `/ws/scenario`. In the UI, confirm there is no scenario control in the left rail, the run form, or the Docs tab | All five routes 404. No scenario control anywhere in the UI. Asserts the documented deferral (OBS-006), not a feature | |

## 10. Suite G — Linux installer (DJR-driven, requires a Linux host)

New in r2. Covers `scripts/install.sh` (PR #8) against `docs/linux-install-script-design.md`.

**This is the least-validated component in the product.** The script has never been executed on Linux. Every claim made about it to date came from `--dry-run`, PATH-shimmed function harnesses, or driving the underlying commands against the existing venv. `docs/linux-install-script-design.md` §8 states outright that it carries no pytest coverage and that final confirmation is a real run on a Linux host.

**Executability today:** INST-00 is automated. INST-03 and INST-04 run from the macOS dev host. **INST-01, INST-02, INST-05..19 are BLOCKED** pending a VM. Do not record them as passed on the basis of a dry run.

| ID | Req | Objective | Steps | Expected | Result |
|----|-----|-----------|-------|----------|--------|
| INST-00 | QG-4 | Static analysis clean | `shellcheck scripts/install.sh` | No findings | |
| INST-01 | IN-1 | Help text complete and accurate | `./scripts/install.sh --help` | Exit 0; documents `--no-web`, `--dev`, `--yes/-y`, `--dry-run`, `--help/-h`; carries the install-time-egress note distinguishing PyPI/npm from the runtime collector-only rule | |
| INST-02 | IN-1 | Unknown flag rejected | `./scripts/install.sh --bogus` | Usage printed to **stderr**, exit 1 (`EX_USAGE`) | |
| INST-03 | IN-3 | `--dry-run` is completely inert (runnable on macOS) | Record `.venv` mtime + `git status`; `./scripts/install.sh --dry-run`; re-check | Warns host is not Linux and continues; prints the full `would run:` plan; closes with the dry-run notice. Nothing installed, no file mtime changed, working tree unchanged | |
| INST-04 | IN-1 | Real run refuses non-Linux (runnable on macOS) | `./scripts/install.sh` on the dev Mac | Dies `EX_USAGE` (1) at preflight, **before** any package manager or sudo interaction | |
| INST-05 | IN-3 | Clean install where the distro already satisfies the minimums | Fresh Debian 12 / Ubuntu 24.04 / Fedora VM | All 9 steps pass (Preflight → Package manager → Prerequisites → Install prerequisites → Virtual environment → Install Replicant → Web UI → Verify → Done); report block prints; `replicant list` works from the venv | |
| INST-06 | IN-4 | **The [Unverified] distro gap, Debian family** | Fresh Ubuntu 22.04 VM (ships Python 3.10) | **Expected to FAIL today:** consents, installs the default `python3`, re-checks, dies `still missing after install: …` (exit 3) having changed the system for no benefit. Confirms DEF-004. Capture the exact output | |
| INST-07 | IN-4 | **The [Unverified] distro gap, RHEL family** | Fresh RHEL/Rocky/Alma 9 VM (ships Python 3.9, `nodejs` < 18) | Same failure as INST-06. RHEL is the core audience for a SIEM tool, so this case gates release more than INST-06 does | |
| INST-08 | IN-3 | `--no-web` skips Node entirely | `--no-web` on a clean VM | No node/npm install attempted, no frontend build; report shows `not built (--no-web)` plus the manual build hint | |
| INST-09 | IN-3 | `--dev` installs the dev extra | `--dev` on a clean VM | pytest/black/ruff/mypy present in `.venv`; `pytest` runs from it | |
| INST-10 | IN-3 | `--dev --no-web` interaction is explained | `--dev --no-web` | Info line stating the dev extra still installs fastapi/uvicorn but no frontend is built | |
| INST-11 | IN-2 | Consent required; declining is safe | Run without `--yes` on a host with missing packages; answer no | Exits 3 with `declined; install the packages above and re-run`; **nothing installed**; host unchanged | |
| INST-12 | IN-2 | No TTY and no `--yes` fails closed | Run with stdin closed / non-interactively, packages missing | `no terminal available to confirm; re-run with --yes to install non-interactively`. Confirms consent is read from `/dev/tty`, never stdin | |
| INST-13 | IN-2 | sudo scope limited to package installs | `bash -x` trace, or audit the sudo log | `sudo` appears only around package-manager calls. Never for venv creation, pip, npm, or verification. Running as root triggers the EUID warning | |
| INST-14 | SR-1, IN-5 | Verification transmits to loopback only | Packet-capture or observe the verify step | UDP datagrams to `127.0.0.1:<ephemeral>` only. No egress to anything else, consistent with safety rule 1 | |
| INST-15 | IN-5 | Verification actually proves the install | Read the Verify step output | `replicant list` succeeds; first line of the file run matches `^CEF:0\|`; loopback listener receives > 0 datagrams | |
| INST-16 | IN-5, SR-5 | Nothing written outside the repository | Marker file + `find` for newer files outside the repo, excluding package-manager paths | Only the repo and package-manager paths touched. Verification manifests are **deliberately kept** in `manifests/` as the safety-rule-5 audit record; confirm they are present rather than cleaned up | |
| INST-17 | IN-1 | Stale sub-3.11 venv rejected with a usable fix | Pre-create a Python 3.9 `.venv`, then run the installer | Dies `EX_VENV` (4) with `existing .venv uses Python 3.9, below 3.11; remove it and re-run: rm -rf <venv>` | |
| INST-18 | IN-1 | ERR trap names the failing step | Induce a failure in an **unguarded** command. Dropping the network during pip does NOT reach the trap: every substantive command is `\|\| die`-guarded and dies cleanly (see OBS-E). Use `chmod 000 /usr/bin/mktemp` after a green baseline, which models a read-only or full `/tmp` | Exactly three stderr lines: `installation failed during "<step>"`, then `line N, exit C: <command>`, then the `--dry-run` hint. Confirms `set -E` is live. More than three means the trap is also firing inside a subshell (DEF-007) | |
| INST-19 | IN-1 | Clean output when not a TTY | `./scripts/install.sh --dry-run > log 2>&1`, then again with `NO_COLOR=1` | No ANSI escape sequences in either log | |

## 11. Suite H — Live SIEM ingestion (DJR-driven, requires a LogRhythm lab)

New in r3. This is the **oldest open item in the project**; it predates v0.1.0 and has never had pass criteria written against it.

**Replicant has never sent a single event to a real SIEM.** Every transport case in Rounds 1 and 2 used an in-process loopback receiver, which proves framing and delivery and nothing else. It cannot tell you whether LogRhythm identifies the log source, whether the MPE policy parses the CEF, which metadata fields populate, or whether a rule fires. Those are the product's entire reason for existing, and they are currently unmeasured.

**Executability today: every case is BLOCKED** pending a LogRhythm deployment. Do not record any case as passed on the basis of a loopback receiver, a `--to-file` inspection, or the golden-line tests. Those already pass and are not evidence for anything in this suite.

**Order matters.** Run these in sequence and stop at the first failure; SIEM-04 onward are meaningless if SIEM-03 shows the message is not being parsed. Use FortiGate throughout unless a case says otherwise.

| ID | Req | Objective | Steps | Expected | Result |
|----|-----|-----------|-------|----------|--------|
| SIEM-01 | LR-1 | One benign line arrives | `replicant connect --host <collector> --port 514 --transport udp --test` | Exactly **one** message reaches the collector and is searchable in LogRhythm. Record the ingestion lag. One, not zero and not several: the test sends a single benign `traffic:forward accept` line | |
| SIEM-02 | LR-2 | Log source identified as FortiGate | Inspect the log source LogRhythm assigned to the sending host | Identified as a Fortinet FortiGate syslog source, **not** Unknown and not a generic syslog catch-all. Record the exact log source type and the MPE policy applied. If it lands as Unknown, that is a High defect: it means the syslog framing or header does not look like FortiGate to the platform | |
| SIEM-03 | LR-2 | MPE parses rather than shelving it | Search for the message and read its classification | Message is parsed and classified, not filed as Unidentified. Record the Common Event assigned. A message that ingests but does not parse is a **fail**: it is invisible to every rule that keys on a field | |
| SIEM-04 | LR-3 | Field mapping matches the oracle | Run REP-001 low with `--anchor now`. Compare LogRhythm's parsed metadata against the field-mapping table in `docs/fortigate-cef-reference.md` | Source/destination IP, source/destination port, protocol, action, bytes in/out, and device identity all populate the fields the reference says they map to. **Compare field by field against the table, not by eye.** Any mismatch is a defect against the reference doc; record which side is wrong before changing either | |
| SIEM-05 | LR-4 | **Event time is correct on a live send** | Run once with `--anchor now`, once with the default fixed anchor. Compare the event time LogRhythm records against the receipt time | With `--anchor now`: event time within minutes of receipt. With the default: event time roughly a year in the past. **This case is the reason the suite exists.** That exact condition once made every recent-window rule silent, which is indistinguishable from a detection that does not work. If `--anchor now` does not produce a current event time, everything downstream of it is unreliable | |
| SIEM-06 | LR-4 | Stale anchor warns before emitting | Start a live send with the default anchor | The CLI prints the stale-anchor warning **before** any event is transmitted (`STALE_ANCHOR_DAYS = 2`, `replicant/config/settings.py`). A warning printed after the fact does not count | |
| SIEM-07 | LR-1, LR-5, SR-4 | Rate is survivable and capped | `--rate 50`, then step up (200, 500) watching the collector | No drops and no queue growth at each step. Record the lab's ceiling. Note the `eps_cap` default is **2000**, which is likely well above what a lab collector wants; the cap governs sending, so a live send is throttled where a `--no-send` run is not | |
| SIEM-08 | LR-6 | **A detection actually fires** | Pick a technique whose `ndr_uc` maps to a rule that exists in the lab (`replicant list` prints the mapping). Run it at an intensity the rule should catch | The alarm fires within its evaluation window, and its evidence points at the synthetic entities from the run. Record the technique, the rule, the intensity, and the time to alarm | |
| SIEM-09 | LR-6 | **The benign baseline does not fire it** | Same rule. Run only the technique's benign baseline, or a technique whose baseline covers the same log type | The rule stays quiet. This is the case that distinguishes a detection from an alarm that fires on everything, and it is why `benign_baseline` is generated rather than merely documented. A rule that fires on both SIEM-08 and SIEM-09 has a false-positive problem the lab should know about | |
| SIEM-10 | LR-3 | Resolve the two `[Unverified]` signature IDs | Run REP-004 (`dns:dns-query`) and REP-007 (`event:vpn`, includes a `tunnel-up` success). Read what the parser makes of signature **54803** and **39947** | Either the parser accepts them, in which case the `[Unverified]` markers in `replicant/profiles/fortigate.py:53,55` come off, or it does not, in which case the correct values are recorded and the code, the reference doc and the CHANGELOG are all corrected together. `dns-response` 54802 and `login-fail` 39426 are already confirmed and serve as the control | |
| SIEM-11 | SR-1 | Egress is the collector and nothing else | Packet-capture the sending host for the duration of a live run | Traffic to the configured collector only. No DNS resolution of the synthetic domains, no connection to any documentation-range address, no telemetry anywhere. This is safety rule 1 tested against real infrastructure instead of a loopback socket | |
| SIEM-12 | SR-2 | What lands in the SIEM is synthetic | Query the ingested events for source and destination addresses and any domains | Addresses confined to RFC1918 and the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Domains under the IANA documentation domains or `.invalid`. **Nothing routable and nothing real.** An analyst finding these later must be able to tell they were synthetic | |
| SIEM-13 | LR-1, SR-5 | Manifest reconciles with what arrived | After a completed run, compare `manifests/<run>.json` against the SIEM's event count for the window | The manifest's event count matches the number ingested. A shortfall is loss and needs SIEM-07 revisited; an excess means the window caught something else. The manifest is the reproduction recipe, so attach it to every recorded result | |
| SIEM-14 | LR-3 | Palo Alto and Check Point, if the lab has them | Repeat SIEM-02..04 with `--vendor paloalto` and `--vendor checkpoint` against matching log sources | Optional and **expected to be skipped**. Both profiles' golden lines are `[Unverified]` and have never been checked against a live build (3 PA markers, 4 CP). Any result here is a bonus; a failure is a known-unknown being resolved, not a regression | |

## 12. Pre-execution findings (from recon, before formal run)

Round 1 recon surfaced 5 issues. All five were re-verified against `main` @ `0af51f7` on 2026-07-21; three are now closed. Round 2 recon adds three more.

| ID | Sev | Priority | Title | Location | Status (2026-07-21) |
|----|-----|----------|-------|----------|---------------------|
| DEF-001 | Trivial | Low | Stale test count in README | `README.md:224` | **FIXED.** README now reads `# 235 tests`, matching the suite. |
| DEF-002 | Low | Medium | Web eps waveform cap hardcoded `2000` instead of `config.eps_cap` | `webui/src/components/RunPanel.tsx` | **FIXED.** `RunPanel` now takes an `epsCap: number` prop and passes `cap={epsCap}` (`:276`). No hardcoded literal remains. |
| DEF-003 | Trivial | Low | All 11 techniques hardcoded `implemented=true` → `soon`/`not-runnable` UI states are dead code | `replicant/web/server.py:92-105` | **STILL OPEN.** Re-confirmed: `implemented` is `technique.id in {…all 11 ids…}`, a set literal, so it is unconditionally true. Cleanup or drive from real state. Not user-facing while all 11 are implemented. |
| OBS-001 | Info | — | `/api/catalog` omitted `distributions`/`benign_baseline`/`cef_fields_*`/`references` | `replicant/web/server.py:109-114` | **RESOLVED** by PR #6. All four field groups are now served; the detail panel consumes them. |
| OBS-002 | Info | — | No frontend test runner (no `test` script / vitest) | `webui/package.json:6-10` | **STILL OPEN.** Scripts are `dev`/`build`/`preview` only; zero vitest references. All backend is covered; the SPA is not. |
| DEF-004 | High | High | Installer distro mappings cannot reach the required Python 3.11 (or Node 18) on several current LTS releases | `scripts/install.sh` | **CONFIRMED on real Linux 2026-07-21, then FIXED.** No longer `[Unverified]`. Reproduced in `ubuntu:22.04`: the original script installed packages, re-checked, and died `still missing after install: python node` (exit 3) having mutated the host. Measured availability: Ubuntu 22.04 default `python3` 3.10.6 and `nodejs` 12.22.9; Rocky 9 default 3.9.18 and 16.20.2; Debian 12 already fine at 3.11.2 / 18.20.4. Fix resolves candidates by querying the package manager *before* consenting to sudo, and refuses with actionable guidance when nothing on offer qualifies. Re-verified: Ubuntu 22.04 → exit 3 with `pkg_delta=0`; Rocky 9 → exit 0, Python 3.12.13, verification green. |
| DEF-005 | High | High | apt path installed a GUI desktop stack onto a headless host | `scripts/install.sh:196` | **FOUND BY REAL TESTING, FIXED.** `apt-get install -y` carried no `--no-install-recommends`, so the recommended closure pulled in `tilix` (a GUI terminal emulator), `libgtk-3-bin`, `libvte`, `ubuntu-mono` and `humanity-icon-theme` on a server image. Nobody predicted this; it is invisible to `--dry-run` because dry-run never resolves the dependency tree. Fixed with `--no-install-recommends` (apt) and `--setopt=install_weak_deps=False` (dnf/yum). Rocky 9 post-fix installs 9 packages total. |
| OBS-A | Info | Medium | The eps cap is a fixed-window cap, not an instantaneous one | `replicant/core/orchestrator.py:280-299` | Counts to `eps_cap`, sleeps the remainder of the wall second, resets. Events cluster at the head of each window, so a *sliding* one-second window straddling a boundary can exceed the cap: measured once at 59 against a cap of 50 (+18%), not reproduced on repeat. Fixed one-second buckets never exceeded 50. Does not fail CHAIN-14 (overall 49.94/s), but safety rule 4 should state which guarantee it makes. Recommend documenting it as a fixed-window average. |
| OBS-B | Info | — | CHAIN-12's "materially higher event count" is a weak criterion | `tasks/uat-plan.md` Suite F | `--intensity high` moves SCEN-002 only 181071 → 184151 (+1.7%), because stage 2 is already `high` in the catalog and dwarfs the rest; a tester reading the criterion literally could record FAIL. The decisive test is `--intensity low`, which forces the catalog-`high` stage 180000 → 36000 and so distinguishes a true override from raising a floor. Case text updated accordingly. |
| OBS-C | Info | Low | `scenario show` writes its unknown-id error to stdout, not stderr | `replicant/cli/app.py:296-297` | Exit code is correct (1) and CHAIN-04 does not specify a stream, so this is not a failure. It is inconsistent with INST-02, which requires usage on stderr. Consistency decision, not a defect. |
| OBS-D | Info | Medium | Suite F has no guard against a concurrent session holding the working tree | `tasks/uat-plan.md` §2 | During execution another session edited `README.md` inside the measurement window, which nearly produced a false FAIL on CHAIN-03, the one case whose entire purpose is proving nothing is written. Added to the entry criteria. |
| OBS-005 | Info | — | Menu scenario path cannot write to a file and has no intensity override | `replicant/cli/menu.py:126-132` | Not a defect. `_run_scenario` hardcodes `to_file=None`; the CLI is a strict superset of the menu, which is the direction the CLAUDE.md parity rule requires (anything the menu does, `replicant` does headless). Recorded so it is not re-raised as a bug. |
| OBS-006 | Info | — | Web UI has no scenario surface at all | `webui/src`, `replicant/web/server.py` | Deferred fast-follow per `docs/phase4-scenario-composition-design.md` §13. **CHAIN-16 revised 2026-07-29.** It previously read "grep for `scenario` returns zero hits", which was never a correct test and is now demonstrably wrong: `replicant/web/server.py` imports `replicant.scenario.engine` for `implemented_technique_ids`, so the grep already returns a hit with no scenario feature present. CHAIN-16 now asserts the thing it actually meant, that the candidate routes 404 and no scenario control exists in the UI. |

## 13. Defect management

Severity: **Critical** (safety-rule breach, data leak, crash on core path) → **High** (surface unusable / wrong CEF) → **Medium** (functional deviation w/ workaround) → **Low** (cosmetic/minor) → **Trivial** (docs/typo).
Any Critical against a safety rule is an automatic **No-Go** and blocks release. Each defect logged with: id, severity, priority, steps to reproduce, expected vs actual, location, owner.

## 14. Exit criteria & Go/No-Go

### Round 1 — Phases 1/1.5/2/3 (automated portion signed GO, 2026-07-19)
- [x] Suite A + B + E: 100% pass (Claude).
- [ ] Suite C + D: 100% pass (DJR), or any failure triaged and accepted. **Still outstanding.**
- [x] Zero open Critical/High defects at the time. All 5 safety rules PASS.
- [x] QG-1, QG-2, QG-3 green (against the then-current 179 tests).
- [x] DEF-001..003 dispositioned. DEF-001 and DEF-002 have since been fixed; DEF-003 accepted as Trivial and remains open.

### Round 2 — Phase 4 scenarios + installer (not started)
- [ ] Suite F: 100% pass (Claude).
- [ ] Suite G: 100% pass (DJR on Linux), or each failure triaged and accepted.
- [ ] TUI-07..09 pass (DJR).
- [ ] QG-1 (235 green), QG-2 (lint/type clean), QG-3 (frontend build), QG-4 (shellcheck) all green.
- [ ] **DEF-004 dispositioned.** It is currently High, and a High blocks Go under the rule below. Either the distro mappings are fixed, or the installer refuses before taking sudo on a host it cannot satisfy, or the release explicitly narrows its supported-distro claim. Shipping an installer that changes a RHEL host and then dead-ends is not an acceptable resolution.
- [ ] DEF-003 and OBS-002 re-dispositioned (fix now, or accept + ticket).

**Blocking note:** Round 2 cannot reach Go while Suite G is unexecutable. A Linux VM is the single dependency. Until then the honest status is *Round 2 authored, not run*, and the product should not be described as having a validated Linux install path.

### Round 3 — Live SIEM ingestion (authored 2026-07-29, not started)

- [ ] SIEM-01..06 pass. These are the gate: delivery, identification, parsing, field fidelity, and event time. A failure in any of them stops the round, because the cases after them assume the events are being parsed correctly.
- [ ] SIEM-07 passes and the lab's practical rate ceiling is **recorded**, not just observed.
- [ ] SIEM-08 and SIEM-09 both pass **as a pair**. SIEM-08 alone is not a result: a rule that fires on the technique and also on its benign baseline has told you nothing about whether it detects anything. If the lab has no matching rule, both are marked BLOCKED rather than passed, and Round 3 is explicitly recorded as reaching "parses correctly" and no further.
- [ ] SIEM-10 dispositioned. Either the two `[Unverified]` markers come off, or the correct signature IDs are recorded and `replicant/profiles/fortigate.py`, `docs/fortigate-cef-reference.md`, the technique catalog and the CHANGELOG are corrected **together**. Changing one of the four is the failure mode this project keeps hitting.
- [ ] SIEM-11, SIEM-12, SIEM-13 pass. These are safety rules 1, 2 and 5 tested against real infrastructure for the first time. **Any failure here is Critical and an automatic No-Go**, under the existing rule in §13.
- [ ] SIEM-14 run or explicitly skipped, with the reason recorded.
- [ ] QG-1 (526 Python + 89 frontend green), QG-2, QG-3, QG-4 all green on the commit under test.

**Blocking note:** Round 3 cannot start without a LogRhythm deployment, which is the single dependency and has never been available. Until it runs, the honest status is *Round 3 authored, not run*, and **Replicant must not be described as validated against a SIEM, or as having working detections**. Passing golden-line tests proves the CEF matches a reference document; it does not prove a parser accepts it or a rule fires on it. Those are different claims and only Suite H tests the second one.

**Sign-off:** QA lead (Claude) records automated results; DJR signs the manual + overall Go/No-Go.

## 15. Execution log

### Automated run 1 — 2026-07-19 (on `main` @ `8fe3d31`, PR #5 merge commit)

- **CORE-01 PASS** — `replicant list` shows REP-001..011 with UC-001..010, log types, ATT&CK ids.
- **CORE-02 PASS** — CEF golden lines (fortigate/paloalto/checkpoint) pass within the full suite.
- **CORE-03 PASS** — transport loopback (UDP/TCP/TLS + refused-peer fail-closed) pass within the full suite.
- **CORE-10 PASS** — full suite **179 passed, exit 0**. Non-fatal `StarletteDeprecationWarning` (test dep httpx/testclient) — logged as OBS-003.
- **CORE-11 PASS** — black (44 files unchanged), ruff (all checks passed), mypy (no issues, 30 source files).
- **WEB-01 PASS** — `test_web_api.py` (16) pass within the full suite.
- Env: local `main` fast-forwarded 18 commits to `origin/main` (`8fe3d31`).

### Automated run 2 — Suite A (core/CLI) + Suite E (safety) COMPLETE

- **CORE-04 PASS** — vendor CEF headers: `Fortinet|Fortigate`, `Palo Alto Networks|PAN-OS`, `Check Point|VPN-1 & FireWall-1` (CP severity string `Unknown`).
- **CORE-05 PASS** — REP-004 medium seed 1337 byte-identical across 2 runs (108,000 lines).
- **CORE-06 / SAFE-02 PASS** — entity scan of 5 files (3 vendors + DNS + VPN): 0 IP violations (all RFC1918/doc ranges); DNS names all under non-resolvable `example.net`.
- **CORE-07 / SAFE-01 PASS** — fail-closed, exit 1, when send requested with no collector + no `--to-file`.
- **CORE-08 / SAFE-04 PASS** — eps throttle: N=4000; `--rate 30` → 29.9/s delivered (throttled), `--rate 5000` → 6208/s (unthrottled). Cap governs send rate.
- **CORE-09 PASS** — REP-007 `event:vpn` renders (ssl-login-fail, sev 7, synthetic `duser`/`src`).
- **SAFE-03 PASS** — only socket in the emission path is `transport/syslog.py` (single egress); no `subprocess`/`exec`/`pty`.
- **SAFE-05 PASS** — manifest complete (14 fields) per run.

**Suite A: 11/11 PASS. Suite E: 5/5 PASS. All 5 non-negotiable safety rules verified behaviorally.**
### Automated run 3 — Suite B (web integration) COMPLETE

- **WEB-02 PASS** — server bound loopback `127.0.0.1:<ephemeral>`, 22-char token; `/api/health` 200.
- **WEB-03 PASS** — `/api/catalog` 401 without token, 200 with token, 11 techniques.
- **WEB-04 PASS** — `/api/config`: vendors=[fortigate,paloalto,checkpoint], eps_cap=2000, default_seed=1337.
- **WEB-05 PASS** — run REP-002 high via API: total=4000, live SSE (line×2000 sampled, progress×40, done×1), event_count=4000, loopback sink received all 4000, manifest written.
- **WEB-05b PASS** — stop → `{ok:true}`.
- **WEB-06 PASS** — foreign Host header → 403.
- **OBS-004** (info) — SSE `line` events are sampled/capped at 2000 while the run emitted 4000 (progress + sink confirm the full send). By-design UI flood protection, not a defect.

**Suite B: 6/6 PASS** (plus WEB-00 build, WEB-01 16 API tests within the full suite).

### Automated run 4 — 2026-07-21, Suite F (scenario composition) COMPLETE

Executed against `main` @ `0af51f7`. Every case driven with real commands; no case passed on inspection alone.

- **CHAIN-01/02 PASS** — all 3 chains listed with name, stage count, tactic span. Bare `replicant scenario` output is `diff`-identical to `scenario list`.
- **CHAIN-03 PASS** — `scenario show` wrote nothing. `manifests/` (113 files) sha256 list byte-identical before and after; whole-repo inventory of 338 files showed zero added or removed.
- **CHAIN-04 PASS** — unknown id: exit 1, `unknown scenario: SCEN-999. Try 'replicant scenario list'.`, zero tracebacks.
- **CHAIN-05 PASS** — 1133 events across 3 stages; manifest and advisory share the stem `SCEN-001-seed1337-20260721T131640`. Manifest carries all SR-5 fields plus per-stage records.
- **CHAIN-06 PASS, stronger than specified** — two SCEN-002 seed-1337 runs are byte-identical (sha256 `3ad92c69…`, 181071 lines each) **and the two advisories are byte-identical too** (sha256 `314de1bc…`), not merely "identical apart from timestamps".
- **CHAIN-07 PASS** — `align` appears exactly once in the catalog (`data/scenario-catalog.yaml:15`); the exfil row renders `2025-07-16 00:00 -> 2025-07-16 05:54 (+1d aligned)`.
- **CHAIN-08 PASS** — SCEN-003 correlates per stage: `duser=jsmith`, `duser=mkhan` on the credential stages, `src=10.20.30.139` and `src=203.0.113.224` on the host-keyed stages.
- **CHAIN-09 PASS** — boundary blockquote present verbatim. A regex sweep for `sigma|AIE|KQL|SPL|EventID|index=|sourcetype=|selection:|condition:|logsource|rule that|alert when|threshold` across two generated advisories matched **only the disclaimer line itself**.
- **CHAIN-10 PASS** — Covered: TA0007/TA0011/TA0010; Gaps correctly name TA0006→REP-007, TA0042→REP-008, TA0043→REP-009, TA0001→REP-011.
- **CHAIN-11 PASS** — fail-closed: exit 1, `run refused: fail-closed: sending requested but no collector is configured and no --to-file was given.` Repo inventory unchanged.
- **CHAIN-12 PASS** — per-stage override proven by `--intensity low` (180000→36000 on the catalog-`high` stage), which `--intensity high` alone could not distinguish from raising a floor. See OBS-B.
- **CHAIN-13 PASS** — one distinct header per vendor, zero non-matching lines across 1133 lines each: `Fortinet|Fortigate`, `Palo Alto Networks|PAN-OS`, `Check Point|VPN-1 & FireWall-1`.
- **CHAIN-14 PASS** — real timestamped loopback listener: 653/653 datagrams over 13.076s = **49.94/s** against `--rate 50`; repeat 49.93/s. Not reset per stage, confirmed both by measurement (no bucket spike at stage boundaries) and by `orchestrator.py:366-374` calling `_emit` once on the flattened event list. See OBS-A.
- **CHAIN-15 PASS** — 182,857 lines scanned: **0 non-synthetic IPs** across 1041 distinct addresses; all 180,000 DNS qnames under the single documentation parent `sync.example.net`; usernames from the synthetic pool.
- **CHAIN-16 PASS** — zero `scenario` hits in `replicant/web/server.py`, `webui/src`, or the built SPA. Five candidate scenario routes all 404. Catalog and config endpoints unaffected.

**Suite F: 16/16 PASS.**

### Manual run — 2026-07-21, Suite G (Linux installer) PARTIAL, via containers

The Linux-host entry criterion was met differently than planned: Docker containers (`ubuntu:22.04`, `debian:12`, `rockylinux:9`) rather than VMs. This exercises distro detection, package managers, real package availability, venv creation, pip install, and the verification step. It does **not** exercise `sudo` (containers run as root, so the script's EUID-0 warning path is what runs instead), so INST-13 remains genuinely blocked.

- **INST-00 PASS** — `shellcheck scripts/install.sh` clean, before and after the fix.
- **INST-06 CONFIRMED THE DEFECT, then FIXED** — Ubuntu 22.04 with the original script: exit 3, `still missing after install: python node`, **after** installing packages. Fix verified: exit 3, `pkg_delta=0`, refusal issued before any install.
- **INST-07 PASS (Rocky 9 substituting for RHEL 9)** — original script would have failed identically; fixed script installs Python 3.12.13 and completes. Exit 0, `pkg_delta=9`, verification green (49 CEF lines written, 49 delivered over loopback).
- **INST-05 PASS** — Rocky 9 full run reached `Done` with all 9 step banners in order.
- **INST-05 PASS (Debian 12, full path)** — exit 0, Python 3.11.2, `npm ci` + `vite build` produced `webui/dist/index.html`, verification green. This is the only run that exercised the frontend build end to end.
- **INST-08 PASS** — `--no-web` skipped Node entirely on both Ubuntu and Rocky.
- **INST-15 PASS** — verification proved a working install: catalog loads, first line matched `^CEF:0|`, loopback listener received 49 datagrams.
- **Refusal is all-or-nothing, verified.** Rocky 9 *without* `--no-web` needs both Python and Node. Python resolves (3.12.13 on offer), Node does not (16.20.2). The script refuses on Node with `pkg_delta=0`, so it does not install the Python it could have satisfied and leave the host half-changed. Exit 3.
- **DEF-005 regression check** — post-fix Debian 12 run: `GUI_LEAK=0` (zero of `tilix`, `libgtk-3-0`, `ubuntu-mono`, `humanity-icon-theme` present). Rocky 9 installed 9 packages total.
### Manual run 2 — 2026-07-21, Suite G remainder COMPLETE (11 further cases)

Executed via containers plus the macOS host. **11/11 PASS**, taking Suite G to **18/20**.

- **INST-01 PASS** — all five flags documented, egress note present.
- **INST-02 PASS** — `--bogus`: exit 1, **stdout 0 bytes**, usage on stderr.
- **INST-03 PASS** — `--dry-run` inert, proven twice: a 7,586-entry stat manifest of `.venv` + `webui/dist` byte-identical, and a 16,576-entry full-tree manifest with zero delta. `git status --porcelain` unchanged.
- **INST-04 PASS** — exit 1 at Preflight on macOS. An 80-line `bash -x` trace contains no sudo, apt-get, dnf, yum, pacman, zypper, npm or venv token. It refuses before touching anything.
- **INST-09 PASS** — `--dev` installs pytest 9.1.1, black 26.5.1, ruff 0.15.22, mypy 2.3.0; `.venv/bin/pytest` runs 238 passed.
- **INST-10 PASS** — the `--dev --no-web` info line is accurate: no node/npm anywhere, no `webui/dist`, yet fastapi 0.139.2 and uvicorn 0.51.0 present exactly as the line claims.
- **INST-14 PASS** — tcpdump across the whole run, correlated to the Verify step boundaries: **49 packets, 100% UDP, 100% `127.0.0.1 > 127.0.0.1`, zero non-loopback**, matching the script's own "delivered 49 events". Non-loopback traffic (PyPI, DNS) occurs only *before* Verify, which also demonstrates install-time egress stopping at that boundary.
- **INST-16 PASS** — of 7,604 entries outside the repo, everything after excluding package-manager paths is toolchain cache (`/root/.npm`, `/root/.cache/pip`, apt logs). **Zero** under `/opt`, `/srv`, `/home`, `/usr/local/bin`, `/etc/systemd`. Zero `replicant-*` files left in `/tmp`, so `cleanup_tmp` works. One verification manifest kept in `manifests/` as the expected SR-5 record.
- **INST-17 PASS** — pre-seeded Python 3.9 venv: exit 4 (`EX_VENV`), `existing .venv uses Python 3.9, below 3.11; remove it and re-run: rm -rf /repo/.venv`, and `Install prerequisites` reported nothing to install, so the host was unchanged.
- **INST-18 PASS** — trap fired naming the step, `set -E` confirmed live. Surfaced NEW-2 (below).
- **INST-19 PASS** — 0 ESC bytes redirected, 0 with `NO_COLOR=1`, 0 with `NO_COLOR=1` on a real pty. Control (pty, no `NO_COLOR`) showed 72 ESC bytes, so the negatives are meaningful rather than vacuous.

**Still BLOCKED (2):** INST-11 and INST-12 (interactive consent and the no-TTY refusal) plus the sudo-scope clause of INST-13. All need an unprivileged Linux login. Note every container run did emit the EUID-0 warning, satisfying that one clause of INST-13.

### Findings from manual run 2

| ID | Sev | Title | Status |
|----|-----|-------|--------|
| DEF-006 | Medium | **`verify_cmd` reported success for a command it never ran.** `err="$(mktemp ...)"` was unchecked. When mktemp failed, `err` was empty, the redirect `2>"$err"` could not open, the command never executed, and the function returned 0 regardless. The installer printed a green `[ok]` for verification it had not performed. Observed live during INST-18: stderr showed `mktemp: Permission denied` while stdout printed `[ok] catalog loads`. Directly undermines INST-15's guarantee. | **FIXED.** Temp allocation moved into a checked `new_tmp_file` helper; `verify_cmd` now fails closed with `could not be verified: no writable temporary file available`. Re-verified in a container with a control: the same call now returns non-zero. |
| DEF-007 | Low | **ERR trap output duplicated.** `set -E` propagates the trap into the command-substitution subshell, so an unguarded `tmp_log="$(mktemp ...)"` fired it twice with different `BASH_COMMAND` values. Six stderr lines where the design specifies three. | **FIXED** by the same guard. |
| OBS-E | Info | **INST-18's suggested induction cannot reach the trap.** "Drop the network during pip" produces `[fail] pip install failed` and exit 4 with no trap output, because every substantive command (`apt-get`, pip, `npm ci`, `npm run build`, each verify) is `\|\| die`-guarded. The trap's reachable surface was essentially the two unguarded `mktemp` assignments, both now guarded. | Case text updated to name a reachable induction. |
| OBS-D | Info | **Concurrent-session interference, worse this time.** During execution another session landed 5 commits and moved `HEAD` from `2d0d460` to `18062e1`. The first container copy was a torn mid-edit snapshot, producing a spurious `test_scenario_cli` failure, and a second confound proved a load-dependent flake in `test_scenario_orchestrator::test_scenario_loopback_udp_delivers` (passed 3/3 in isolation). | Entry criterion already added after run 1; **reinforced**: take the tree with `git archive HEAD` rather than copying a live working directory. |

---

## Round 1 automated UAT verdict (Claude-driven, 2026-07-19): **GO**

Scope: Phases 1, 1.5, 2, 3, against `main` @ `8fe3d31`. **This verdict does not cover Phase 4 or the installer**, neither of which existed when it was issued.

- Suite A **11/11** · Suite B **6/6** · Suite E **5/5** · Quality gate (179 pytest / black / ruff / mypy / frontend build) **all green**.
- **All 5 non-negotiable safety rules verified behaviorally** (fail-closed, synthetic entities, strings-only/no-exec, eps throttle, manifest-per-run), not just by code inspection.
- Open defects at the time: **DEF-001** (trivial doc), **DEF-002** (Low — web eps waveform cap hardcoded), **DEF-003** (trivial dead UI state). None Critical/High; none blocked release. DEF-001 and DEF-002 have since been fixed.
- **Pending human sign-off:** Suite C (Rich menu) + Suite D (web UI) manual walkthrough by DJR, and final Go/No-Go. Still outstanding as of 2026-07-21.

---

## Round 2 UAT verdict (2026-07-21): **CONDITIONAL GO**, pending manual sign-off

Scope: Phase 4 scenario composition (Suite F, TUI-07..09) and the Linux installer (Suite G), against `release/v0.1.0-publish-prep` off `main` @ `0af51f7`.

- **Suite F 16/16 PASS.** Every case driven with real commands and concrete evidence; no case accepted on inspection.
- **Suite G 18/20 PASS.** The Linux-host criterion was met with Docker containers rather than VMs. Two cases remain genuinely blocked (INST-11, INST-12, plus the sudo clause of INST-13): they need an unprivileged Linux login, which a root container cannot provide.
- **TUI-07..09 0/3.** Manual, still needs DJR.
- Quality gate: **238 passed**, black / ruff / mypy clean (32 source files), `shellcheck`, `actionlint`, 8 frontend tests, frontend builds.

**Four defects found and fixed by executing rather than reviewing.** DEF-004 (predicted, confirmed destructive), DEF-005 (unpredicted, and structurally invisible to `--dry-run`), DEF-006 (a verification step that reported green for work it never did), DEF-007 (duplicated trap output). Every one required running the thing on a real system.

**What changed the verdict from blocked to conditional go:** DEF-004 was confirmed on real Linux, not merely predicted, and then fixed and re-verified. DEF-005 was found only because the script was executed rather than reasoned about. Both are now closed with evidence. The installer has gone from never-executed to validated on three distributions.

**Conditions remaining before an unconditional GO:**
- [ ] TUI-07..09 and Round 1's Suites C and D signed by DJR. These are the only cases requiring a human at a terminal.
- [ ] INST-11, INST-12, INST-13, INST-16..19 executed on an unprivileged Linux login. Containers run as root, so the `sudo` elevation path, the interactive consent prompt, and the no-TTY refusal are all still unexercised. The README states this limitation rather than hiding it.
- [ ] DEF-003 (dead `implemented` UI state) and OBS-002 (no frontend test runner) dispositioned. Both Trivial/Info; neither blocks.

**Honest scope statement for release:** the installer is verified on Debian 12, Rocky 9, and Ubuntu 22.04 (as a correct refusal). Alma, RHEL proper, Arch, and openSUSE carry unexercised package mappings and are labelled `[Unverified]` in the README.
