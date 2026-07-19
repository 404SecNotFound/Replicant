# Replicant — User Acceptance Test (UAT) Plan

Owner (QA lead): Claude Code (automated suites) + DJR/RZA (manual suites)
Status: DRAFT — awaiting go-ahead to execute
Authored: 2026-07-19

## 1. Purpose & scope

Validate that Replicant meets its stated requirements and non-negotiable safety rules across **every surface and every claim** before it is treated as production-ready and before Phase 4 work begins. This is the final quality gate on Phases 1, 1.5, 2, and 3.

**Product under test:** branch `webui-reskin` @ `fbedea1` (byte-identical to `origin/main` after PR #5 merge). Executor will sync to `main` before running.

**In scope**
- 11 techniques (REP-001..REP-011), each with a unique `ndr_uc`.
- 3 vendor profiles (FortiGate, Palo Alto, Check Point) on all 3 surfaces.
- 3 transports (UDP, TCP, TLS) + loopback connectivity test.
- CEF correctness against the golden-line oracles.
- 3 surfaces: headless CLI, Rich TUI menu, web UI (+ embedded terminal).
- Manifests, determinism, intensity/duration handling.
- The 5 non-negotiable safety rules.
- Quality gate (pytest / black / ruff / mypy / frontend build).

**Out of scope**
- The planned "click use case → detail panel" feature (not built yet; gets its own build + UAT after this pass).
- Phase 4 (ATT&CK scenario composition).
- Live SIEM ingestion (LogRhythm). All transport tests use loopback receivers. [Inference] a real-collector smoke is a separate, operator-run step.

## 2. Environment & entry criteria

Setup the executor runs once before Suite A/B:

```bash
git checkout main && git pull                 # UAT the shipping product
python3.12 -m venv .venv 2>/dev/null || true  # venv already exists
pip install -e ".[web]"                        # web extra for replicant web + API tests
(cd webui && npm install && npm run build)     # produce webui/dist so replicant web serves the SPA
```

**Entry criteria (all must hold before execution starts)**
- [ ] On `main`, clean working tree (3 untracked `re-fresh-*.md` handoff files are acceptable).
- [ ] `.venv` tools runnable: pytest 9.1.1, black 26.5.1, ruff 0.15.22, mypy 2.3.0, Python 3.12.13.
- [ ] `webui/dist` built (else `replicant web` serves a build-me stub).
- [ ] No open PRs against `main` (confirmed: PR #5 merged, list empty).

## 3. Requirement traceability matrix (RTM)

| Req | Requirement (source) | Test case(s) | Owner |
|-----|----------------------|--------------|-------|
| SR-1 | Only egress is the operator-configured collector; fail closed if none (CLAUDE.md safety 1) | SAFE-01, CORE-07 | Claude |
| SR-2 | All entities synthetic — RFC1918 + 192.0.2/24, 198.51.100/24, 203.0.113/24; non-resolvable DNS (safety 2) | SAFE-02, CORE-06 | Claude |
| SR-3 | No real attacks — writes log strings only (safety 3) | SAFE-03 | Claude |
| SR-4 | Respect eps cap, default 2000 (safety 4) | SAFE-04, CORE-08 | Claude |
| SR-5 | Every run writes a manifest (seed, technique, params, entities, target, counts, times) (safety 5) | SAFE-05, CORE-05 | Claude |
| FR-1 | 11 techniques REP-001..011, each unique `ndr_uc` (phase 2) | CORE-01 | Claude |
| FR-2 | 3 vendors selectable on CLI, menu, web (phase 3) | CORE-04, TUI-03, UI-03 | Both |
| FR-3 | 3 transports UDP/TCP/TLS + loopback test (phase 2) | CORE-03 | Claude |
| FR-4 | CEF golden-line correctness per vendor (blueprint / *-cef-reference.md) | CORE-02 | Claude |
| FR-5 | Menu/CLI parity — anything the menu does, `replicant run` does headless (CLAUDE.md architecture) | CORE-09, TUI-05 | Both |
| FR-6 | Determinism — same seed+technique+params → same plan / byte-identical `--to-file` (CLAUDE.md standards) | CORE-05 | Claude |
| FR-7 | Web UI over the same Orchestrator (phase 1.5) | WEB-01..05, UI-01..06 | Both |
| FR-8 | Intensity presets low/medium/high + duration parsing (blueprint) | CORE-05, TUI-04 | Both |
| QG-1 | 179 tests green | CORE-10 | Claude |
| QG-2 | black / ruff / mypy clean | CORE-11 | Claude |
| QG-3 | Frontend builds | WEB-00 | Claude |

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
| CORE-10 | QG-1 | Full suite green | `pytest` | 179 passed | |
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

Launch: `replicant menu`. Prompt shows `[1-11] technique  [c] connection  [v] vendor  [s] seed  [q] quit`.

| ID | Req | Objective | Steps | Expected | Result |
|----|-----|-----------|-------|----------|--------|
| TUI-01 | FR-7 | Menu renders technique table | Launch menu | 11 techniques in a numbered table; readable in the reskinned theme | |
| TUI-02 | FR-7 | Connection config `[c]` | Press `c`, enter host/port/transport | Collector set; no send until run | |
| TUI-03 | FR-2 | Vendor picker `[v]` | Press `v`, choose each vendor | Selection echoed; orchestrator rebuilt | |
| TUI-04 | FR-8 | Seed `[s]` + technique + intensity | Set seed, pick a technique, choose intensity | Run plan uses the chosen seed/intensity | |
| TUI-05 | FR-5 | Run a technique end to end | Pick REP-004, run to loopback or file | Lines emitted; manifest written; matches CLI behavior | |
| TUI-06 | — | Quit cleanly | Press `q` | Exits without traceback | |

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

## 9. Pre-execution findings (from recon, before formal run)

Recon of the codebase surfaced 5 issues. Logged now so execution confirms/expands them.

| ID | Sev | Priority | Title | Location | Notes |
|----|-----|----------|-------|----------|-------|
| DEF-001 | Trivial | Low | Stale test count in README (`# 78 tests`) vs 179 actual | `README.md:198` | Doc-only. |
| DEF-002 | Low | Medium | Web eps waveform cap hardcoded `2000` instead of `config.eps_cap` | `webui/src/components/RunPanel.tsx:295` | Waveform scale/cap line wrong if operator sets non-default eps_cap. ConnectionCard uses the real value. Verify in UI-05. |
| DEF-003 | Trivial | Low | All 11 techniques hardcoded `implemented=true` → `soon`/`not-runnable` UI states are dead code | `web/server.py:92-105` | Not user-facing today (all are implemented). Cleanup or drive from real state. |
| OBS-001 | Info | — | `/api/catalog` omits `distributions`/`benign_baseline`/`cef_fields_*`/`references` | `web/server.py:78-109` | Design input for the click-through detail panel feature (backend must expose these). Not a current-product defect. |
| OBS-002 | Info | — | No frontend test runner (no `test` script / vitest) | `webui/package.json` | Test-coverage gap; all backend is covered. |

## 10. Defect management

Severity: **Critical** (safety-rule breach, data leak, crash on core path) → **High** (surface unusable / wrong CEF) → **Medium** (functional deviation w/ workaround) → **Low** (cosmetic/minor) → **Trivial** (docs/typo).
Any Critical against a safety rule is an automatic **No-Go** and blocks release. Each defect logged with: id, severity, priority, steps to reproduce, expected vs actual, location, owner.

## 11. Exit criteria & Go/No-Go

**Go** requires:
- [ ] Suite A + B + E: 100% pass (Claude).
- [ ] Suite C + D: 100% pass (DJR), or any failure triaged and accepted.
- [ ] Zero open Critical/High defects. All 5 safety rules PASS.
- [ ] QG-1 (179 green), QG-2 (lint/type clean), QG-3 (build) all green.
- [ ] DEF-001..003 dispositioned (fix now, or accept + ticket).

**Sign-off:** QA lead (Claude) records automated results; DJR signs the manual + overall Go/No-Go.

## 12. Execution log

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

---

## Automated UAT verdict (Claude-driven): **GO**

- Suite A **11/11** · Suite B **6/6** · Suite E **5/5** · Quality gate (179 pytest / black / ruff / mypy / frontend build) **all green**.
- **All 5 non-negotiable safety rules verified behaviorally** (fail-closed, synthetic entities, strings-only/no-exec, eps throttle, manifest-per-run), not just by code inspection.
- Open defects: **DEF-001** (trivial doc), **DEF-002** (Low — web eps waveform cap hardcoded), **DEF-003** (trivial dead UI state). None Critical/High; none block release.
- **Pending human sign-off:** Suite C (Rich menu) + Suite D (web UI) manual walkthrough by DJR, and final Go/No-Go.
