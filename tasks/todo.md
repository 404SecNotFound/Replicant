# Safety-hardening before public flip (in progress, 2026-07-22, branch: fix/safety-hardening)

Source: accurate code review pasted 2026-07-22. Scope: safety-truth blockers only;
packaging / numeric-ranges / bundle / Apache-headers / coverage deferred to v0.1.1.
Every change is test-first (TDD). Branch off `main` (b9d4bcc), clean repo.

- [x] 1. **EPS cap cannot be silently disabled.** DONE. `Field(gt=0)` on `Settings.eps_cap`,
      `RunRequest.rate_override`, `ScenarioRunRequest.rate_override`. 12 tests in
      tests/test_safety_constraints.py. Full suite 261 green.
- [x] 2. **Universal event ceiling holds for every builder.** DONE (guard, no prod change).
      Parametrized test plans all 11 techniques at high/86400s against max_events=10; all
      respect it, so the [Unverified] REP-007/008/011 escape worry is verified false.
- [x] 3. **Manifests are collision-resistant.** DONE. `_write_unique` adds a uuid token +
      exclusive create in manifest.py; both write_manifest and write_scenario_manifest.
      2 tests; name prefix preserved so existing assertion holds.
- [x] 4. **Manifest + syslog identity follow the active vendor, not FortiGate.** DONE.
      `VendorProfile.hostname`/`.accepted_as` (abstract; PAN-OS/Check Point [Unverified]);
      CheckPointDevice gained `hostname=CP-LAB-GW-01`; `Settings.hostname`/`accepted_as`
      now Optional None; shared `build_profile`/`effective_identity`; orchestrator props +
      web echo. 8 tests. Full suite + mypy green.
- [x] 5. **Web runs cannot multiply collector load; handles do not leak.** DONE.
      `RunInProgressError` + double-checked single-active guard; `_evict_terminal` bounds
      the map at MAX_TERMINAL_RETAINED (never a live one); server maps to HTTP 409. 6 run-manager
      tests + 1 server 409 test.
- [x] 7. **Loopback-only bind is enforced.** DONE. `_require_loopback` rejects any non-loopback
      host (localhost/127.x/::1 allowed) before bind; called in `serve`; IPv6 family handled.
      10 tests. The "(loopback only)" line is now truthful.
- [x] 6. **Frontend stops hiding an active emitter.** DONE. Extracted a pure
      `pollRunUntilTerminal` (webui/src/lib/runLifecycle.ts) so the decision is unit-testable;
      RunPanel's SSE `onerror` now polls `/api/runs/{id}` and keeps the run + Stop active until
      the backend reports terminal. 5 vitest tests; tsc + build clean.

Out of scope (v0.1.1 backlog): wheel/asset packaging + clean-install smoke; port 1..65535 /
facility 0..23 constraints + 4xx malformed-body tests; bundle lazy-load (JS chunk 578kB, over
Vite's 500kB warn); Apache headers on the 22 pre-existing frontend files + font OFL NOTICE;
broader frontend coverage; plan-twice cost; stale egg-info.

## Review

All seven safety-truth items landed test-first (RED observed, then GREEN). Final gate:
297 Python tests (was 249; +48), 14 frontend tests (was 9; +5), ruff/black/mypy clean,
frontend tsc + production build clean. New files carry the Apache header. CHANGELOG has a
"Security hardening" subsection under 0.1.0. Two findings were verified NOT real: every
technique builder already respects `max_events` (item 2), so the [Unverified] REP-007/008/011
escape worry was false. Vendor log-source names for PAN-OS/Check Point are labelled
[Unverified], consistent with those profiles. Backlog items above are genuine but do not affect
the correctness of what ships; recorded for v0.1.1.

---

# Close outstanding items before lab test (complete, 2026-07-21, branch: chore/close-outstanding-items)

Everything that could be closed without DJR at a terminal or an unprivileged Linux login.

- [x] 1. **CI, which the repo had none of.** Four jobs: Python 3.11/3.12, frontend Node 18/20, shell lint, and the installer run inside real `debian:12`, `rockylinux:9`, `ubuntu:22.04` containers with asserted outcomes. The installer job makes DEF-004 and DEF-005 permanent regression guards. actionlint clean.
- [x] 2. **Suite G 7/20 -> 18/20.** All 11 runnable cases pass. Only INST-11, INST-12 and the sudo clause of INST-13 remain, and those genuinely need an unprivileged Linux login.
- [x] 3. **DEF-006 (Medium), found by running INST-18.** `verify_cmd` reported success for commands it never executed when its own `mktemp` failed. Verification that lies in the direction of reassurance, in a script whose job is proving an install works. Fixed, with a control both before and after.
- [x] 4. **DEF-007 (Low).** Duplicated ERR trap output from `set -E` propagating into a command-substitution subshell. Fixed by the same guard.
- [x] 5. **DEF-003.** `/api/catalog` now derives `implemented` from the engine registry instead of a hardcoded id set. +3 tests.
- [x] 6. **OBS-C, widened.** All nine CLI error paths moved to stderr, not just the one the observation named. Test updated: it had asserted stdout, encoding the bug as the requirement.
- [x] 7. **OBS-A.** The eps cap documented as a fixed-window average at the limiter, in the README safety table, and in the CHANGELOG.
- [x] 8. **OBS-002.** vitest + jsdom + Testing Library, 8 tests. Found and fixed a real bug on first run: `vendorLabel` resolved `"constructor"` and `"toString"` through the prototype chain, so the `??` fallback never fired.
- [x] 9. **Launch write-up** (article + LinkedIn variant), drafted in the session scratchpad rather than the repo, since adding launch copy to a repo about to go public is DJR's call.

Gate: 238 Python tests, 8 frontend tests, black, ruff, mypy (32 files), shellcheck, bash -n, actionlint, frontend build. All green.

**Open, and not closeable from here:**
- Round 1 Suites C and D, plus TUI-07..09. Need DJR at a terminal.
- INST-11, INST-12, INST-13 sudo clause. Need an unprivileged Linux login.
- **The `v0.1.0` tag predates all of the above.** It points at `2d0d460`. Since the release is an unpublished draft and the repo is still private, the clean move is to re-cut the tag after lab testing rather than ship a known Medium defect in the first public release. Not done unilaterally: moving a tag is the kind of thing that should not be a surprise.

---

# Publish prep v0.1.0 (complete, 2026-07-21, branch: release/v0.1.0-publish-prep, MERGED as PR #9)

Goal: make Replicant fit to publish as a public GitHub repo with a tagged release.

- [x] 1. **Execute UAT Suite F** (scenario composition). **16/16 PASS**, every case driven with real commands. Full evidence in `tasks/uat-plan.md` §14, automated run 4.
- [x] 2. **Validate the installer on real Linux.** Docker containers rather than VMs: `ubuntu:22.04`, `debian:12`, `rockylinux:9`. This is the first time `scripts/install.sh` has ever executed on Linux.
- [x] 3. **DEF-004 confirmed, then fixed.** Reproduced the destructive failure on Ubuntu 22.04 (installed packages, then died exit 3). Replaced the assumed package mapping with a resolver that queries the package manager *before* consenting to sudo, and refuses with per-distro guidance when nothing on offer qualifies. Re-verified: Ubuntu 22.04 exit 3 / 0 packages installed; Debian 12 full success incl. frontend build; Rocky 9 success on Python 3.12.13.
- [x] 4. **DEF-005 found and fixed** (nobody predicted this one). The apt path lacked `--no-install-recommends` and pulled a GUI desktop stack (tilix, GTK, icon themes) onto a headless server. Added `--no-install-recommends` / `--setopt=install_weak_deps=False`. Regression check: `GUI_LEAK=0`.
- [x] 5. **Front-page accuracy.** README headline, tagline, vendor badge and the positioning paragraph all claimed FortiGate-only; the product has shipped three vendors since Phase 3. Corrected, plus an honest supported-distribution table that labels what is verified and what is not.
- [x] 6. **Quality gate green:** 235 tests, black, ruff, mypy (32 files), shellcheck, `bash -n`, frontend build.
- [ ] 7. Stale `pyproject.toml` description (still says "FortiGate CEF firewall telemetry generator").
- [ ] 8. Release notes / tag for v0.1.0.
- [ ] 9. Flip repository visibility to public. **Requires DJR.** Not something to do without an explicit go.

Deliberately NOT done: DEF-003 (dead `implemented` UI state, Trivial) and OBS-002 (no frontend test runner, Info). Neither blocks a v0.1.0 publish; both are recorded in the UAT plan for disposition.

---

# UAT plan revision 2 - Phase 4 scenarios + Linux installer (complete, 2026-07-21)

`tasks/uat-plan.md` was authored 2026-07-19 against Phases 1/1.5/2/3 and carries a signed **GO**. It predates Phase 4 (PR #7) and the Linux installer (PR #8), and several of its stated facts have gone stale. Revising in place, versioned, so the Round 1 record stays intact and attributable.

- [x] A. Front matter + section 1 scope. Add a revision line; retarget **Product under test** from `webui-reskin@fbedea1` to `main@0af51f7`; move Phase 4 out of "Out of scope"; drop the "detail panel not built yet" line (shipped in PR #6); add scenario composition + installer to "In scope"; add the two genuine new exclusions (web UI scenario support, deferred; macOS/Windows installer, a stated non-goal).
- [x] B. Section 2 environment + entry criteria. Refresh the setup block; correct the entry criteria (working tree is clean now, the 3 untracked `re-fresh-*.md` files are gone; PRs #7/#8 merged); add a Linux-host criterion gating Suite G.
- [x] C. Section 3 RTM. Correct QG-1 from 179 to 235 tests. Add FR-9..FR-12 (scenario composition, paired advisory+manifest, dual-surface reachability, advisory-only boundary) and IN-1..IN-5 (installer fail-closed reporting, sudo scope + consent, flag behaviour, distro version reachability, verification integrity).
- [x] D. Suite C additions: TUI-07..09 covering the `[a]` scenario picker, the advisory-before-emit ordering, and the no-collector guidance path.
- [x] E. New Suite F - scenario composition, automated, **CHAIN-01..16** (planned 15; CHAIN-16 added to assert the web UI scenario surface stays absent, so a later partial implementation is caught). Prefix is `CHAIN-` deliberately: `SCEN-001` is already a catalog scenario id, so a `SCEN-` test prefix would collide.
- [x] F. New Suite G - Linux installer, **INST-00..19** (planned 01..19; INST-00 added for `shellcheck`, which is automatable today and became QG-4). Only INST-00/03/04 are runnable without Linux; the rest are BLOCKED pending a VM and are marked as such rather than left to look executable.
- [x] G. Renumber sections 9-12 to 11-14 after the two inserted suites.
- [x] H. Pre-execution findings. Re-verified all five: **DEF-001 FIXED** (README now says 235), **DEF-002 FIXED** (RunPanel takes an `epsCap` prop), **DEF-003 STILL OPEN** (`server.py:92-105` hardcodes a set of all 11 ids, so `implemented` is unconditionally true), **OBS-001 RESOLVED** by PR #6, **OBS-002 STILL OPEN** (no vitest, no `test` script). Add DEF-004 (installer distro/python gap, High), OBS-005 (menu scenario path is a subset of the CLI - parity rule satisfied, not a defect), OBS-006 (web UI has zero scenario surface).
- [x] I. Exit criteria + verdict. Split Round 1 (executed, GO) from Round 2 (pending); retitle the existing verdict as Round 1 so it is not read as covering the new surfaces; correct 179 to 235.

Constraint: this is a plan revision only. No product code changes in this pass. DEF-003, DEF-004, and OBS-002 are recorded for disposition, not fixed here.

## UAT r2 Review (complete)

`tasks/uat-plan.md` grew 206 -> 319 lines. Sections renumbered to 1-14, sequential. 39 new test cases: Suite F CHAIN-01..16, Suite G INST-00..19, Suite C TUI-07..09. RTM extended from 16 requirements to 26 (added FR-9..12, IN-1..5, QG-4).

Verified rather than assumed:
- **Traceability closes both ways.** Scripted cross-check of the finished file: 26 requirements defined, 26 cited, zero cited-but-undefined, zero defined-but-uncovered. The new CHAIN cases were also back-referenced into the existing SR-1/2/4/5 and FR-2/6/8 rows, otherwise tracing "what covers safety rule 1?" would have silently missed CHAIN-11 and INST-14.
- **All five Round 1 findings re-checked against `0af51f7`, not carried forward on trust.** Three had already closed (DEF-001, DEF-002, OBS-001 via PR #6); two are genuinely still open (DEF-003, OBS-002). A plan that lists fixed defects as open is worse than no plan.
- **Baseline re-run:** 235 passed, exit 0.
- The three surviving `179` references are deliberate. They sit inside the Round 1 execution log, exit criteria, and verdict, where 179 was the true count at the time.

Two judgement calls worth recording:
- **Round 1's GO was retitled, not overwritten.** It now reads "Round 1 automated UAT verdict (2026-07-19)" and states explicitly that it does not cover Phase 4 or the installer. A signed verdict silently widened to cover code that did not exist when it was signed would be the worst possible outcome of this edit.
- **Suite G is marked BLOCKED, not merely untested.** 17 of its 20 cases cannot run without a Linux VM. The exit criteria say so directly, so that "Round 2 authored" is never mistaken for "Round 2 passed". DEF-004 is logged High, which under the existing severity rule blocks Go until it is fixed or the supported-distro claim is narrowed.

Not done here, by design: no product code touched, so DEF-003, DEF-004 and OBS-002 remain open. Suite F is fully automatable today and is the obvious next execution step; Suite G waits on hardware.

---

# Phase 3 - multi-vendor (complete, branch: phase-3-paloalto off phase-2c-polish)

- [x] Palo Alto (PAN-OS) vendor profile — done. `docs/paloalto-cef-reference.md` oracle (7 golden lines, all [Unverified]); `replicant/profiles/paloalto.py` renders the neutral (log_type, subtype) categories -> PAN-OS CEF (TRAFFIC / THREAT / GLOBALPROTECT / SYSTEM), non-reversed integer severity.
- [x] Check Point (Log Exporter) vendor profile — done. `docs/checkpoint-cef-reference.md` oracle (7 golden lines, all [Unverified], grounded in Check Point's R80.20 `CefFieldsMapping.xml`, SK122323, and Sekoia samples); `replicant/profiles/checkpoint.py` renders the same categories -> Check Point CEF. Faithful specifics: string CEF severity (Unknown/Low/Medium/High/Very-High, so `CefHeader.severity` widened to `int | str`), `rt` in epoch milliseconds, numeric `proto`, capitalized `act`, blade-driven Device Product (VPN-1 & FireWall-1 / SmartDefense / Mobile Access / Check Point), `cp_severity` mirror, `deviceDirection`.
- [x] Menu + web vendor pickers — done. Rich menu `[v]` picker (`_pick_vendor`); web `/api/config` exposes vendor + vendors and a ConnectionCard `<Select>` sets the per-run/per-test vendor. Canonical id list centralized in `settings.VENDORS` (`fortigate` | `paloalto` | `checkpoint`).
- [ ] Optional cleanup: rename `technique.fortigate` binding to a neutral name (values already neutral; not blocking; deferred).

Design note: adding a vendor = implement `VendorProfile` + a reference file with golden lines (blueprint s10). The `(log_type, subtype)` values the engine emits are neutral log categories; each profile maps them to its own log family and field layout. All three vendors' golden lines reuse the same synthetic entities for direct comparison.

## Phase 3 Review (complete)

Multi-vendor done across three vendors: FortiGate + Palo Alto (PAN-OS) + Check Point (Log Exporter). Vendor selectable via `--vendor {fortigate,paloalto,checkpoint}` (run + connect), the Rich menu `[v]` picker, and the web UI selector; all resolve to `settings.vendor` -> `Orchestrator._build_profile`. One technique catalog and one scenario engine drive every vendor; only serialization differs.

Gate: **179 Python tests pass**, black/ruff/mypy clean (30 source files), frontend `tsc -b` + vite build clean. Every new source file carries the Apache header. All three vendors' golden lines reproduce byte-for-byte from their reference docs.

Check Point specifics (all [Unverified] against a live build; grounded in Check Point's R80.20 `CefFieldsMapping.xml`, SK122323, and Sekoia Log Exporter samples): string severity (widened `CefHeader.severity` to `int | str`, non-breaking since the serializer already stringified it), ms epoch `rt`, numeric `proto`, blade-driven Device Product, `Check Point` literal Device Version, and the `cp_severity` / `auth_status` / `administrator` / `operation` keys.

Verified end-to-end: `replicant run REP-001 --vendor checkpoint` emits `CEF:0|Check Point|VPN-1 & FireWall-1|...`; web `POST /api/runs` with `vendor=checkpoint` writes Check Point CEF; the connect-test line reflects the selected vendor. The web selector renders and binds the header to vendor state (the Radix dropdown not opening under browser automation is a harness limitation, not a defect; it is the same `Select` as the working Transport/Intensity controls).

Safety re-checked: only egress is the configured collector; all entities synthetic (RFC1918 + documentation ranges, incl. gateway origin 192.0.2.1); no real attacks executed; eps cap and manifest intact.

---

# Phase 2 - full catalog + hardening (in progress, branch: phase-2b)

Session goal: finish the last four techniques (REP-007/009/008/011), then TLS transport + docs. Order: 007 -> 009 -> 008 -> 011 (011 last so the two "unimplemented" guard tests flip exactly once). One commit per technique off main; user merges via PR.

Remaining techniques (each: TDD engine planner + tests + mark implemented + CLI verify):
- [x] REP-003 Horizontal sweep (one port, many hosts) — done. Added synthetic sweep pool (10.50.0.0/16) to the entity model; planner holds src+dpt, varies dst, mostly deny. 78 tests green.
- [x] REP-005 Outbound exfil volume anomaly (large out bytes, off-hours) — done. Off-hours placement helper (00:00-06:00 UTC+04:00); large out with >20:1 out/in ratio to few adversary destinations. 81 tests green.
- [x] REP-006 Destination fan-out burst — done. One source to many unique destinations (mixed internal + external synthetic pools) in a 5-minute window, mostly accept, small bytes. 85 tests green.
- [x] REP-007 Brute force / password spray (event:vpn ssl-login-fail) — done. spray = one external src vs many synthetic victims (2 attempts each, reason varies); brute = one victim, many attempts, one success (tunnel-up) at the end. Added deterministic synthetic-username generator. 93 tests green.
- [x] REP-008 Newly observed external destination (warm-up baseline, manifest note) — done. One host emits a stable known-destination baseline (5 benign peers over N days), then first-seen adversary destinations; returns a warm-up note that flows into the CLI summary and RunManifest.warmup_note. 103 tests green.
- [x] REP-009 IDS/IPS event-rate spike (utm:ips) — done. Burst of signature resets against one held target; varied src + attack (label-only signature pool) + escalating cnt; header severity high/critical (CEF 6/7). 98 tests green.
- [x] REP-010 Denied outbound connection burst — done. One source, a burst of denied connections to a few synthetic external destinations in a 60s window, front-loaded (sharp spike then decay). 88 tests green.
- [x] REP-011 VPN geovelocity anomaly (event:vpn, synthetic country tags) — done. One held user, N successful tunnel-up logins from distinct synthetic GeoIP country blocks inside a short window (impossible travel). Added conditional FTNTFGTsrccountry to the vpn template (golden lines unaffected); repointed the two "unimplemented" guard tests to the engine/error contract. All 11 techniques implemented.

Other Phase 2 items:
- [x] TLS transport — done. Added `tls` to CollectorProfile.transport (ssl-wrapped TCP), plus tls_verify / tls_cafile fields and `--tls-cafile` / `--tls-insecure` CLI flags. Loopback TLS test (ephemeral self-signed cert via openssl) + fail-closed test; verified end-to-end through `replicant connect --transport tls`. 111 tests green.
- [ ] off-hours/business-hours weighting (deferred; REP-005 already off-hours)
- [x] saved-profile menu polish — done (branch phase-2c-polish). Rich menu now offers a saved-collector picker (`_pick_saved_profile`, sorted, or [n]ew) before the manual wizard, and the wizard supports tls with verify/CA-bundle prompts. Unit-tested the selection logic; verified the picker interactively via `replicant menu`.
- [x] web UI TLS options — done (branch phase-2c-polish). Added tls_verify/tls_cafile to the web CollectorBody, wired both handlers, and added a transport=tls path with a Verify-cert switch + CA-file input in the React ConnectionCard. Backend test asserts the options reach the CollectorProfile; verified end-to-end in the in-app browser (TLS test log received by a loopback collector). 114 tests green.

## Phase 2 Review (complete)

All eleven techniques (REP-001..011) implemented; TLS transport added; docs updated. Gate: **111 tests pass**, black/ruff/mypy clean (28 source files), every source file carries the Apache header. Seven CEF golden lines still reproduce byte-for-byte (the conditional FTNTFGTsrccountry addition does not touch them).

This session (branch phase-2b, off main at 86308a7): 5 commits.
- `cd3f5aa` REP-007 brute/spray — event:vpn ssl-login-fail. spray holds src, varies duser+reason across a synthetic-username pool; brute holds src+duser, many attempts + one tunnel-up success. New `synthetic_usernames` generator (deterministic, seed-independent).
- `8d96bcf` REP-009 IPS spike — utm:ips reset. Holds dst, varies src + attack/attackid (label-only signature pool) + escalating cnt; header severity 6/7.
- `5706a17` REP-008 newly-observed dst — traffic:forward accept with a compressed known-destination baseline then first-seen adversary destinations; warm-up note flows to the CLI summary and RunManifest.warmup_note.
- `daf8f1a` REP-011 geovelocity — event:vpn tunnel-up. Holds duser, N logins from distinct synthetic GeoIP country blocks in a short window; conditional FTNTFGTsrccountry added to the vpn template; the two "unimplemented" guard tests repointed to the engine/error contract (synthetic unregistered technique -> NotImplementedError; web start -> 400).
- `ada646d` TLS transport — ssl-wrapped TCP behind the same SyslogEmitter; verify/cafile options; CLI flags; loopback + fail-closed tests.

Verification (drove the real CLI, not just tests):
- REP-007 low: 100 lines (50 users x 2), one held src, reason varies; high: 401 lines (400 fail + 1 tunnel-up success at sig 39947), src+duser held.
- REP-009 low: 20 lines, one held dst, 19 distinct src, 8 distinct signatures, cnt escalates 1->5, `=` escaped in request.
- REP-008 medium: 70 baseline events (5 stable benign dst) + 3 first-seen adversary dst; warm-up note in the manifest JSON.
- REP-011 high: 4 logins, one held user, 4 distinct src across 4 country tags, srccountry emitted after remip; golden test unaffected.
- TLS: `connect --transport tls --tls-insecure --test` delivered the framed benign line to an in-process loopback TLS collector.

Deferred (not in scope this session): business-hours weighting beyond REP-005, saved-profile menu polish, web UI TLS options (backend defaults verify=on). Signature IDs still flagged [Unverified] in code/catalog: DNS 54803, VPN success/tunnel-up 39947. Confirm on a live FortiOS build before customer use.

Safety re-checked: only egress is the configured collector; all entities synthetic (RFC1918 + documentation ranges, synthetic usernames, label-only attack/signature names, synthetic country tags); no real attacks executed; eps cap and manifest intact.

---

# Phase 1.5 - Web UI + embedded terminal (in progress)

User chose: React + Vite + Tailwind + shadcn frontend, and a FULL embedded TTY terminal (xterm.js + PTY/websocket bridge running the real Rich menu). Web server binds 127.0.0.1 on a random port. Both interfaces call the same Orchestrator.

- [ ] W1. Orchestrator: add optional `on_event(line, event)` callback (backward-compatible) so the web layer streams serialized lines without re-implementing run logic.
- [ ] W2. `replicant/web/` FastAPI backend: catalog/config/connect-test/run(SSE stream)/stop/manifest endpoints + `/ws/terminal` PTY bridge. Localhost bind + per-session token. `[web]` optional deps.
- [ ] W3. `replicant/web/pty_bridge.py`: spawn `replicant menu` in a PTY, async read/write over websocket, window resize.
- [ ] W4. `replicant web` CLI verb: bind 127.0.0.1:0, print URL with token, open browser, serve built frontend.
- [ ] W5. `webui/` Vite React-TS + Tailwind + shadcn-style components: connection card, catalog table, run panel with live event stream + Stop, manifest view, Terminal tab (xterm.js) with a Dashboard/Terminal switch.
- [ ] W6. Backend tests (FastAPI TestClient): catalog, connect-test loopback, run stream, stop, token guard. on_event unit test.
- [x] W7. Build frontend, wire server to serve dist, verify end-to-end in the in-app browser (run a technique + open the terminal). Update README + report.

Safety: localhost-only bind, per-session token on API + WS, Host-header check (DNS-rebinding guard). Web runs use the same fail-closed Orchestrator, eps cap, and manifest.

## Phase 1.5 Review (complete)

All W1-W7 done. Gate: **75 Python tests pass** (64 core + 11 web API), black/ruff/mypy clean (28 source files), frontend typechecks and builds. Verified in the in-app browser:
- Dashboard renders (dark shadcn UI): collector card, 11-technique catalog with ready/Phase-2 badges, run panel.
- Ran REP-001 from the web: live CEF lines streamed over SSE, progress bar filled (243 events), manifest summary shown.
- Connect test delivered a benign line to a loopback receiver (verified by API test + urllib).
- Embedded terminal: banner renders in the browser; full menu navigation (answer connect prompt -> main menu -> select technique -> params/intensity prompt) verified authoritatively via a real websocket client against `/ws/terminal`.

Two real bugs found and fixed during verification:
1. PTY Enter key: xterm sends CR; the canonical line discipline needs LF. Fixed by enabling ICRNL on the child TTY and normalizing CR->LF server-side in the input pump.
2. uvicorn[standard] defaults to uvloop; forced `loop="asyncio"` so `loop.add_reader` on the PTY master fd fires reliably.

Note: the in-app browser automation cannot inject a trusted Enter keystroke into xterm (xterm ignores untrusted synthetic key events), so terminal navigation was proven with a websocket protocol client rather than screenshot keystrokes. A real user's Enter works (it produces the same CR the client sent).

Deviations from the original minimal-deps rule (user-approved): added FastAPI + uvicorn (Python `[web]` extra) and a Node/React/Vite/Tailwind frontend toolchain in `webui/`. Core CLI/menu remain dependency-light; web deps are optional.

---

# Replicant Phase 1 - Implementation Plan

Source of truth: `docs/blueprint.md`, `docs/fortigate-cef-reference.md`, `data/technique-catalog.yaml`, `CLAUDE.md`.
Build order follows the kickoff prompt: scaffold -> models -> CEF serializer (+golden) -> FortiGate profile -> scenario engine -> transport -> orchestrator -> CLI -> menu.

## Tasks

- [ ] 1. Scaffold: `pyproject.toml` (Apache-2.0, py3.11+), package layout, `.gitignore`, `README.md`, Apache header on every source file. LICENSE/NOTICE already present and correct.
- [ ] 2. `core/models.py`: Pydantic v2 models (CefHeader, Technique, CollectorProfile, Entity, EventRecord, RunRequest, RunManifest). Catalog loader + validation.
- [ ] 3. `cef/serializer.py`: header + extension escaping (blueprint s9). No vendor knowledge.
  - [ ] tests: escaping unit tests from ArcSight examples (pipe/backslash/equals split header vs extension).
- [ ] 4. `profiles/base.py` (VendorProfile interface, CefHeader) + `profiles/fortigate.py` (7 record templates, severity map, logid->sigid).
  - [ ] tests: `test_cef_serializer.py` golden - reproduce the 7 reference CEF payloads byte for byte via profile+serializer.
  - [ ] tests: `test_fortigate_profile.py` - severity mapping, sig-id derivation, field names.
- [ ] 5. `entities/model.py`: seeded synthetic pools (internal hosts RFC1918, adversary/benign external docs ranges, resolver, ports, users, interfaces, device identity).
- [ ] 6. `scenario/distributions.py` + `scenario/engine.py`: deterministic, no I/O. Plans for REP-001, REP-002, REP-004.
  - [ ] tests: `test_scenario_engine.py` - determinism (same seed == same plan), distribution bounds, cardinality, held/varied fields.
- [ ] 7. `transport/syslog.py` (UDP/TCP + send_test, RFC3164 framing) + `transport/filesink.py`.
  - [ ] tests: `test_transport_loopback.py` - in-process UDP + TCP receiver, lines arrive intact, no external collector.
- [ ] 8. `core/orchestrator.py` + `audit/manifest.py` + `config/settings.py`: request->plan->emit, manifest (seed/technique/params/target/counts/times UTC+04:00), kill switch, fail-closed.
- [ ] 9. `cli/app.py` (list, connect, run) + `cli/menu.py` (Rich flow). Menu calls Orchestrator only.
- [ ] 10. `tests/test_catalog_valid.py`: every entry parses, ndr_uc unique.
- [ ] 11. Quality gate: black, ruff, mypy clean; pytest green. Run the 3 techniques to file; confirm acceptance criteria 1-10.
- [ ] 12. README + hand-back report (built / how to run / test+lint status / [Unverified] sig IDs / deviations).

## Key correctness decisions (locked from the reference)

- Golden test compares the **CEF payload** (from `CEF:0|`), since the syslog prefix is transport-added (blueprint s9). Syslog framing tested separately.
- Severity = reversed FortiOS level: `CEF = 8 - numeric` (notice=3, warning=4, alert=7). Table in reference s2.4.
- Signature ID = last 5 chars of full logid; full logid kept as `FTNTFGTlogid`.
- Per-template extension **field order is exact** and differs (accept has app/trandisp/duration/pkts; deny has policytype, no app). Templates encode the golden order.
- Device Product is `Fortigate` (lower-case g). Device identity constants match golden lines (serial FGVMSYNTH0000001, vd root, host FGT-LAB-01, v7.4.3, port1/port2).
- `rt` in the catalog is realized as `FTNTFGTeventtime` (epoch) + syslog timestamp; the FortiGate templates do not emit a separate `rt=` key. [Deviation, documented]
- Determinism: eventtime = fixed anchor epoch + deterministic plan offset, so same seed => byte-identical `--to-file` output (acceptance #8). Anchor is configurable.
- CLI uses stdlib argparse (blueprint allows, cuts a dependency).

## [Unverified] signature IDs carried from catalog/reference (flagged, not blocking)
- DNS dns-query `54803` (dns-response 54802 is the confirmed anchor).
- SSL-VPN success/tunnel-up `39947` (login-fail 39426 confirmed).
- IPsec/geovelocity IDs (Phase 2).

## Review (Phase 1 complete)

All 12 tasks done. Quality gate: **64 tests pass**, black/ruff/mypy clean, Apache header on every source file.

Acceptance criteria 1-10 all verified by driving the real CLI:
1. `replicant list` prints 11 techniques + UC mappings. ✓
2. `connect --host 127.0.0.1 --port 5514 --transport udp --test` delivered a benign `traffic:forward accept` line (to a benign 198.51.100.x dst) to a loopback receiver. ✓
3. REP-001 to file: periodic, constant src/dst/dpt/proto, small bytes in preset bounds, interval base+jitter (high/5m gaps all within [27,33]s of the 30s base). ✓
4. REP-002: 1000 events, 1000 unique dpt, 995 deny / 5 accept, one src/one dst. ✓
5. REP-004: 4000 unique high-entropy qnames (label entropy 4.76 b/char) under one synthetic parent, qtype weighted TXT+NULL > A+CNAME, held resolver/53/udp. ✓
6. Seven golden CEF lines reproduced byte-for-byte (reference file used as the oracle). ✓
7. Loopback UDP + TCP transport tests green, no external collector. ✓
8. Two same-seed REP-001 `--to-file` runs are byte-identical. ✓
9. black/ruff/mypy clean; all tests pass. ✓
10. Manifest written per run (seed, technique, params, entities, target, count, UTC+04:00 times, anchor). ✓

### Deviations (documented, all justified)
- `rt` (catalog varied field) is realized as `FTNTFGTeventtime` epoch + the syslog timestamp; the FortiGate templates emit no separate `rt=` key, matching the reference golden lines.
- Golden tests compare the **CEF payload** (from `CEF:0|`); the syslog prefix is transport-added (blueprint s9). Framing tested separately.
- Syslog PRI is derived properly from FortiOS level (notice->189, warning->188, alert->185) rather than the reference's <189>/<188> placeholders; this only affects the prefix, not the golden payload.
- CLI uses stdlib argparse (blueprint permits, cuts a dependency). TLS transport deferred to Phase 2 per scope.
- Toolchain: Python 3.12 venv (system was 3.9). mypy skips numpy internals (PEP 695 stubs don't parse under the 3.11 target); engine casts all numpy returns to plain Python types.

### [Unverified] signature IDs carried forward (flagged in code + catalog)
- DNS dns-query `54803` (dns-response 54802 confirmed).
- SSL-VPN success/tunnel-up `39947` (login-fail 39426 confirmed).
These are constants in `profiles/fortigate.py` with inline `[Unverified]` notes.
