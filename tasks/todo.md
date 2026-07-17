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
- [ ] saved-profile menu polish (deferred)

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
