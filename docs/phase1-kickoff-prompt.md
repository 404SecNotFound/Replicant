# Replicant — Phase 1 Kickoff Prompt for Claude Code

Paste the block below into Claude Code at the root of the Replicant repo, after placing these files:
`docs/blueprint.md`, `docs/fortigate-cef-reference.md`, `docs/prior-art-and-licensing.md`, `data/technique-catalog.yaml`, and `CLAUDE.md`.

---

You are implementing Phase 1 of Replicant. Read `CLAUDE.md` and `docs/blueprint.md` in full before writing code. Follow the safety rules and coding standards there without exception.

## Goal of Phase 1

A working end-to-end pipeline that a detection engineer can run: bring the tool online, connect to a syslog collector, send a test log, pick a technique from a menu, and stream realistic synthetic FortiGate CEF telemetry to the collector. Three techniques must work end to end: REP-001 periodic C2 callback, REP-002 vertical port scan, REP-004 DNS tunneling.

## Scope (build exactly this, no more)

1. Project scaffold: `pyproject.toml` (Apache-2.0, Python 3.11+), package layout from blueprint section 16, `LICENSE`, `NOTICE` with the attributions from blueprint section 20, and the MITRE ATT&CK notice.
2. Config: `config/settings.py` loading and saving YAML config and collector profiles, with the precedence rule CLI over menu over config over default. Seed support.
3. Models: `core/models.py` Pydantic v2 for Technique, RunRequest, CollectorProfile, Entity, EventRecord, RunManifest. Load and validate `data/technique-catalog.yaml`.
4. CEF serializer: `cef/serializer.py` implementing the header and escaping rules from blueprint section 9. This module has no vendor knowledge.
5. FortiGate profile: `profiles/base.py` interface and `profiles/fortigate.py` covering the log types needed for the three techniques: traffic:forward (accept and deny) and dns:dns-query. Field names, signature IDs, and severity mapping come from `docs/fortigate-cef-reference.md`.
6. Entity model: `entities/model.py` with seeded synthetic pools (internal hosts, external synthetic-adversary pool, resolver, ports). Enough for the three techniques.
7. Scenario engine: `scenario/engine.py` and `scenario/distributions.py`. Deterministic, no I/O. Implement plans for REP-001 (interval plus jitter, small lognormal bytes, held src/dst/dpt), REP-002 (many dpt, one src one dst, mostly deny), REP-004 (high-entropy qnames, high label cardinality, weighted qtypes).
8. Transport: `transport/syslog.py` with UDP and TCP senders and `send_test()`, plus `transport/filesink.py`. RFC3164 framing.
9. Orchestrator: `core/orchestrator.py` tying request to plan to emit, writing the run manifest, honoring a kill switch.
10. CLI: `cli/app.py` verbs `list`, `connect --host --port --transport --test`, `run <id> --intensity --duration --seed --to-file --no-send`.
11. Menu: `cli/menu.py` Rich flow from blueprint section 7 (startup, connect wizard, test log, main menu, params, run view, stop). The menu calls the Orchestrator only.
12. Tests: `tests/` with CEF golden tests against the seven sample lines, FortiGate profile tests, scenario determinism and distribution-bound tests, catalog validation, and a loopback UDP and TCP transport test that needs no external collector.

## Hard constraints

- Fail closed if no collector is configured. The only socket target is the configured collector.
- Synthetic entities only, per the safety model. No real domains or hosts.
- The Scenario Engine performs no I/O and is fully deterministic under a seed.
- No behavior lives only in the TUI. Every menu action has a CLI equivalent.
- Small dependency set only: rich, typer or argparse, pydantic, PyYAML, numpy, stdlib socket and ssl, pytest.
- Do not copy code from GPL, AGPL, or Elastic-licensed sources.

## Acceptance criteria (Phase 1 is done when all pass)

1. `replicant list` prints the catalog menu with the eleven techniques and their UC mappings.
2. `replicant connect --host 127.0.0.1 --port 5514 --transport udp --test` sends one benign traffic:forward accept CEF line to a local receiver.
3. `replicant run REP-001 --intensity medium --duration 2m --seed 1337 --to-file ./out/rep001.log` produces a periodic-callback stream with fixed interval plus jitter, small byte values, and constant src, dst, dpt across events.
4. `replicant run REP-002 ...` produces one src to one dst across many unique destination ports, mostly deny.
5. `replicant run REP-004 ...` produces DNS queries with high-entropy qnames and high unique-label cardinality under a synthetic parent domain, qtypes weighted to TXT and NULL.
6. The CEF golden tests reproduce the seven reference sample lines byte for byte.
7. The loopback transport test confirms UDP and TCP lines arrive intact in CI with no external collector.
8. Running the same command twice with the same seed produces identical output.
9. black, ruff, and mypy are clean. All tests pass.
10. A run writes a manifest file recording seed, technique, params, target, event count, and start and end times in UTC+04:00.

## Order of work

Scaffold and models first, then the CEF serializer with its golden tests (this is the riskiest correctness point, lock it early), then the FortiGate profile, then the scenario engine with determinism tests, then transport with loopback tests, then the Orchestrator, then the CLI, then the Rich menu last. Keep tests green as you go. Do not start Phase 2 techniques or TLS or multi-vendor work.

## What to hand back

A short report: what was built, how to run the three techniques, test and lint status against the acceptance criteria, any `[Unverified]` FortiGate signature IDs you could not confirm, and any deviations from the blueprint with the reason.
