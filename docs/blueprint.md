# Replicant Coding Blueprint (v1)

**Repository:** github.com/404SecNotFound/Replicant
**Author:** RZA
**Created:** 2026-07-16 (UTC+04:00 Dubai)
**Status:** Design locked for Phase 1. Hand this file, `CLAUDE.md`, `replicant-technique-catalog.yaml`, `replicant-fortigate-cef-reference.md`, and `replicant-prior-art-and-licensing.md` to Claude Code.
**License target:** Apache-2.0.

---

## 1. What Replicant is, and is not

Replicant is a Python tool that generates safe, synthetic firewall and network security telemetry in CEF, streams it over syslog to a SIEM (LogRhythm first), and is driven by a MITRE ATT&CK grounded technique catalog. A detection engineer selects a technique from a menu, and Replicant emits a realistic sequence of firewall logs that exercise the detection built for that behavior.

Replicant IS:
- A fabricator of log text. Every output is a synthetic string sent to one operator-specified collector.
- A validation harness for network detection content. Each catalog entry carries a generic `ndr_rule` label for the class of detection it exercises, which you map to whatever your own rule pack calls the equivalent.
- Vendor-profile driven. FortiGate first, other next-gen firewalls added as profiles.

Replicant is NOT:
- An attack tool. It never executes commands, never scans real hosts, never resolves or contacts real C2, never moves real data. Byte counts and attack names are fields in a log line, nothing else.
- A packet crafter. It writes application-layer log records, not raw network traffic.

## 2. Positioning and prior art (honest)

Replicant is not the first synthetic log generator. The prior-art review (see `replicant-prior-art-and-licensing.md`) found two near-neighbors:

- Cisco Talos EvidenceForge (MIT): strong permissive engine, but writes batch dataset files, is host-centric, and its only firewall output is Cisco ASA syslog. No live syslog streaming, no NGFW CEF.
- summved/log-generator (GPL-3.0): streams CEF firewall logs over syslog with ATT&CK chains, but firewall is one generic source, not NGFW-vendor-accurate or LogRhythm-tuned. Copyleft, so its code cannot be reused in an Apache-2.0 project.

Replicant's defensible differentiators, in order:
1. NGFW-accurate CEF modeled on a real vendor schema (FortiGate first), field-for-field.
2. LogRhythm parser alignment. The output is shaped so LogRhythm can accept it as a syslog source and, later, parse it with a known MPE policy.
3. Live streaming with realistic timing (rate, jitter, business-hours weighting), not batch dumps.
4. Safe-by-design fabrication with an explicit safety model.
5. An ATT&CK catalog mapped to a specific, published detection pack, so telemetry and detection ship together.

Do not market Replicant as "first" or "the only." Market it on firewall fidelity, LogRhythm alignment, live streaming, and safety.

## 3. Design principles

- Safe by design. The only network egress is to the configured collector. Everything else is string generation.
- Deterministic and seedable. A given seed plus catalog plus params yields the same event stream, so tests and detections are reproducible.
- Statistically realistic. Byte sizes, intervals, and cardinalities follow the distributions in the catalog, not flat constants. This is the difference between a toy and a tool.
- Vendor-profile driven. The CEF header, field dictionary, and value generators live behind a profile interface. FortiGate is the first implementation.
- Catalog-driven UI. The menu and CLI are generated from the technique catalog. Adding a technique is a data change, not a code change.
- Stream or batch. Default is live streaming to syslog. A file sink writes the same records to disk for offline review and CI.
- Offline first. No internet dependency at runtime. No telemetry phone-home.
- Testable. CEF serialization, transport, and distributions each have unit tests. Golden sample lines from the reference file are the oracle.

## 4. Safety model (read before writing any emitter)

1. Single destination. Replicant sends only to the collector IP and port the operator enters in the connection wizard. There is no other socket target. A hard guard rejects sends when no collector is configured.
2. Synthetic entities only. Default IP pools are RFC1918 and IANA documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). DNS parent domains are non-resolvable synthetic names. Usernames come from a synthetic directory. No real domains, no real malware names beyond signature labels.
3. Rate limits. A global max events-per-second cap (default configurable, for example 2000 eps) protects the operator's own collector. The wizard states the cap.
4. Kill switch. Any run can be stopped immediately (menu stop, Ctrl-C, or a stop flag in headless mode). Partial runs end cleanly and print a summary.
5. Audit trail. Every run writes a run manifest: seed, technique, params, entity pools used, start and end time, event count, and the collector target. This lets the analyst line up telemetry with detections.
6. Clear labeling option. A config switch can stamp a benign marker field (for example a custom CEF label) so lab data is separable from production if the collector is shared. Off by default to preserve fidelity, documented prominently.
7. Ethics and scope note in README. Replicant is for environments the operator owns or is authorized to test. State it plainly.

## 5. Architecture

Layered, one direction of dependency, top calls down:

```
+--------------------------------------------------------------+
|  Presentation                                                |
|   - Rich interactive menu (TUI)                              |
|   - Headless CLI (argparse/typer), same actions as the menu  |
+---------------------------+----------------------------------+
                            |
+---------------------------v----------------------------------+
|  Orchestrator                                                |
|   - loads config + catalog, resolves a Run request           |
|   - owns the run lifecycle, kill switch, run manifest        |
+------------+----------------------------+--------------------+
             |                            |
+------------v-----------+   +------------v---------------------+
|  Scenario Engine       |   |  Connection Manager             |
|   - technique -> timed  |   |   - collector profiles          |
|     event plan          |   |   - UDP / TCP / TLS transport   |
|   - entity selection    |   |   - test-log handshake          |
|   - distributions, jit. |   +------------+--------------------+
+------------+-----------+                |
             |                            |
+------------v-----------+   +------------v--------------------+
|  Vendor Profile        |   |  Syslog Emitter                |
|   (FortiGate)          |   |   - RFC3164/5424 framing        |
|   - field dictionary   |   |   - pacing to the plan clock    |
|   - value generators   |   |   - file sink mirror            |
|   - log-type templates |   +---------------------------------+
+------------+-----------+
             |
+------------v-----------+
|  CEF Serializer        |
|   - header + extension  |
|   - escaping (spec)     |
+------------------------+

Cross-cutting: Entity/Asset Model, Config/State, Logging/Audit, Seeded RNG.
```

## 6. Module breakdown

Each module is a package under `replicant/`. Key responsibilities and the main types:

- `cli/` Presentation. `menu.py` (Rich screens: startup, connection wizard, main TTP menu, technique params, run view). `app.py` (argparse or typer entry, headless verbs). Both call the Orchestrator only.
- `core/orchestrator.py` `Orchestrator` resolves a `RunRequest` (technique id, intensity, overrides, collector profile) into a `Run`, drives the Scenario Engine, feeds records to the Emitter, writes the manifest, honors the kill switch.
- `core/models.py` Pydantic v2 models: `Technique`, `RunRequest`, `RunManifest`, `CollectorProfile`, `Entity`, `EventRecord` (vendor-neutral intermediate event before serialization).
- `core/pacing.py` when each event is allowed to leave the host. `send_offsets` turns a planned timeline plus the rate cap into one list of send offsets; `compress_timeline` rescales event times for `--speed`. Pure, no clock and no sockets: the Orchestrator owns the waiting, this owns the arithmetic, so the schedule can be asserted exactly rather than measured.
- `scenario/engine.py` `ScenarioEngine.plan(technique, params, entities, seed) -> Iterator[PlannedEvent]`. Turns one technique into a time-ordered sequence with per-event field values. Pure, deterministic, no I/O.
- `scenario/distributions.py` seeded helpers: `lognormal_bytes`, `jittered_interval`, `business_hours_weight`, `unique_pool_sampler`. numpy-backed.
- `profiles/base.py` `VendorProfile` interface: `header(technique) -> CefHeader`, `extension(planned_event) -> dict`, `severity(level)`, `byte_fields()`.
- `profiles/fortigate.py` `FortiGateProfile`. Field dictionary and log-type templates for traffic, dns, utm/ips, event/vpn, event/system. Source of truth for field names and signature IDs is `replicant-fortigate-cef-reference.md`.
- `cef/serializer.py` `to_cef(header, extension) -> str`. Implements the escaping rules exactly (see section 9). No vendor knowledge here.
- `transport/syslog.py` `SyslogEmitter`. UDP, TCP, and TLS senders behind one interface. `send(line)`, `send_test() -> bool`. RFC3164 framing by default, RFC5424 optional.
- `transport/filesink.py` mirrors every emitted line to a `.log` file for offline review and CI.
- `entities/model.py` `EntityModel` builds and holds coherent pools: internal subnets, host pool, user pool, benign external pool, synthetic-adversary external pool, GeoIP country tags, service and port maps. Shared across events so a scenario is coherent.
- `config/settings.py` load and save YAML/TOML config and saved collector profiles. Seed management.
- `audit/manifest.py` writes the per-run manifest and the human run summary.

## 7. Menu UX flow (exactly as specified)

Startup sequence:

1. Banner: "Replicant online." Show version, vendor profile (FortiGate), and safety one-liner.
2. Prompt: "Connect to a syslog collector now? [Y/n]". This is the precursor step before any technique can run.
3. If yes, open Connection Settings:
   - Collector IP or host
   - Port (default 514)
   - Transport (UDP default, TCP, TLS)
   - Optional facility and app-name for the syslog header
   - Save as a named profile? [y/N]
4. Send test log: Replicant emits one benign FortiGate `traffic:forward accept` CEF line to the collector and asks "Did your collector receive the test log? [Y/n]". In LogRhythm the operator accepts the new log source as syslog. Parsing is intentionally out of scope now.
5. On confirmation, show the Main Menu, generated from the catalog:

```
Replicant  |  collector 10.20.0.50:514/udp  |  seed 1337

  Select a technique to generate telemetry:

  [1] REP-001  Periodic C2 callback (low-and-slow)     -> UC-001
  [2] REP-002  Vertical port scan                      -> UC-002a
  [3] REP-003  Horizontal sweep                        -> UC-002b
  [4] REP-004  DNS tunneling / DNS exfil               -> UC-003
  [5] REP-005  Outbound exfil volume anomaly           -> UC-004
  [6] REP-006  Destination fan-out burst               -> UC-005
  [7] REP-007  Brute force and password spray          -> UC-006
  [8] REP-008  Newly observed external destination     -> UC-007
  [9] REP-009  IDS/IPS event-rate spike                -> UC-008
  [10] REP-010 Denied outbound connection burst        -> UC-009
  [11] REP-011 VPN geovelocity anomaly                 -> UC-010

  [c] Connection settings   [s] Seed   [q] Quit
```

6. On selection, show technique params: intensity (low/medium/high), duration, rate override, entity pool choices, and a "dry run to file only" toggle. Show the estimated event count and duration before starting.
7. Run view: live counters (events sent, elapsed, eps, target), a progress indication, and a Stop control. On stop or completion, print the run summary and manifest path.

Headless equivalent (for Claude Code and CI):

```
replicant connect --host 10.20.0.50 --port 514 --transport udp --test
replicant run REP-001 --intensity medium --duration 30m --seed 1337
replicant run REP-004 --intensity high --to-file ./out/dns.log --no-send
replicant list                # prints the catalog menu
```

Both modes call the same Orchestrator. No behavior lives only in the TUI.

## 8. Syslog connection and transport

- Transports: UDP (default, port 514), TCP (framing per RFC6587 octet-counting optional), TLS (TCP plus certificate; allow self-signed for lab with an explicit insecure flag).
- Framing: RFC3164 header by default (`<PRI>Mmm dd HH:MM:SS HOST tag:`), RFC5424 optional. The CEF payload follows the header.
- Test-log handshake: `send_test()` emits one benign line and returns transport success. Note that UDP cannot confirm receipt, so the wizard asks the operator to confirm on the collector side. TCP and TLS confirm the socket connected.
- LogRhythm notes: the operator points Replicant at the System Monitor Agent or Open Collector syslog listener. In the console the new source is accepted as a syslog log source. MPE parsing is deferred by design. Record the exact "accepted as" source type in the run manifest for later parser work.
- Saved profiles: connection profiles persist to the config directory so repeat runs skip the wizard.

## 9. CEF serializer specification

Header, seven fields after the syslog prefix:

```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

Escaping rules (implement exactly, unit-test against golden lines):
- Header field values: escape backslash as `\\` and pipe as `\|`. Equals is literal. Spaces literal.
- Extension values: escape backslash as `\\` and equals as `\=`. Pipe is literal. Encode newlines as `\n` or `\r`.
- Whole message is UTF-8.
- The syslog prefix is added by the transport layer and is not part of the CEF header.

FortiGate specifics the serializer receives from the profile:
- Device Vendor `Fortinet`, Device Product `Fortigate` (lower-case g, matches real output).
- Signature ID is the last five digits of the FortiOS `logid`.
- CEF severity is the reversed FortiOS level (alert maps to 7, warning to 4, notice to 3). The profile owns this mapping; the serializer just writes the integer.
- Native FortiGate fields with no standard CEF key are prefixed `FTNTFGT` (for example `FTNTFGTqname`). Standard keys (`src`, `dst`, `spt`, `dpt`, `proto`, `act`, `app`, `duser`, `out`, `in`, `deviceExternalId`, `rt`, `externalId`) are used where they exist.

Golden test oracle: the seven constructed sample lines in `replicant-fortigate-cef-reference.md`. The serializer plus FortiGate profile must reproduce those lines byte for byte given the same inputs.

## 10. Vendor profile abstraction

`VendorProfile` is the extension point. FortiGate ships first. Palo Alto, Check Point, and Cisco ASA or FTD are later profiles, each supplying its own header constants, field dictionary, severity mapping, and per-technique templates. The Scenario Engine and CEF serializer stay vendor-neutral. Adding a firewall is implementing one interface plus a reference file like the FortiGate one.

## 11. Technique catalog

The catalog (`replicant-technique-catalog.yaml`) is loaded at startup and validated against the Pydantic `Technique` model. It powers the menu, the CLI `list`, and the Scenario Engine. Each entry names its NDR rule and UC so telemetry and detection stay in lockstep. Signature IDs marked `[Unverified]` must be confirmed on a live FortiOS build before customer use.

## 12. Scenario engine (the sophistication)

`ScenarioEngine.plan()` converts one technique into a deterministic, time-ordered `Iterator[PlannedEvent]`:

- Entity selection: pick a source host, destination or destinations, user, and ports from the Entity Model using the seeded RNG. Hold the fields the catalog marks `cef_fields_held`, iterate `cef_fields_varied`.
- Timing: base interval plus jitter for callbacks; tight gaps for scans; off-hours weighting for exfil; burst-then-decay for denied bursts. `business_hours_weight` shifts event times toward or away from working hours in UTC+04:00.
- Volume shape: byte sizes from `lognormal_bytes`, cardinalities from `unique_pool_sampler`, counts from the intensity preset.
- Warm-up where needed: REP-008 first emits a baseline of known destinations per host, then introduces first-seen ones. The manifest records when the anomaly begins.
- Determinism: same seed plus technique plus params yields the same plan. The engine performs no I/O, which makes it fully unit-testable.

## 13. Entity and asset model

One coherent world per run so multi-event scenarios line up:
- Internal subnets and a host pool (RFC1918).
- User pool (synthetic directory, canonical usernames so UC-006 and UC-010 normalization holds).
- Benign external pool and a separate synthetic-adversary external pool (documentation ranges), each with GeoIP country tags.
- Service and port maps.
The same source host keeps its identity across a scenario, the same user logs in from consistent geography until a geovelocity scenario says otherwise.

## 14. Configuration and state

- `config.yaml` in an OS-appropriate config dir: default seed, eps cap, default intensity, entity-pool sizes, benign-marker switch, byte-field key.
- `profiles.yaml`: saved collector profiles.
- Precedence: CLI flag over menu input over config file over built-in default.

## 15. Tech stack and dependencies

- Python 3.11+.
- `rich` for the TUI. `typer` or stdlib `argparse` for the CLI (prefer `typer` for ergonomics, acceptable to use argparse to cut a dependency).
- `pydantic` v2 for models and catalog validation.
- `PyYAML` for catalog and config.
- `numpy` for distributions.
- Standard library `socket` and `ssl` for transport. No heavyweight networking dependency.
- `pytest` for tests. `ruff` and `black` for lint and format. `mypy` for types.
Keep the dependency set small. No scapy, no requests at runtime.

## 16. Project layout

```
Replicant/
  README.md
  LICENSE                      # Apache-2.0
  NOTICE                       # attributions (section 20)
  pyproject.toml
  replicant/
    __init__.py
    cli/
      app.py                   # headless entry, verbs: connect, run, list
      menu.py                  # Rich interactive menu
    core/
      orchestrator.py
      models.py
    scenario/
      engine.py
      distributions.py
    profiles/
      base.py
      fortigate.py
    cef/
      serializer.py
    transport/
      syslog.py
      filesink.py
    entities/
      model.py
    config/
      settings.py
    audit/
      manifest.py
  data/
    technique-catalog.yaml     # from replicant-technique-catalog.yaml
    entities.default.yaml
  docs/
    fortigate-cef-reference.md
    prior-art-and-licensing.md
    blueprint.md               # this file
  tests/
    test_cef_serializer.py     # golden lines
    test_fortigate_profile.py
    test_scenario_engine.py
    test_transport_loopback.py
    test_catalog_valid.py
```

## 17. Testing and validation

- CEF serializer golden tests: reproduce the seven reference sample lines byte for byte.
- FortiGate profile tests: field names, signature IDs, severity mapping.
- Scenario engine tests: determinism (same seed same plan), distribution bounds, cardinality counts, warm-up ordering for REP-008.
- Transport loopback: a tiny in-test UDP and TCP receiver confirms lines arrive intact. Runs in CI with no external collector.
- Catalog validation: every entry parses against the model, every `ndr_uc` is unique and known.
- End-to-end acceptance (manual, documented as a runbook): point Replicant at a LogRhythm syslog listener, run REP-001, confirm the source is accepted and events arrive. Then, once the matching UC rule is deployed in silent mode, confirm the rule fires on the generated pattern. This closes the loop: Replicant validates the pack, the pack validates Replicant.

## 18. Roadmap and phases

- Phase 1 (pipeline): scaffold, config, CEF serializer with golden tests, minimal FortiGate profile, UDP and TCP syslog with test-log handshake, Rich menu plus headless CLI, and three techniques end to end (REP-001 periodic callback, REP-002 vertical scan, REP-004 DNS tunneling). Loopback CI green. This is the Claude Code kickoff scope.
- Phase 2 (full catalog): the remaining catalog entries, entity model hardening, off-hours weighting, warm-up baseline for REP-008, TLS transport, saved profiles, run manifest polish.
- Phase 3 (multi-vendor): Palo Alto and Check Point profiles plus their reference files. Profile-selection in the menu.
- Phase 4 (ATT&CK and AI builder): a technique-selection and scenario-composition helper that assembles multi-step scenarios from ATT&CK. Keep any AI assist advisory; the human authors the detection design. AI must not write the LogRhythm rule design notes. Done 2026-07-19: data/scenario-catalog.yaml + replicant/scenario/composer.py + advisory.py + Orchestrator.run_scenario, CLI 'scenario' verb and Rich menu [a]. Deterministic, no LLM. Web UI deferred.
- Phase 5 (web UI): the React 18 + Vite + TypeScript + Tailwind + shadcn/ui front end from the earlier product notes, driving the same Python core over an API.

## 19. Open questions and assumptions

1. LogRhythm ingestion target: confirm whether the first collector is the System Monitor Agent syslog listener or Open Collector, since it affects the recommended framing. [Assumption] UDP 514 to a syslog listener for Phase 1.
2. Signature IDs marked `[Unverified]` in the catalog and reference (DNS query 54803, SSL-VPN success 39947, IPsec ids) need confirmation on a live FortiOS build.
3. Byte-field key default: catalog assumes `out`/`in`. Confirm the FortiOS build in the target lab does not emit `FTNTFGTsentbyte`/`FTNTFGTrcvdbyte`, or keep both switchable (planned).
4. RFC5424 vs RFC3164: default 3164 for FortiGate realism, confirm LogRhythm acceptance.
5. Benign-marker field: decide the exact custom CEF label if shared collectors are in scope.

## 20. Attribution and credits (NOTICE)

License-safe reuse, from the prior-art review:
- Technique-catalog YAML shape is informed by Atomic Red Team (MIT).
- Token and distribution templating is informed by Splunk Eventgen (Apache-2.0).
- Canonical-event model, Jinja-style emitters, and a quality-scoring idea are informed by Cisco Talos EvidenceForge (MIT).
- The plan-to-emitter pipeline is informed by flowsynth (Apache-2.0).
Do not copy code from AGPL-3.0 (Endgame RTA), GPL-3.0 (AttackGen, summved, tcpreplay), or Elastic License 2.0 (elastic/detection-rules). These are inspiration only.

MITRE ATT&CK notice to include in README and NOTICE:
"This project uses MITRE ATT&CK. (c) 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. ATT&CK is a registered trademark of The MITRE Corporation. Use does not imply endorsement."

Credit summved and Cisco Talos EvidenceForge in the README as prior art that shaped the design, even though their code is not reused.
