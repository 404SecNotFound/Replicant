# Changelog

All notable changes to Replicant are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Claims that have not been validated against a live vendor build or a real host are marked `[Unverified]`, and stay marked until they are.

## [0.3.0] - 2026-07-29

The web UI becomes something you can actually reach and navigate. No change to the
technique catalog, which stays at 24 entries and its own version 0.2.0.

### Changed: the web UI is directly reachable

`replicant web` bound a **random** loopback port, minted a **per-session** token
into the URL, and rejected any `Host` that was not localhost. The URL changed on
every restart and reaching it from another machine meant an SSH tunnel. Driven by
`tasks/webui-access-and-nav-spec.md`.

- **Fixed port.** `--port`, defaulting to **9787**. A busy port is now an error
  naming the port and the flag, not a reason to silently pick another: a fixed port
  is only useful if it is actually fixed. 8787 was the first candidate and was
  dropped after it turned out to be occupied on the author's own machine, which is
  exactly the collision a fixed port has to avoid. [Unverified] against the IANA
  registry.
- **Non-loopback binds are supported.** `--host` accepts any local address or
  `0.0.0.0`. This deliberately relaxes the enforcement added in 0.1.0 (below).
- **The Host allowlist follows the bind address**, plus loopback, plus repeatable
  `--allowed-host`. On a wildcard bind any IP *literal* Host is accepted, because
  DNS rebinding needs a hostname whose resolution the attacker controls; hostnames
  still have to be named.
- **The token persists** to `~/.config/replicant/web-token`, created `0600` in a
  `0700` directory, so a bookmark and a systemd unit keep working across restarts.
  `--rotate-token` mints a new one. A blank or unreadable file is treated as absent
  rather than as a valid empty token.
- **The token is accepted four ways**: `Authorization: Bearer`, the existing
  `X-Replicant-Token`, a query parameter, and an httpOnly `SameSite=Strict` session
  cookie set on the first authenticated load. The frontend then strips the token
  from the address bar.
- **`--no-auth`**, with a loud warning, refused outright on a non-loopback bind
  unless `--i-understand-this-is-unauthenticated` is also passed.
- **The terminal tab is off by default on a non-loopback bind**, restored with
  `--enable-terminal`, and reported to the frontend so the tab is hidden rather
  than offered and broken.
- **`scripts/replicant-web.service`**, a systemd unit template. **Verified** against
  a real systemd (Debian 12, systemd 252, PID 1 in a container): the unit starts,
  runs as a non-root service user, serves, refuses an unauthenticated request,
  writes its token 0600 under `ProtectHome=read-only`, disables the terminal tab on
  its `0.0.0.0` bind, and recovers from `SIGKILL` via `Restart=on-failure` with the
  token intact. `scripts/verify-systemd-unit.sh` is those assertions, and CI runs
  them on every push (job `systemd-unit`), so the unit cannot rot silently.

### Security: the token no longer reaches the systemd journal

Running the unit for real found a defect that no amount of reading it would have.
The startup banner printed the full URL including `?token=...`. Interactively that
is the point. Under systemd, **stdout is the journal**, so every start wrote the
token in cleartext into a file readable by root and the systemd-journal group,
giving away precisely what the `0600` token file protects.

The banner now prints the token only when stdout is a terminal. Otherwise it prints
the URL without it and names the file to read it from, and drops the "stop: Ctrl-C"
hint, since nobody is at a keyboard. Covered by three unit tests and by an assertion
in `scripts/verify-systemd-unit.sh` that greps the journal for the live token.

### Security: what replaces the loopback bind

0.1.0 refused a non-loopback bind because the token was per-session, there was no
origin check, and the transport is plain HTTP. That refusal is now gone, so:

- **A cookie is an ambient credential and the previous ones were not.** A browser
  attaches it to a cross-site request on its own, which a header or query token
  never was. A state-changing request authenticated *by the cookie* must therefore
  carry an `Origin` the Host allowlist accepts; a missing `Origin` is refused.
  Requests authenticated by a header or query parameter are exempt, because nothing
  spends those on a user's behalf.
- **The terminal websocket now performs its own Host, Origin, token, and
  enabled checks.** Websocket scopes never traverse HTTP middleware, so the guard
  protecting every `/api` route did not protect `/ws/terminal`. That was invisible
  while the bind was loopback-only. Recorded at
  `docs/end-to-end-debug-audit-2026-07-21.md:296-298`; now closed.
- **Still plain HTTP.** The token and the traffic are readable on the wire. Put the
  UI on a management segment or behind a TLS-terminating proxy named with
  `--allowed-host`.

### Added: the web UI is navigable at 24 techniques

The left rail was a flat list of 24. Part 2 of the same spec.

- **Grouped by ATT&CK tactic**, collapsible, with a count per group. A technique
  mapped to several tactics appears under each. The order is the kill chain, stated
  explicitly in `webui/src/lib/catalogView.ts`, because it is neither alphabetical
  nor numeric: Reconnaissance is the first tactic and carries the highest number
  (TA0043), and Exfiltration (TA0010) follows Command and Control (TA0011).
- **A filter box** matching technique id, name, use case id, and ATT&CK technique id
  at once, since an engineer arriving from a detection backlog has whichever
  identifier their ticket carried. Groups that empty out disappear.
- **Log-type toggles** for the five render paths the catalog uses.
- **A Docs tab** serving the three vendor CEF references and the two catalog
  expansion research notes from a fixed allowlist. The requested id is a dictionary
  key, never a path fragment, so traversal resolves to nothing. Rendered with
  `marked` (MIT), lazy-loaded the same way xterm already is, so the Emitter view's
  first paint is unchanged. `docs/` ships with the repository rather than the
  package, so on a non-editable install the tab says so instead of failing.
- **An anchor control in the run form**, `now` or `fixed`, defaulting to `now` for a
  live send and `fixed` for file output, with a notice before the run when a live
  send is about to go out with a fixed anchor. `POST /api/runs` now accepts
  `anchor` and returns the resolved `anchor_epoch` and an `anchor_warning`. The web
  path previously had no way to set the anchor at all, so a live send from the UI
  always carried the deterministic default: the CEF `eventtime` sits at the anchor
  while the syslog header is stamped at send time, and on a SIEM that keys on parsed
  event time no recent-window rule fires. That is indistinguishable from a broken
  detection, which is the exact ambiguity this project exists to remove.

### Fixed

- **The run readout claimed a cap that was not being applied.** It printed
  `cap 2000` on every run, including runs with no collector. The events-per-second
  cap is only enforced where there is an emitter to throttle, so a dry run or a
  file-only run is not limited at all, and the readout sat next to a measured rate
  an order of magnitude above the number it displayed. The figure was right and the
  label was false, which reads as the cap being broken. It now shows `uncapped` when
  no collector is attached, with a tooltip saying why, and `cap N` only when sends
  are actually governed by it. The value is frozen when a run starts, so toggling
  the destination mid-run cannot relabel a run already in flight.
- No `webbrowser.open` attempt when there is no display, which printed a `gio`
  "Operation not supported" error over the startup banner on every headless start.
- **UAT case CHAIN-16 could not pass.** It asserted the web UI has no scenario
  surface by grepping `replicant/web/server.py` for the literal string `scenario`,
  expecting zero hits. That file imports `replicant.scenario.engine` for
  `implemented_technique_ids`, so the grep already returned a hit with no scenario
  feature present. Re-expressed as what it meant: five candidate routes 404 and no
  scenario control exists in the UI.

### Docs

- The README safety-model table said the web server "binds to loopback only" and
  "requires a per-session token". Both were true and are not any more; rewritten to
  the controls that now exist.
- `CLAUDE.md`, `AGENTS.md`, and this file each claimed a test asserts the web UI's
  scenario surface is absent. **There is no such test.** The artifact is a manual
  UAT row (`tasks/uat-plan.md`, CHAIN-16). Corrected in all three.

## [0.2.0] - 2026-07-26

Catalog expansion: 11 techniques to 24. Every new entry is anchored to a
peer-reviewed paper with measured results, and the anchors plus the feasibility
analysis are recorded in `docs/technique-catalog-expansion-research.md` (round 1,
strongest anchor regardless of date) and
`docs/technique-catalog-expansion-research-round2.md` (round 2, restricted to
2023-2026 top-venue work with a firewall and IDS focus and a
deployment-evidence bar).

### Added: thirteen techniques

Each was selected because it exercises a detection that no existing entry
exercises. Where a new entry is a harder variant of an old one, the pairing is
deliberate: the existing entry is the easy case and the new one is the graded
version.

- **REP-012 jittered and fleet-aggregate C2 callback.** BAYWATCH (DSN 2016);
  aggregation-based detection across large campus networks (ACSAC 2023, which
  found 43% more periodic domains by aggregating across networks). REP-001 is
  fixed-interval and trips any periodicity test; this widens jitter and spreads a
  rare callback across a fleet so the period exists only in the aggregate.
- **REP-013 self-propagating malware spread.** PORTFILER (IEEE CNS 2021,
  precision above 0.94 on WannaCry-like and Mirai-like patterns from border
  connection logs). REP-003 is one source sweeping many hosts; this grows the
  count of distinct sources geometrically per generation.
- **REP-014 cryptomining pool session.** MineShark (NDSS 2025, ten months on a
  10 Gbps campus network, 105 pools, 17.6% encrypted, over 99.3% of false alarms
  auto-filtered); MineHunter (ACSAC 2021, precision 97.0% and recall 99.7% over
  28 TB). Long-lived, low-rate, roughly symmetric byte ratio.
- **REP-015 low-throughput DNS exfiltration.** Nadler, Aminov and Shabtai
  (Computers & Security, 2019). REP-004 runs at 20-200 queries per second; this
  runs at queries per *hour*, deliberately under the thresholds REP-004 trips.
- **REP-016 DGA NXDOMAIN cluster.** Pleiades (USENIX Security 2012, 15 months in
  a production ISP, twelve previously unknown DGA botnets); Woodbridge et al.
  2016 (AUC 0.9993). Requires the new `dns:dns-response` path, below.
- **REP-017 encrypted DNS (DoH) policy bypass.** CIRA-CIC-DoHBrw-2020 corpus and
  derived detection literature. The signal is an *absence*: resolver traffic stops
  as TLS sessions to a DoH resolver start.
- **REP-018 lateral movement login chain.** Hopper (USENIX Security 2021, 94.5%
  detection at fewer than 9 alerts per day over 780M internal logins). REP-007 is
  failure volume and REP-011 is one user in two countries; neither models a path
  with a mid-path credential switch.
- **REP-019 stealth scan below rate threshold.** Threshold Random Walk (Jung et
  al., IEEE S&P 2004), which is the detector this technique is parameterized to
  defeat. The negative control for REP-002 and REP-003.
- **REP-020 first contact with a newly registered domain.** PREDATOR (CCS 2016,
  70% detection at 0.35% false positive, days to weeks ahead of blacklists).
  REP-008 is a novel destination IP per host; this is organization-wide domain
  novelty.
- **REP-021 inbound perimeter scan reception.** "Have you SYN me?" (IMC 2024, ten
  years of telescope data, over 750M scanning campaigns, more than 45B packets).
  Every prior scan technique is outbound; this is the direction a real perimeter
  mostly logs, and it doubles as the false-positive source for outbound scan
  rules.
- **REP-022 multi-stage IDS alert chain.** Kill Chain State Machines (Wilkens et
  al., 446,458 alerts condensed to 700 scenario graphs); ALERTPRO (Computers &
  Security, 2023); AACT (2025, 61% alert reduction at 1.36% false negative over a
  six-month real SOC deployment). REP-009 is a rate spike with no ordering; this
  is kill-chain ordered on a held entity pair and buried in unrelated alert noise.
- **REP-023 TLS 1.3 C2 with flow-only signal.** "Extending C2 Traffic Detection
  Methodologies: From TLS 1.2 to TLS 1.3-enabled Malware" (RAID 2024, 10.1M flow
  dataset). Emits no handshake metadata at all, so a JA3 or cipher-suite rule has
  nothing to match. Low byte variance is the only signal left, which is the
  condition TLS 1.3 creates.
- **REP-024 internal host as proxy relay.** Adversarially robust residential
  proxy detection (NDSS; 15 months of collection, around 900 GB, 120k gateway and
  110k relayed connections). Models a host used as infrastructure rather than as
  attacker or target: paired inbound and outbound legs with correlated byte
  volumes.

### Added: `dns:dns-response` render path

The only new plumbing this expansion required. `dns:dns-query` carries no
response code, and a DGA's detectable artifact is *failed* resolution, so REP-016
was not expressible without it. Implemented on all three vendor profiles, with an
eighth golden line added to each reference document and to each golden test.

FortiGate signature id `54802` is confirmed. The extension key names
(`FTNTFGTrcode`, `FTNTFGTipaddr`, `PanOSDNSResponseCode`,
`PanOSDNSResolvedAddress`, `dns_rcode`, `dns_resolved_addr`) are `[Unverified]`
against live builds. A resolved address is emitted only when the name resolved,
so its absence is itself the NXDOMAIN signal.

This path also makes fast flux and DNS TTL anomaly techniques possible later, so
it is infrastructure rather than a one-off.

### Changed: benign look-alikes are now a correctness requirement

Bilot et al. (USENIX Security 2025) reimplemented eight state-of-the-art
provenance intrusion detection systems and found none deployment-ready despite
near-perfect published results, with a simple neural network matching them on
five of seven DARPA datasets. The implication for a telemetry generator is direct:
a plan that emits only the malicious pattern lets any detection score perfectly
while teaching the operator nothing.

So the catalog's existing `benign_baseline` field is now treated as a property to
generate, not just to document. REP-012 ships a benign periodic destination,
REP-013 a stable server population on the same port, REP-014 a bursty long-lived
session, REP-015 a same-volume low-cardinality parent, REP-016 a benign NXDOMAIN
trickle, REP-018 an admin star pattern, REP-019 sparse policy denies, REP-022
unrelated alert noise, REP-023 high-variance browsing, and REP-024 a sanctioned
proxy with an identical pattern. Tests assert each control is present.

### Added: `scanner_external` entity pool

Inbound scanner sources for REP-021, on `192.0.2.0/24`, the one IANA
documentation range no other pool drew from. `EntityConfig.scanner_reserve` skips
the low addresses of that range because the Check Point profile's default `origin`
is `192.0.2.1`, and a scan source that is also the reporting gateway's own address
would be nonsense in a log.

The usable ceiling is 500 addresses. This is a safety constraint and not a tuning
limit: the IMC study observed 465,251 unique scanners and Replicant cannot
represent that without leaving synthetic space. When the ceiling binds, the run
summary says `capped` rather than silently emitting fewer sources, and a test
asserts no shipped preset hits it.

### Fixed

- **REP-018 had no `max_events` cap** and produced 25 events against a limit of
  10, violating safety rule 4. Caught by the existing
  `test_builder_never_exceeds_max_events`, which is parameterized over every
  implemented technique and therefore covered the new entries automatically.
- **REP-013's spread factor was degenerate at the low preset.**
  `max(1, fanout // 6)` is 1 when `fanout` is 8, so each infected host spawned
  exactly one more, the population never grew, and the technique was a slow
  REP-003 rather than a propagation pattern. Floored at 2.

### Notes

- REP-022's kill-chain `stage` marker is engine-internal and deliberately never
  rendered. Real FortiOS has no such field, and emitting it would both make the
  record unrealistic and hand the answer to the detection under test. A test
  proves the chain is still recoverable from rendered CEF through attack-name
  order, ascending severity, and the held source and destination pair.
- At 24 entries the deferred backlog item to group the catalog by MITRE tactic in
  the web UI left rail stops being cosmetic and becomes close to a prerequisite
  for the menu staying usable.
- Ideas considered and rejected, with reasons, are recorded in both research
  documents: TLS fingerprinting (needs handshake metadata), malicious file
  download (hash fields invite pasting a real malware hash), Tor egress (the real
  detection is IP reputation, and naming real nodes would break the
  synthetic-entity rule), WAF payloads (moves toward carrying real exploit text,
  against safety rule 3), provenance techniques, LLM triage systems, and full APT
  campaign replay (already the Phase 4 scenario composer's job).

## [0.1.0] - 2026-07-21

First public release.

An earlier `v0.1.0` tag was cut mid-preparation and then re-cut on this commit.
Nothing had consumed it: the repository was private and the release was an
unpublished draft. The entries below therefore ship as part of 0.1.0 rather than
as a 0.1.1 follow-up, and the pre-release validation described in them is what
the tag actually contains.

### Security hardening

A final pre-publication code review found several ways the tool's own safety
claims could be violated. All are fixed here, each with a regression test.

- **The events-per-second cap could be silently disabled.** The emit loop treats
  a non-positive cap as "no limit", and neither `Settings.eps_cap` nor a
  `rate_override` was constrained, so a zero or negative value turned off the
  collector protection (safety rule 4) without any error. Both are now positive
  integers by construction at the model boundary, which the CLI, menu, web API,
  and scenario paths all pass through.
- **Concurrent web runs multiplied the cap, and run handles never expired.** Each
  run gets its own rate limiter, so N simultaneous runs delivered N times the
  configured eps to one collector, and the handle map grew for the life of the
  server. The web layer now allows one active run at a time (a second request
  gets HTTP 409) and retains only a bounded number of completed handles, never
  evicting a live one.
- **The web server's "loopback only" claim was not enforced.** `--host` was bound
  verbatim while the banner always said loopback, so `--host 0.0.0.0` exposed the
  UI on every interface. A non-loopback bind address is now refused before the
  socket is created; the claim is enforced, not just printed.
- **A run's manifest could be overwritten by another in the same second.** The
  manifest filename carried a second-precision timestamp, so two same-id,
  same-seed runs in one second resolved to one path and the second destroyed the
  first run's audit record (safety rule 5). Names now carry a unique token and are
  created exclusively.
- **Alternate-vendor runs claimed FortiGate identity.** A Palo Alto or Check Point
  run wrote a manifest asserting the Fortinet FortiGate log-source parser and
  framed its syslog with the FortiGate lab hostname, both sourced from
  FortiGate-flavoured defaults. Identity now comes from the active vendor profile,
  with an operator override still honoured. The PAN-OS and Check Point log-source
  names are `[Unverified]`, consistent with those profiles' reference docs.
- **A dropped event stream looked like a finished run.** In the web UI, any SSE
  error set the run to complete and removed the Stop control while the backend
  kept emitting. The UI now polls authoritative run status on a stream drop and
  keeps the run (and Stop) active until the backend reports a terminal state.

### Added

- **`--anchor` on `run` and `scenario run`**, accepting `now`, an epoch, or an
  ISO-8601 timestamp. This closes a real trap. Event times derive from a fixed
  anchor so identical seeds give byte-identical output, but that anchor was over
  a year in the past, and the syslog header is stamped at send time. A live run
  therefore delivered records whose header said *now* and whose CEF `eventtime`
  said **371 days ago**. On a SIEM keying on receipt time nothing looked wrong;
  on one keying on the parsed event time, every recent-window rule stayed silent,
  which is indistinguishable from the detection being broken. That ambiguity is
  the exact thing this project exists to remove. Sending with an anchor more than
  two days from now now prints a warning naming the drift and the remedy.

- **Continuous integration.** GitHub Actions across four jobs: Python on 3.11 and
  3.12, frontend on Node 18 and 20, shell linting, and the installer executed
  inside real `debian:12`, `rockylinux:9` and `ubuntu:22.04` containers with
  asserted outcomes. The installer job is a regression guard for the two defects
  found during pre-release validation, both of which are invisible to a dry run.
- **Frontend test suite.** vitest with jsdom and Testing Library, nine tests.
  The Python suite grew to 249.

### Fixed

- **Verification could report success for a command it never ran.** In
  `scripts/install.sh`, `verify_cmd` allocated its stderr capture file with an
  unchecked `mktemp`. Where mktemp failed (read-only or full `/tmp`, hardened
  container), the path was empty, the redirect could not open, the command never
  executed, and the function returned 0 regardless, printing a green `[ok]` for
  verification that had not happened. Temp allocation is now checked and fails
  closed.
- **Duplicated failure banner.** `set -E` propagates the `ERR` trap into
  command-substitution subshells, so an unguarded temp-file assignment printed
  six lines of failure output where three are specified.
- **`/api/catalog` reported every technique as implemented** from a hardcoded id
  set rather than from the engine, making the "not yet implemented" interface
  states unreachable and guaranteeing a wrong answer for any future technique
  added to the catalog without a planner.
- **CLI diagnostics went to stdout.** All nine error paths now write to stderr,
  so redirecting stdout no longer hides the reason a run refused.
- **`vendorLabel` returned functions for prototype keys.** `VENDOR_LABELS[id] ?? id`
  resolved `"constructor"` and `"toString"` through the prototype chain, so the
  `??` fallback never fired. Now an own-property check.
- **The web UI's events-per-second readout aliased against the rate limiter.** It
  sampled every 220ms and reported an instantaneous rate, while the limiter runs
  on a one-second period, so each sample landed either inside a burst or inside a
  sleep. During a run steadily delivering ~1660/s it alternated between 5313/s
  and **0/s, the latter printed next to an "EMITTING" indicator**, and the
  waveform was a sawtooth crashing to zero. The rate is now averaged over a
  trailing second, which spans a full burst-plus-sleep cycle. Display only: the
  limiter itself was always correct.
- **The waveform's window label was hardcoded** to "30s" while the plot held 48
  samples at 220ms, which is 10.6s. It is now derived from the sampling
  parameters.

### Documentation

- README now shows all three surfaces: the web UI catalog and technique detail,
  a live run with the delivered rate plotted against the cap, the embedded
  terminal running the Rich menu, and `replicant list`. All captured from the
  running product against a real loopback collector.

### Changed

- The events-per-second cap is documented as a **fixed-window average** rather
  than an instantaneous ceiling, at the limiter, in the README safety table, and
  below. It was previously stated only as "a cap", which reasonably reads as the
  stronger guarantee.

- **Input domains are constrained at the model boundary.** Collector `port` is
  bounded to 1..65535 and syslog `facility` to 0..23, and the web request bodies
  reject an unknown intensity, transport, or out-of-range port with a 422 instead
  of failing deep in a handler. Malformed-body tests cover each.

- **The web bundle no longer ships xterm.js on first paint.** The terminal view is
  loaded on demand when its tab opens, splitting the single ~578 kB chunk into a
  ~288 kB main chunk and a ~292 kB chunk fetched only if the terminal is used. The
  build no longer trips Vite's size warning.

- **Licensing hygiene for the web UI.** Every first-party frontend source and
  config file now carries the Apache header; the vendored shadcn/ui components
  carry a header crediting their MIT origin. `NOTICE` gains the bundled
  third-party attributions it was missing: IBM Plex (SIL OFL 1.1), shadcn/ui and
  Radix UI (MIT).

### What ships in 0.1.0

**Technique catalog.** Eleven techniques, `REP-001` through `REP-011`, each mapped one-to-one to a named detection use case and to MITRE ATT&CK:

| ID | Technique | Use case | ATT&CK |
|---|---|---|---|
| REP-001 | Periodic C2 callback (low-and-slow) | UC-001 | T1071, T1571 |
| REP-002 | Vertical port scan (one host, many ports) | UC-002a | T1046 |
| REP-003 | Horizontal sweep (one port, many hosts) | UC-002b | T1046, T1018 |
| REP-004 | DNS tunneling / DNS exfil | UC-003 | T1071.004, T1048.003 |
| REP-005 | Outbound exfil volume anomaly | UC-004 | T1041, T1048 |
| REP-006 | Destination fan-out burst | UC-005 | T1018, T1046 |
| REP-007 | Brute force and password spray | UC-006 | T1110, T1110.003, T1110.004 |
| REP-008 | Newly observed external destination per host | UC-007 | T1071, T1583 |
| REP-009 | IDS/IPS event-rate spike | UC-008 | T1595, T1190 |
| REP-010 | Denied outbound connection burst | UC-009 | T1071, T1090 |
| REP-011 | VPN geovelocity anomaly | UC-010 | T1078, T1133 |

**Vendor profiles.** Three, selectable with `--vendor {fortigate,paloalto,checkpoint}`, in the Rich menu (`[v]`), or in the web UI. One technique catalog and one scenario engine drive every vendor; only serialization differs. Each has a reference document with seven golden sample lines used as the correctness oracle, reproduced byte-for-byte by tests.

- **FortiGate (FortiOS).** Modeled first, field-for-field.
- **Palo Alto (PAN-OS)** and **Check Point (Log Exporter).** `[Unverified]` against live builds; the reference docs are grounded in vendor documentation and published samples, and say so.

**Scenario composition.** Three curated chains that compose the existing techniques into one deterministic multi-stage CEF timeline sharing a synthetic through-line:

- `SCEN-001` Perimeter intrusion to exfiltration (3 stages)
- `SCEN-002` Recon, first contact, DNS exfil (3 stages)
- `SCEN-003` External access to foothold (4 stages)

Each run writes an advisory document beside its manifest, mapping the chain to ATT&CK tactics, naming the cross-stage correlation key, and flagging tactics the catalog can exercise but this chain does not. The advisory is deterministic and derived from the composed events; no model generates it. It is coverage context only, and states so in its own header: you author the detection design.

**Three surfaces, one orchestrator.** Headless CLI (`replicant list|connect|run|scenario|web|menu`), a Rich terminal menu, and a browser UI with an embedded terminal. Anything the menu can do, the CLI can do headless.

**Transports.** UDP, TCP, and TLS syslog, with a loopback connectivity test.

**Safety model.** Five non-negotiable rules, verified behaviorally rather than only by inspection: single-collector egress that fails closed when no collector is configured; synthetic entities only (RFC1918 plus the documentation ranges, non-resolvable DNS parents); log strings only, with no command execution, scanning, or data movement; an events-per-second cap; and a manifest written for every run.

**Determinism.** Same seed plus technique plus parameters yields byte-identical output. Verified across 181,071-line scenario runs, advisories included.

**Linux installer.** `scripts/install.sh` handles prerequisites, virtualenv, package install, frontend build, and then verifies the result by loading the catalog, rendering CEF, and sending over loopback UDP. Flags: `--no-web`, `--dev`, `--yes`, `--dry-run`.

### Known limitations

- **Installer coverage.** Verified against live package repositories on Debian 12, Rocky 9, and Ubuntu 22.04 (where the correct behavior is a refusal). `[Unverified]` on AlmaLinux, on RHEL proper as distinct from Rocky, and on Arch and openSUSE, whose package mappings are carried over unexercised. The `sudo` elevation path, the interactive consent prompt, and the no-TTY refusal are also `[Unverified]`, because the container runs that validated everything else execute as root.
- **Ubuntu 22.04, Debian 11, and RHEL-family 8** ship Python below 3.11 and cannot be satisfied from their own repositories. The installer refuses on these with guidance rather than installing packages that would not help. Ubuntu 22.04 offers `python3.11` only as a release candidate (`3.11.0~rc1`), which the installer deliberately declines.
- **The events-per-second cap is a fixed-window cap,** not an instantaneous one. It counts to the cap, sleeps the remainder of the wall second, then resets, so events cluster at the head of each window. A sliding one-second window straddling a boundary was measured once at 59 against a cap of 50; the overall delivered rate held at 49.94/s. Treat the guarantee as a fixed-window average.
- **The web UI has no scenario surface.** Scenario composition is CLI and Rich menu only. Deferred by design. The deferral is checked by a manual UAT row (`tasks/uat-plan.md`, CHAIN-16), not by an automated test. Earlier revisions of this file described it as a test; that was wrong.
- **Signature IDs** for DNS `dns-query` (54803) and SSL-VPN tunnel-up (39947) are `[Unverified]` against a live FortiOS build and carry inline notes saying so. Confirm before customer use.
- **The built wheel is not yet self-contained.** The technique and scenario catalogs live in the repo-root `data/` directory, which the supported install (a git clone plus an editable install) resolves correctly and CI verifies in real containers. A plain `pip install` of the wheel would not bundle them. Relocating the catalogs into the package so the wheel stands alone is deferred to 0.1.1, since the shipping path does not use the wheel.

### Security

Replicant writes log text. It never executes commands, scans hosts, resolves or contacts real infrastructure, or moves real data. Attack names, signature labels, and byte counts are fields in a log line and nothing more.

Installing pulls packages from your distribution's repositories, PyPI, and npm. That is install-time egress and is separate from the runtime rule, which is unchanged: at run time the only network egress is the collector you configure.

### Attribution

This project uses MITRE ATT&CK. Copyright 2026 The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation. ATT&CK is a registered trademark of The MITRE Corporation. Use does not imply endorsement.

Licensed under the Apache License 2.0. Third-party notices are in [`NOTICE`](NOTICE).

[0.1.0]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.1.0
