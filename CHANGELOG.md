# Changelog

All notable changes to Replicant are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Claims that have not been validated against a live vendor build or a real host are marked `[Unverified]`, and stay marked until they are.

## [Unreleased]

## [0.10.0] - 2026-09-01

Execution of the 2026-09 five-persona roadmap (`docs/roadmap-2026-09.md`): all 13
buildable survivors of the 16, across ten PRs, each code-reviewed with every new
guard run red against the unfixed code before being accepted. The three that did
not ship are lab-gated (the operational pilot, and the two that refine the
still-unbuilt F2/F5), and stay behind the launch gate. Two changes alter emitted
output, which is why this is a minor bump: the synthetic marker now defaults on
for non-loopback sends, and packet counts now vary per flow.

The keystone holds: every timing and delivery claim remains loopback-only until
the first observed rule fire. External posture stays "generates vendor-accurate
CEF, detection-unverified."

### Added

- **Per-technique validation-transferability property.** Each technique declares
  whether a green result exercises the shipped rule (`transfers`) or only its
  parser (`parser-only`, with a required reason). REP-011, REP-016 and REP-020 are
  parser-only (synthetic GeoIP tag, `.invalid` TLD, no WHOIS registration age);
  surfaced in `replicant list` and the web catalog.
- **Per-run analyst validation card.** A single-technique run writes a
  copy-pasteable `<manifest>.card.md`: the pivot entities, the emitted window, the
  correlate-on fields, a find-events search (keyed on the run id when the run is
  marked), and what a green result does and does not prove.
- **Statistical fidelity-regression suite.** Asserts each technique's emitted
  stream satisfies the quantitative property it claims (DGA/tunnel character
  distribution, NXDOMAIN ratio, beacon interval jitter, and that bytes-per-packet
  is not a fixed fingerprint).
- **Two structural false-positive foils.** REP-006 gains a shared-egress fan-out
  foil and REP-007 a NAT/proxy source-collapse foil: benign traffic that breaks
  the aggregation key, so a rule keyed on that key alone fires on it.
- **CLI-first container image.** A `Dockerfile` and `.dockerignore` plus a CI job
  that builds and drives it. `pip install replicant` / `pip install "replicant[web]"`
  documented.
- **Reference detection specs** (`docs/detection-specs/`), phased on the pilot
  technique: the REP-001 periodicity detection in SIEM-neutral pseudocode, with a
  spec/catalog sync guard. No rule is auto-generated.
- **`docs/deployment-boundary.md`**: detection lab, not production SIEM.

### Changed

- **Synthetic marker is destination-conditional and default-on for a non-loopback
  send** (was opt-in only), off for `--to-file`/loopback; `--no-marker` overrides
  and is logged; the run manifest records the decision in `marker_attestation`.
- **Packet counts (`sentpkt`/`rcvdpkt`) vary per flow** instead of a fixed
  `bytes // 150|1400` divisor, so bytes-per-packet is no longer a constant an
  analyst spots. Emitted values for a given seed differ from prior versions;
  same-seed reproducibility within a version is preserved.
- **Scenarios compose the attack (positive) stream only**, so a foil-emitting
  stage never leaks benign events onto the scenario wire, and scenario runs now
  carry a run id.
- Positioning: identity resolved to OSS detection-as-code (CLI-first); PAN-OS and
  Check Point reframed as beta against the FortiGate verified oracle; the
  AlphaSOC flightsim contrast named in the prior-art survey; external claims
  scoped to generator-verified / delivery-unverified.
- Catalog expansion is now gated on the tactic-gap tally (recorded rule).

### Fixed

- The `wheel` CI job (and the new container job) count distinct technique ids
  rather than raw lines, so a catalog-list footer can no longer inflate the count.

## [0.9.0] - 2026-09-01

A defect release from an end-to-end review of the whole codebase (10 subsystem
finders, every finding adversarially verified against the real code; 10 of 17
raised survived). Gates were green before and after. One change alters rendered
output, which is why this is a minor bump: REP-011 on Check Point now carries the
source country it used to drop.

### Fixed: three techniques or paths behaved against their own contract

- **Scenario runs bypassed the F-08 send lock.** `run()` held the
  one-sending-run-per-host lock; `run_scenario()` called the emit loop directly
  without it, so a `scenario run` sent unlocked and a concurrent `replicant run`
  found the slot free and both streamed up to the eps cap, the doubling F-08
  exists to prevent. The scenario path now holds the same lock. Guarded by a real
  second-process test, with a `--no-send` control proving a dry scenario run is
  not blocked.
- **Check Point dropped the geovelocity source country, blinding REP-011 on one
  vendor.** FortiGate and PAN-OS rendered `srccountry`; the Check Point mobile
  access path had no branch, so a correlation rule keyed on source country never
  fired against Check Point logs, on the one technique whose whole signal is the
  changing country. It now renders a Source Region field (`cs4`, following
  `auth_status`, `[Unverified]` field name against a live exporter). All three
  vendors now carry it; the eight golden lines are unchanged, since REP-011 is
  not among them.
- **A malformed `--duration` crashed with a raw traceback**, and in the Rich menu
  it tore down the whole interactive session. `--duration 30min` now gets the
  same clean refusal every other bad flag does, validated on the request model so
  the CLI, the menu and the web form all reject it identically.

### Fixed: robustness and web hardening

- **`high_entropy_labels` hung forever** when asked for more distinct labels than
  the alphabet can form (reachable through param overrides), pegging a CPU with
  no error. It now refuses like `unique_ints` already did.
- **TLS certificate verification, the secure default, was never tested.** Every
  TLS test set verify off, so flipping the default to `CERT_NONE` would have
  shipped green. A test now asserts verify-on rejects an untrusted certificate,
  with a positive control that the same cert pinned as the CA is accepted.
- **A header-token API client with no cookie jar minted a session per request,**
  retained for the 12-hour TTL, so a once-a-second monitoring poll grew tens of
  thousands of dead sessions in half a day. Only the browser's URL-token
  navigation is promoted to a cookie now; the header path mints nothing.
- **The run-event stream fan-out had no lock,** so a browser tab subscribing at
  the instant of a publish could miss that item, including the terminal
  done/error event, and stay showing an in-progress run. Subscribe, unsubscribe
  and publish are now mutually exclusive.
- **The Docs viewer's link sanitizer allowed protocol-relative URLs,** so a repo
  document containing `[x](//host)` rendered a working off-site link. It now
  rejects a second leading slash. Repo-controlled content plus the page CSP kept
  this open-redirect class, but the sanitizer exists to be defence in depth.

### The theme, and the method

Four of the ten were the class this project keeps relearning: a renderer or guard
that covers one verdict of two, or an invariant asserted but never negatively
tested. The DNS response was rendered in a test only for NXDOMAIN, never the
resolved answer; the synthetic-range guard that stands between a config and a
real-IP log had no rejection test. Both now have one.

Nine of the ten guards were run against the unfixed code and observed to fail
before being trusted. The tenth, the stream fan-out race, has a window that
cannot be forced from Python; its guard is a concurrency load test plus mutual
exclusion by construction, and is labelled as such rather than dressed up as a
forced-red control.


## [0.8.0] - 2026-08-31

### Fixed: the eighth golden line of every vendor was never compared

All three vendor golden tests assert that the reference document contains eight
golden lines, assert that the event fixtures match that count, and then
byte-compare `range(7)`. The eighth line of FortiGate, PAN-OS and Check Point had
never been compared to anything.

Changing all three to `range(8)` leaves 30 of 30 passing, so the lines were
correct and simply unchecked: a coverage hole rather than a live defect, and
still the most important thing found this cycle. This project's correctness story
is the golden oracle, and the oracle was proving seven eighths of what its own
test names claimed. Same class as the REP-013 guard whose seed avoided the
collision it asserted against.

Found by an external roadmap proposal whose triage is recorded in
`docs/10x-roadmap-triage.md`. Roughly 13 person-weeks of 58 to 62 were adopted;
the rejections and their reasons are in that file so they can be argued with
rather than rediscovered.

### Changed: Node 20 is the floor, and the npm advisories are gone (F-14)

`npm audit` reported six advisories, one critical, and the fixes needed vite 8
and vitest 4, both of which drop Node 18. That made it a supported-platform
decision rather than a version bump, and it is now taken: **Node 18 is dropped.**
It left maintenance in April 2025, so the floor the installer declared was
already behind the platform it named.

vite 5 to 8, vitest 2 to 4, `@vitejs/plugin-react` 4 to 6, jsdom 25 to 30.
`npm audit` now reports **0 vulnerabilities**. The installer's `MIN_NODE_MAJOR`
is 20 and the CI frontend matrix is 20 and 22.

`jsdom` is pinned to 26 rather than 30 on purpose: 30 requires Node 22.22+, above
the floor being declared here, and pinning it keeps the test toolchain inside the
platform the installer actually promises. `npm audit` is clean at 26.

**Debian 12 can no longer build the web UI from its own repositories.** It ships
Node 18. The installer refuses correctly and says so, and the CI matrix now
covers it with `--no-web` while `debian:13`, which ships Node 20, carries the
full install case. That is the real cost of dropping Node 18 and it is stated
rather than discovered later.

One config change came with vite 8, which tightened dev-server filesystem
access: `TechniqueDiagram.test.tsx` reads the real technique catalog with `?raw`
so its coverage check sees the shipped 24 entries rather than a fixture that
could drift, and the catalog sits one level up in the Python package. That path
is now allowed explicitly, scoped to the repository root rather than by turning
`fs.strict` off, because the dev server is still a server.

170 frontend tests pass on the new majors, tsc clean, and the build still emits
into `replicant/webui_dist` with its chunks split as before.

### Added: one sending run per host, enforced (security review F-08)

The events-per-second cap is applied by a single process's emit loop, so two
Replicant processes sending at once delivered twice the cap to the operator's
collector and neither was doing anything wrong. Safety rule 4 exists to protect
that collector, and a cap any second invocation silently doubles is not
protecting it.

Two remedies were open. A host-level lease keyed on collector destination would
let runs aimed at different collectors proceed together, and is a
distributed-systems problem in a lab tool: leases expire, clocks drift, a killed
process orphans one. The operator chose the other: state the scope and enforce
it. One sending run per host is the supported configuration, and a second is now
refused rather than allowed to double the rate, with the holding pid named in
the refusal because "another process" is not actionable.

`--no-send` and `--to-file` never acquire the slot, because they cannot reach a
collector and so cannot exceed anything. The lock is advisory and released by the
kernel when the holder exits, kill -9 included, so there is nothing stale to
clean up. What it does not cover is stated rather than implied: two hosts pointed
at one collector are two caps, and nothing on this machine can see that.

Guarded by `tests/test_sendlock.py`, which spawns a **real second process**: the
finding is precisely that the guard was scoped to one process, so a test that
re-entered the context manager in-process would pass against code that locked
nothing. Positive control run, and the refusal test observed to fail with the
lock neutered.

### Fixed: the test suite no longer reads and writes the operator's real config

`config_dir()` honours `REPLICANT_CONFIG_DIR`, and the suite had no `conftest.py`
telling it to, so running the tests touched the real `~/.config/replicant`: the
saved collector profile, the persistent web token, and now the send lock. Each
test gets its own directory.

This surfaced as five failures rather than as a tidy-up. The send lock is
host-global by design, so a web test that started a run and never stopped it held
a slot the next test's sending run was then correctly refused. Every one of those
failures was a true report about shared global state, which is why the fix is
isolation rather than a weaker lock.

### Changed: REP-018 carries Defense Evasion alongside Lateral Movement

`v0.7.0` removed TA0006 Credential Access from REP-018, because none of its
three techniques carry it. That was correct and it left TA0008 alone, which was
defensible but lost something: `T1078` Valid Accounts and `T1550` Use Alternate
Authentication Material are both Defense Evasion as well, and using valid
accounts and alternate authentication material to move laterally IS the evasion.
The entry is now TA0008 plus TA0005. Operator decision, recorded because the
v0.7.0 note states the narrower list.

## [0.7.0] - 2026-08-30

A defect release, from an external review of the technique catalog. A minor bump
rather than a patch one because the shape of the emitted telemetry changed: plans
for REP-002, REP-013, REP-014, REP-016 and REP-024 differ from every prior release
at the same seed. Determinism is intact; the output is not the same output. No
golden CEF line changed.

### Fixed: three techniques emitted telemetry their own catalog text denies

These matter more than ordinary bugs. The tool's entire claim is that the
telemetry is what the catalog says it is, so a detection validated against the
wrong signal is a false validation, and it validates as a pass.

- **REP-024's relay lag was a constant one second at every preset.**
  `int(ms) // 1000` floor-divided the shipped millisecond ranges to zero and the
  clamp made them one, so the technique whose stated purpose is defeating naive
  fixed-window timing correlation emitted precisely the fixed window it exists to
  defeat, and its foil used a fixed `+1s` on top. The lag is now drawn in float
  seconds with the sub-second remainder dithered to a whole second, so the drawn
  variance survives onto an integer-second timeline with its expected value
  intact. Measured after the fix: inter-leg gaps of 1, 2 and 3 seconds appear at
  every preset where only 1 existed before. The foil draws from the same
  distribution.
- **REP-002 ignored its own `window_s` preset and `--duration` entirely.** The
  builder read `unique_ports` and `gap_ms` and nothing else, so the low preset
  finished in about six seconds against a declared 120-second window, roughly
  twenty times more aggressive than documented, and a one-hour duration override
  returned a byte-identical plan. Probes now spread across the window with
  `gap_ms` surviving as jitter on the spread. Measured after the fix: 119s, 59s
  and 29s spans against declared windows of 120, 60 and 30. A duration override
  keeps preset density and lets the probe count give way, as REP-019 does:
  `--duration 12s` on the low preset yields 20 probes across 11 seconds.
- **REP-014's benign foil was trivially separable on the technique's own primary
  feature.** The catalog makes long duration the property the miner and the foil
  *share*, and byte burstiness the thing that separates them. The foil topped out
  at eleven steps of four share intervals, so a duration threshold alone scored
  perfectly, which is the shortcut the foil exists to deny. Foil spacing now
  tracks the session length. Measured: the foil spans 0.92 of one pool session at
  every preset, against 0.37, 0.046 and 0.010 before.

### Fixed: two ATT&CK mappings that would mislead a detection engineer

- **REP-007 mapped `T1110.004` Credential Stuffing**, which MITRE defines as
  replaying breached credential pairs. Nothing in the builder models that; one
  user against many attempts is `T1110.001` Password Guessing. Now
  `T1110, T1110.001, T1110.003`.
- **REP-012 mapped `T1029` Scheduled Transfer**, an Exfiltration technique, on a
  C2 beacon entry that lists neither TA0010 nor any transfer behaviour. Wrong
  technique and wrong tactic. Dropped; `T1071` already carries the periodicity.
- Three tactic lists claimed a tactic none of their own techniques carry. REP-009
  listed TA0043 while carrying `T1190`, now TA0043 and TA0001. REP-017 listed
  TA0005 with only C2 techniques, now TA0011. REP-018 listed TA0006 while
  carrying `T1021`, `T1078` and `T1550`, none of which MITRE assigns to Credential
  Access, now TA0008.

### Fixed: smaller defects of the same family

REP-016's benign NXDOMAIN trickle ran past the plan window it is meant to blend
into. REP-013's baseline servers could be drawn from the worm's own seed set, so a
control could grow like the worm. `jittered_interval` was unbounded, so a jitter
override above 100 percent produced negative intervals and backward timestamps.
DNS labels were not clamped to the RFC 1035 63-octet limit. The engine docstring
still claimed REP-016 had no builder. Catalog text had drifted from code in six
places, including dead `hours` preset keys and a schema comment describing
`signature_id` as a CEF header input when all three profiles derive the header sig
id from their own logid constants.

`business_hours_weight` is deleted. No builder had ever called it, and the backlog
line keeping it alive is struck in the same change: a helper preserved only by a
to-do entry is dead code with an alibi.

### The finding behind the findings

None of this was caught by 952 passing tests, because **no test asserted that the
code does what the catalog text promises**. Every defect above sat in the gap
between a documented distribution and the one actually emitted. Fourteen tests now
close it, including `tests/test_readme_catalog_sync.py`, which asserts README and
catalog agree on id, name, log type, UC id and ATT&CK ids for all 24 entries.

Two conventions, both earned here:

1. **A guard has to be run against the unfixed code and observed to fail, and the
   seed is part of the guard.** The review's own REP-013 test passed against the
   code containing the bug: seed 1337 draws `10.20.30.139`, which is not a
   baseline server, so the collision it asserts against never occurred. The seed
   draw collides in 2 percent of seeds at the low and medium presets and 4 percent
   at high. Re-pinned to seed 108, which draws `10.20.30.2` at every preset, and
   parametrized across all three. A guard whose seed avoids the defect is a guard
   that has never failed.
2. **A benign foil is a correctness requirement of the technique, not a
   decoration.** Two of the three behavioral defects were foils that a detection
   could separate for free, on the very feature the foil exists to make
   indistinguishable. A foil that is trivially separable is worse than no foil,
   because it reports as coverage.

### Known behaviour change

`replicant run REP-002 --intensity low` now occupies its full 120 seconds instead
of finishing in about six. That is what the preset always declared, and it is why
`tests/test_plan_pacing.py` overrides `window_s` down to five seconds to remain a
fast test rather than a two-minute one.

## [0.6.1] - 2026-08-30

### Fixed: every technique now draws its own signal-path diagram

The web UI's diagram mapped only REP-001..011 to drawings and silently fell
back to the periodic-beacon glyph for everything newer, so a DGA cluster or an
inbound perimeter scan rendered as a fixed-interval beacon with full
confidence. All 24 techniques now have an explicit mapping: eight new glyphs
(fleet beacon, DGA NXDOMAIN cluster, resolver-goes-quiet absence, login chain,
worm spread, inbound fan, kill-chain stages, proxy relay) and six honest
reuses whose captions state their own story (REP-019 reuses the scan fan under
"slow probes, long window", not the burst it is not). The fallback is gone: an
unmapped id renders a labelled gap, and a test that reads the real catalog
fails on any technique added without deciding its diagram.

## [0.6.0] - 2026-08-30

### Changed: the web UI is the Factory system, and dark-only

A visual identity change, not a patch. The web UI now follows the archived
dark-era Factory design ("terminal war room at midnight"), approved from three
standalone mocks that went through a builder/three-critic loop. The design
contract is `docs/webui-factory-design.md`; the amber "signal-instrument"
system it replaces is stamped superseded in `docs/webui-reskin-design.md`.

- **Fonts:** Geist 400/500 (sans) and JetBrains Mono 400, both OFL 1.1,
  self-hosted with their license texts beside the woff2 files so the license
  ships in the wheel. The approved mocks used Switzer, but the ITF Free Font
  License v2.0 that ships with the Fontshare download prohibits distributing
  the font through a repository or publicly accessible server, which is exactly
  what this repo and its releases are. IBM Plex is retired from NOTICE.
- **Palette:** #101010 canvas, #1d1a18 surfaces, #3d3a39 hairlines, bone text,
  and exactly two chromatic colors reserved for live data: signal orange
  #ee6018 and metric green #a0ca92. Weight 400 everywhere. No gradients,
  shadows, or glows. `theme.test.ts` asserts every documented token triplet in
  `index.css` encodes exactly the hex named beside it.
- **Light mode removed** (decision recorded in the design doc): the toggle,
  stored preference, pre-paint script, OS tracking, and the parity guard go
  with it. The screenshot capture script now checks the page painted the
  Factory canvas instead of asserting a theme class.
- **The run panel is a war-room frame:** metric tiles derived from the run's
  own counters, an instrumented sparkline (labeled scale, dotted mean, time
  axis), and a progress track. The mock's bytes tile does not ship because no
  byte counter exists behind it; labels say emitted, never sent or delivered,
  where only rendering is measured.
- **Honesty carried into color:** "sent, unconfirmed" renders neutral rather
  than signal-colored, the armed-collector dot is bone, active filter chips
  recess to the canvas instead of taking the signal color, and log-line
  emphasis is brightness only.

Two defects found by measuring the rendered page, both now guarded:

1. Stock tailwind-merge classifies the custom type-scale rungs as text COLOR
   classes, so `cn("text-label", "text-signal")` silently deleted the size and
   the element inherited its parent's. The vendor segmented control rendered
   16px against a class list saying 12px. `cn()` now registers the rungs and
   `utils.test.ts` pins every rung the config declares.
2. LogsView's info level styled itself with `text-text-2`, a token that does
   not exist, so the class compiled to nothing and the color was inherited by
   accident.

Type scale: `title` 24 to 36 and `lede` 15 to 16 (the approved mock's values),
plus a `stat` rung at 22px for metric-tile values. All four README screenshots
regenerated; the light-theme shot is retired.

A generated near-black circuit/topology backdrop (18 KB WebP, provenance in
NOTICE) sits behind the canvas under a flat scrim; cards are opaque, so it
reads as texture and no text pair loses its measured contrast.

## [0.5.2] - 2026-08-04

A readability release. No behaviour changes, no new techniques, nothing in the
emitted telemetry moves. Upgrading is worthwhile only if you look at the web UI.

### Fixed: more than half the web UI rendered below 12px

Reported plainly as "the text is quite small, you have to really focus your
eyes". Measured on the rendered page rather than argued about:

| | |
|---|---|
| most common size in the whole UI | **10.5px** (30 of 104 elements) |
| below 12px | **58 of 104** |
| at or above the 16px browser default | **3 of 104** |
| smallest text on screen | **8.5px**, a rule id inside the signal-path diagram |
| contrast failures | **1** |

Contrast was fine. It was audited during the reskin and the audit held. Size was
never audited at all, and that was the real gap.

It was also not a design decision. `docs/webui-reskin-design.md` defines a
palette, spacing and a motif and contains no type scale whatsoever, while the
code carried **eleven hardcoded sizes across 84 call sites**. Eleven sizes is not
a scale, it is eleven separate decisions taken one component at a time and never
compared with each other.

The scale added here distinguishes **read** from **scan**, which is the
distinction that was missing. Prose is read in sentences and needs size;
monospace and tabular data is scanned, and density genuinely helps there. So
scanned data stays tight at 12.5px while body prose moves from 13px to 14px, the
technique objective gets its own 15px, and nothing renders below 11px. Six named
rungs replace the eleven ad hoc values, so the next component cannot invent a
twelfth.

Two regressions were introduced by the change and caught by measuring again
afterwards, both recorded because the second one had shipped once before:

- `SIGNAL FIELDS` in the signal-path diagram grew wide enough to sit on top of
  its own values. The values moved rather than the label shrinking back.
- `Check Point` wrapped to two lines in the vendor picker and doubled the
  control height. It needs 84.1px in an 83.7px segment, so half a pixel of
  growth tipped it over; it had always been marginal. Restored to 12px and given
  `nowrap`, so the next long vendor name overflows visibly instead of silently
  reflowing, which is exactly how it shipped that way the first time.

### Fixed: the screenshot script had been broken for months

`scripts/capture-webui-screenshots.py` clicked a button labelled `Start run`.
v0.5.1's predecessor renamed that button to name its destination, so the script
had been failing since, and nobody knew, because it only runs when someone
regenerates screenshots. It now matches on a stable prefix. All five images in
`docs/images/` are regenerated against the new scale.

### Changed

- README test count corrected to 952.

### Unchanged

Every known limitation from 0.5.1 still stands, including **F-08** (the
events-per-second cap is per process) and **F-14** (remaining advisories are
development-only and their fixes drop Node 18). Palo Alto and Check Point vendor
fidelity remains `[Unverified]` against real appliances.

## [0.5.1] - 2026-08-04

A security and correctness release. Everything actionable from two independent
reviews, plus three defects that surfaced during a live LogRhythm lab session and
that neither review found.

**Upgrade from 0.5.0.** That release is affected by every item in the "Security"
section below, including a cross-origin hijack of the embedded terminal.

### Security

- **Cross-site WebSocket hijack of the terminal (F-01).** Origin validation compared
  hostnames and ignored scheme and port, so any other development server on an
  analyst's laptop could drive the PTY using the ambient session cookie. An origin is
  now the `(scheme, host, port)` triple, and it is required on every handshake.
- **The session cookie was the master token (F-04).** It held the persistent launch
  token from `~/.config/replicant/web-token` verbatim: no expiry, no rotation, and no
  way to revoke one browser without regenerating the token file and breaking every
  other client. The cookie now carries a short-lived random session id the server can
  expire and revoke, and `POST /api/session/logout` ends one browser only. The token
  is also gone from EventSource and WebSocket query strings, where URLs reach server
  logs, history and Referer.
- **A terminal child could hang the whole server (F-05).** Termination sent SIGTERM and
  then blocked on `waitpid` on the asyncio event loop, so a child ignoring SIGTERM
  froze every request the server was serving. Termination is now non-blocking with
  SIGKILL escalation. Terminal sessions are also capped, globally and per client.
- **Failed runs wrote no manifest (F-02).** Safety rule 5 says every run writes one, and
  the failure path is the one that most needs it.
- **Markdown in the Docs tab could execute same-origin code (F-03),** plus a
  `javascript:` link protocol hole found while fixing it. A Content-Security-Policy is
  now sent as defence in depth.
- **`--no-auth` opened HTTP but rejected every terminal session (F-06).**
- **Web file output could truncate arbitrary paths (F-07).** Output is confined to a
  server-chosen directory.
- **Malformed duration strings were accepted silently (F-09).** `-1h` parsed as a
  positive hour, `abc123` as 123 seconds. A typo produced a run of a different length
  and no signal.

### Fixed: the telemetry was wrong on two of three vendors

- **A successful login rendered as a failed one.** Check Point hardcoded
  `act=Reject` and `auth_status=Failed Login`, and Palo Alto hardcoded
  `PanOSEventID=auth-fail`, on the `event:system` path. The engine only ever sends
  `status=success` there, so **every** administrative login in REP-018 was
  self-contradictory, wrong in exactly the field a correlation rule matches, on the
  technique whose whole premise is successful logins moving host to host. FortiGate was
  always correct. A detection engineer tuning against this would have concluded their
  rule was broken.

### Fixed: runs that looked like they were working

- **A configured collector did not mean send.** The web form's destination switch
  defaulted off and the API defaulted `no_send=True`, so a verified collector plus a
  technique plus the run button produced a run that rendered every event and delivered
  none, while the stream, the progress and the events-per-second readout all looked
  identical to a working run. Measured after the fix: CLI 200 datagrams, web 200
  datagrams, identical parameters. The send path was never broken, only its default.
- **The single-run lock was invisible.** Only one run may be active, which is correct
  because concurrent runs multiply the eps cap. But the form's `running` flag is
  per-panel state, so a page reload showed an idle form while the server was hours into
  a plan-paced run, and pressing the button produced a 409 naming a run id the operator
  could not resolve, see or stop. `GET /api/runs/active` reports it, and the form names
  the technique holding the lock and offers to stop it.
- **`Send test log` reported `verified` against a collector that could not receive
  anything.** It was set from a UDP `sendto` succeeding, which only proves a route
  exists, and it showed green against an unreachable address across two lab sessions.
  The word is gone from the codebase entirely. What replaced it is disclosure rather
  than a probe: the connect test now reports what it proved and what it did not, and
  shows the source address beside the destination, because that is what makes a
  mistyped address visible. (A connected-UDP probe to the real mistyped lab address
  returns no error at all, so it would not have caught it.)
- **A collector that will not talk to us produced a traceback**, not a message. The
  transports raise `OSError` and every run handler caught only
  `(RuntimeError, NotImplementedError)`. The connect timeout also governed every later
  send, so a collector applying ordinary backpressure raised `socket.timeout` mid-run.
- **Drift messages reversed past and future (F-13),** describing the default historical
  anchor as future-dated.

### Added

- **Every use case states its core objective**, one sentence on what running it is meant
  to establish, shown first in the web UI. The panel used to open with "emits synthetic
  X telemetry that exercises Y", which is true of all 24 entries and so answered nothing.
- **IPv6 collectors (F-10).** Every socket was `AF_INET`; the address family now comes
  from `getaddrinfo`.
- **Run manifests are self-describing:** `vendor`, `duration`, `rate` and `send_stats`.
  `send_stats` counts datagrams the kernel accepted, against `event_count` which counts
  events rendered.

### Changed

- The run event stream fans out (F-12): each consumer gets its own queue seeded with
  bounded history, so two browser tabs no longer split one run between them.
- Progress reports a final callback with the true count, instead of stopping at the last
  multiple of 100.
- Sample lines are cached, so selecting a technique no longer rebuilds a 180,000-event
  plan to show three lines.
- Packaging metadata uses the PEP 639 SPDX form (F-15); LICENSE and NOTICE now ship in
  the wheel.
- A terminal resize below 20 columns is refused rather than honoured.

### Known limitations

- **F-08 is open.** The events-per-second cap is per process, so several processes can
  multiply it against one collector. Terminal sessions are now capped, which bounds it,
  but the remedy (a host-level lease, or an enforced single-process scope) is undecided.
- **F-14 is partially addressed.** Production dependencies audit clean; the remaining
  advisories are development-only and their fixes require dropping Node 18.
- Vendor fidelity for Palo Alto and Check Point remains `[Unverified]` against real
  appliances, as before.

## [0.5.0] - 2026-08-01

Replicant emulates a TTP by writing the telemetry the attack would have produced, so
the shape of that telemetry is the product. v0.4.0 fixed *when* events arrive. This
fixes *how much* of the behaviour you get when you ask for a window of it.

### Fixed: four use cases ignored `--duration`

Replicant emulates a TTP by writing the logs it would have produced, so the shape has
to be faithful, and duration is half the shape. Four of the twenty-four use cases
silently planned the wrong length:

- **REP-005** pinned itself to a fixed six hour off-hours window and ignored the flag.
- **REP-014** read the value as a *per-session* length and then multiplied it by the
  session count, so 2h asked produced 6h planned.
- **REP-019** derived its span from a probe count times a random gap.
- **REP-023** from a session count times a fixed interval.

A catalogue where the flag works on twenty entries is worse than one where it works on
none: an operator learns to trust it and is then wrong four times in twenty-four without
being told which. `tests/test_duration.py` now asserts all 24, by parameter, so a
regression names the technique.

The governing rule, now applied consistently: **`--duration` bounds the span, and where
the interval between events IS the signal, the interval is preserved and the event count
falls.** A two hour beacon is twenty-four callbacks five minutes apart, not two hundred
and forty callbacks fifty seconds apart. REP-005 caps rather than honours a request
longer than its window, because off-hours bulk transfer spilling into the working day
would no longer be the thing it exists to demonstrate.

### Added: `--duration` on scenarios

A scenario's span used to be whatever its catalog stage offsets happened to add up to.
SCEN-001 was 12h 14m and nothing could ask for two hours; the only lever was `--speed`,
which is a different operation.

Duration scales the composition: stage offsets move proportionally and each stage is
planned for a proportionally shorter window, so the chain keeps its order and its
relative spacing while every technique inside it keeps its own interval and emits fewer
events. Two passes, because the scale factor cannot be known until the natural chain has
been built - stage spans come from each technique's preset, not from the catalog. The
untimed path stays a single pass and is byte-identical.

`ScenarioManifest` records the requested duration (safety rule 5).

**A stage pinned to an absolute window is reported, not hidden.** REP-005 advances in
whole days to clear off-hours, so SCEN-001 cannot be compressed below that jump: asked
for 2h it composes 7h 16m and says so in the manifest. Returning a quietly twelve hour
run for a two hour request would be the same class of defect as the pacing one this
release opened with.

## [0.4.0] - 2026-07-31

Two things a live LogRhythm test found, and neither was a bug in what Replicant
generates. The events were always right; when they arrived, and whether the interface
could be read, were not.

### Added: events are sent when the plan says they happen

Measured against a live LogRhythm collector: REP-001 at low intensity delivered **49
events in about 3 seconds**, carrying event times spread over **238 minutes**. The
plan has always held a per-event `eventtime`. The emit loop ignored it and fired as
fast as the rate cap allowed, so what arrived was a snapshot claiming to be four
hours of history. No interval-keyed detection can work on that: a beacon rule asking
for N callbacks at a regular interval over M minutes sees every callback at once.

- **`--pace {burst,plan}`.** `plan` reproduces the gaps the plan's own timeline holds,
  so a four hour beacon takes four hours. `burst` is the previous behaviour, kept
  because a file has no wall clock to reproduce.
- **The default follows the destination**: plan when sending to a collector, burst for
  `--to-file`. An operator who has never heard of the option still gets a stream.
- **`--speed N` compresses the timeline, event times included.** Compressing only the
  schedule would re-create the original defect at 1/60 scale, shipping events stamped
  238 minutes ahead and delivering them in four. Moving both keeps one invariant that
  holds at any speed: with `--pace plan --anchor now`, an event is sent at the moment
  its own timestamp says it happened. Verified over a real socket: a 14280 second plan
  at 1428x delivered 49 datagrams over 10.0 seconds carrying a 10 second event-time
  span, with **nothing future-dated**.
- **The cost is stated, not buried.** Compression preserves relative timing and changes
  absolute intervals, so a rule keyed on five minute gaps will not match a run
  compressed 60x. Real time to validate a rule, compressed for a smoke test.
- **`--rate` is unchanged and composes rather than competes.** It stays the flood guard
  and enters the schedule as a floor on spacing, so a plan holding several events in
  one second still cannot deliver them together. The two answer different questions and
  are kept apart in the UI.
- **The web form prices both options at once.** `POST /api/plan` builds the plan without
  running it, so each option carries its own duration (`Plan time 3h 58m` beside
  `Burst 0.2s`) with the consequence written underneath. Radio buttons rather than a
  dropdown, because a dropdown hides the alternative and the comparison is the point.
- Every run manifest now records `pace` and `speed` (safety rule 5): the same seed and
  technique can now put very different shapes on the wire.

Three things this work established, worth keeping:

1. **A default that is right for the product can still be wrong for the caller.** Making
   plan the default turned four test files into hangs, because a live-send test that
   was never about pacing inherited a 238 minute timeline. The fix was to make those
   tests name `pace="burst"`, which reads better than the silence it replaced.
2. **`eventtime` is integer epoch seconds, so one second is the finest gap a plan can
   express.** That is a real ceiling on compression, not a test artifact: past roughly
   the plan's own gap size, every event collapses into the same second. It also bounds
   how short an honest plan-paced integration test can be.
3. **A rate cap enforced only against a schedule is not enforced.** The first
   implementation computed each event's slot from a fixed baseline, so once real work
   ran late, consecutive events whose slots had both passed fired back to back and the
   cap became a number in a log line. It is now measured against the previous actual
   send.
4. **A default is a change to every caller that never named the value.** The
   installer's loopback verification runs `replicant run REP-001 --intensity low
   --host 127.0.0.1` to prove a socket works. It stopped being a smoke test and became
   a 238 minute wait, and two container jobs in CI sat on it until they were cancelled.
   Shipped, then found by running it, not by review: the local suite was green because
   the four *test* files that broke had already been fixed, and the script had no test.
   `tests/test_shipped_commands.py` now fails if any unattended script sends to a
   collector without naming a pace.
5. **Two guards can cancel each other out.** Adding that runtime floor then masked the
   catch-up check sitting beside it: once the loop ran late the floor set the deadline
   to roughly now, so a lag measured against that deadline read zero and never fired. A
   600ms stall was silently paid back by compressing the gaps that followed, which is
   the shape distortion plan pacing exists to prevent. Each guard was correct on its
   own, and the pair was not. Found by a test that stalls the emitter deliberately.

### Added: a light theme, and a responsive layout

The web UI was dark-only. A light palette existed in the stylesheet but it was the
stock shadcn slate, so the toggle worked and produced a theme that was not
Replicant's.

- **Warm paper, not cold white**, for the same reason the dark theme is warm graphite
  rather than blue-black. Contrast was **measured pair by pair against the dark
  theme's own ratios**, so light reads as the same instrument lit differently rather
  than as a second design.
- **The amber darkens to `#a04c03`.** The dark theme's `#f4b23e` is 1.9:1 on paper,
  and it is used as small text (the "emitting" chip, links in the Docs tab), so it
  needs 4.5:1, not the 3:1 a graphic needs. One `--signal` token, so the rule that
  amber means live signal survives intact.
- **First load follows `prefers-color-scheme`**; an explicit toggle is remembered and
  from then on beats the operating system. A pre-paint script applies the class
  before the bundle loads, so the page never flashes the wrong theme. That script
  cannot import the module holding the rule, so the rule exists twice, and a test
  extracts the script and asserts the two agree for every input.
- **Responsive below 1024px.** The fixed-viewport shell with independently scrolling
  panes is a desktop affordance; on a short screen it traps the run stage in a few
  hundred pixels. It becomes an ordinary scrolling page, the left rail becomes a
  disclosure labelled with the armed technique, the run controls reflow 5 columns to
  4 to 2, and the Docs sidebar becomes a horizontal strip.
- **The terminal follows the theme.** It hardcoded a blue-slate `#0b1120` that matched
  neither theme and would have been a black box on paper. It now resolves its colours
  from the stylesheet and recolours **in place**, because rebuilding it would tear
  down the websocket and kill the operator's running menu process.

### Fixed: contrast defects the audit found in the shipped dark theme

Three of the four were never light-theme bugs. The design spec claimed the tokens
were AA-verified, and they were; their **usage** never had been.

- **`--text-4` was body text in seven places, at 2.78:1**, against its own documented
  "decoration only, never body text" rule. At 9.5px a faint label reads as
  deliberately faint, which is why it survived. Moved to `--text-3`. Genuine
  decoration and the one disabled-control label stay put.
- **Near-white on the red fill is 3.02:1.** Latent rather than live: the only consumer
  is a Button variant nothing currently renders. Fixed so it is not waiting for
  whoever uses that variant first.
- **11 of xterm's 16 default ANSI colours fail on the light card, 6 of 16 on the dark
  one.** The embedded Rich menu was partly illegible before light mode existed. Two
  measured palettes now. ANSI `black` stays low-contrast in dark by design: it is the
  background-adjacent slot programs use for fills, not for text.
- **The page scrolled sideways to 3452px at 375px wide.** A CSS grid item defaults to
  `min-width: auto` and will not shrink below its content, so one 3376px CEF sample
  line inside an `overflow-x-auto` stretched the whole column track instead of
  scrolling inside its own box.
- **The vendor picker's middle segment overflowed.** Three equal segments in a 336px
  rail leave about 92px each, and "Palo Alto (PAN-OS)" wrapped to two lines and spilled
  out of its 28px-tall button. Width-constrained controls now use a short label
  (`PAN-OS`); prose keeps the full name, where there is room and it is clearer.

### Changed: CI actions moved off the deprecated Node 20 runtime

Every job carried a deprecation warning. `actions/checkout@v4`, `actions/setup-python@v5`
and `actions/setup-node@v4` all declare `using: node20`, which the runners deprecated and
were already overriding to Node 24. Pinned to the current majors, `v7` for all three, each
of which declares `using: node24` in its own `action.yml`.

Pinned at the current major rather than the floor. The first Node 24 majors are checkout
v5, setup-python v6 and setup-node v5, so pinning there would clear the warning and leave
two majors of drift to redo. The breaking changes between were checked against this
workflow rather than assumed: checkout v7 blocks fork checkouts for `pull_request_target`
and `workflow_run`, neither of which this workflow uses; setup-python v7 removes the
`pip-install` input, which was never set; setup-node v5 added automatic caching keyed on a
`packageManager` field, and `webui/package.json` has none, no root `package.json` exists,
and `cache: npm` is passed explicitly anyway.

All three require runner v2.327.1 or newer. Every job is `runs-on: ubuntu-latest`, so that
is satisfied by GitHub-hosted runners. A self-hosted runner would need checking.

### Changed: CI no longer runs for a commit it cannot be affected by

A documentation commit queued all ten jobs, including three installer containers and a
wheel build that no prose can change. `push` and `pull_request` now carry a `paths`
filter that skips prose: markdown anywhere, `docs/`, `tasks/`, `LICENSE` and `NOTICE`.
Measured against the last 112 non-merge commits, 34 of them would have skipped the
matrix. `workflow_dispatch` stays unfiltered and forces a full run on any ref.

The filter defaults to running (`"**"` first, exclusions after), so a new kind of file
fails safe rather than silently skipping the gate. Five files under `docs/` are
re-included because they are executable in practice, not prose: the three vendor CEF
references are the golden-line oracle that `tests/test_*_golden.py` parse, and
`tests/test_web_docs.py` asserts all five exist on disk.

`tests/test_ci_paths_filter.py` guards both halves of that. It asserts the `push` and
`pull_request` lists stay identical, that load-bearing paths still trigger, and that
every page in `DOC_PAGES` is re-included, deriving the list from `DOC_PAGES` rather
than repeating it so a new Docs tab page fails the test until the workflow covers it.
The lists are written out twice on purpose: a YAML anchor would say it once, but
GitHub Actions does not support anchors while PyYAML does, so the guard would have
resolved the alias and passed against a workflow GitHub rejected.

### Added: a Logs tab, and logging for it to show

Replicant had no logging. Not a quiet logger, none: `grep -rn "import logging"` over
the package returned nothing. That went unnoticed until the first live LogRhythm test,
where a run reported **921 events per second sent** while the collector received
nothing, and the tool could say no more than that.

It was not lying. For UDP, `sendto` reports that the kernel accepted a datagram, not
that anything received it, so "sent" was the strongest honest claim in the code. The
fix is to record the things that distinguish the cases.

- **`replicant/obs/log.py`**: stdlib logging plus a bounded in-memory ring buffer.
  Four modes, matching the four an operator asked for: `debug`, `verbose`, `info`,
  `warning`. VERBOSE is a custom level at 15, between DEBUG and INFO, because a line
  per datagram is higher volume than a diagnostic and lower value than a warning.
- **Instrumentation that answers the question that prompted it**: the resolved
  destination and transport at connect; the framed byte count per send; cumulative
  sends, bytes, errors and oversize counts; a once-per-second throughput line; and the
  burst width when the rate cap fires, which is the part an events-per-second figure
  hides.
- **Two warnings that name a cause rather than a symptom.** A datagram above 1472
  bytes will fragment, and fragments are dropped by more collectors and middleboxes
  than most people expect, which is a common reason a short connect test arrives and
  full CEF lines do not. And an event time more than two days from now while the
  syslog header is stamped now, which makes events look absent rather than late on a
  SIEM keying on parsed event time.
- **`GET /api/logs`, `GET /api/logs/stream`, `PUT /api/logs/level`**, behind the same
  token guard as everything else, plus a Logs tab with the mode selector, pause,
  copy and follow-tail.

Three deliberate constraints:

1. **Nothing here performs I/O beyond memory.** Safety rule 1 says the only egress is
   the operator's collector, so records live in this process and are read back over
   the existing localhost API.
2. **`propagate` is off.** Under systemd stdout is the journal. This project has
   already leaked the web token that way once; a logger defaulting to writing every
   record there would be the same mistake twice.
3. **Redaction happens on write, not on render.** A record scrubbed at display time is
   still sitting in memory in the clear for every other reader. `test_web_logs.py`
   asserts the token cannot be read back through the API.

`SyslogEmitter.send` now returns the framed byte count instead of `None`, and a failed
send is counted and reported before being re-raised rather than passing silently.

### Notes

The eps signal readout was verified mid-run against a real loopback collector, since
a run with no collector is unthrottled and finishes too fast to observe. Over 108000
events the readout matched the collector exactly at 2000 events per second, and
delivery was exact with no UDP loss.

`scripts/capture-webui-screenshots.py` gained `--theme` and `--views`. The theme is now
**pinned and asserted** rather than inherited: the UI follows `prefers-color-scheme`,
headless Chrome reports light, so the script would otherwise have quietly re-themed
every committed screenshot the first time it ran after this change. The README's
screenshots were regenerated, which also picked up the contrast fixes above.

89 frontend tests (68 before). No backend change: 526 Python tests unchanged.

## [0.3.1] - 2026-07-29

A packaging fix. Nothing changes for anyone running from a git clone, which is how
0.3.0 was tested and how CI runs. Everything in 0.3.0 still applies.

### Fixed: a wheel install produced a tool that could not run

`pip install` of the 0.3.0 artifact succeeded and `replicant --version` printed
`0.3.0`. Every other command then failed with `catalog not found`, and the web UI
served its "build the frontend" placeholder instead of the real interface.

Everything Replicant needs at run time lived **outside** the package and was reached
by repository-relative paths. `pyproject.toml` packages `replicant*` and there is no
`MANIFEST.in`, so the wheel contained 40 entries: the Python modules and `py.typed`,
no catalogs and no built frontend. It was also dependent on the working directory,
because the CLI fell back to `Path.cwd()`. That is why it went unnoticed. From a
checkout it worked and from anywhere else it did not, and every test imports from the
source tree, so the suite stayed green while the artifact was unusable.

- `data/` moved to `replicant/data/`, and the frontend build output moved to
  `replicant/webui_dist/` (vite `outDir`). Both now sit inside the package.
- `replicant/resources.py` is the single place that knows where runtime files live.
  Anything resolving a repository-relative path is now a defect.
- `package-data` covers the catalogs, the built UI, and its fonts.
- Catalog resolution prefers the packaged copy over working-directory guesses, so
  behaviour no longer depends on where you stand. An explicit `catalog_path` setting
  still wins.
- `docs/` is deliberately **not** packaged. It is documentation, it is large, and a
  second copy inside the package would drift from the first.

This closes the "the built wheel is not yet self-contained" limitation recorded
under 0.1.0.

### Added: guards, because unit tests structurally could not catch this

- `tests/test_packaging.py` asserts that runtime files resolve inside the package,
  that `package-data` actually covers them (moving a file and leaving the glob
  behind produces the same broken wheel), and that the catalog resolves from an
  empty working directory.
- A `wheel` CI job builds the frontend, builds a wheel, installs it into a clean
  virtualenv, and runs it from an unrelated directory. A test that imports from the
  source tree cannot fail the way a wheel fails, so the check lives where the
  consequence lands.
- The version is asserted to be single-sourced: `replicant.__version__` and the
  `version` in `pyproject.toml` have to agree. They are two files that must say the
  same thing, which is the same drift risk in miniature.

Verified from a clean virtualenv outside the repository, in a directory containing
no `data/`: `replicant list` shows 24 techniques, a run writes 36000 CEF lines,
`replicant scenario list` works, and the web UI serves the real single-page app.

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

[0.9.0]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.9.0
[0.8.0]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.8.0
[0.7.0]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.7.0
[0.6.1]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.6.1
[0.6.0]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.6.0
[0.5.2]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.5.2
[0.5.1]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.5.1
[0.5.0]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.5.0
[0.4.0]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.4.0
[0.3.1]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.3.1
[0.3.0]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.3.0
[0.2.0]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.2.0
[0.1.0]: https://github.com/404SecNotFound/Replicant/releases/tag/v0.1.0
