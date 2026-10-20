# Lab test runbook: Replicant into a live LogRhythm

**Purpose.** Turn the oldest open item in the project into evidence. Replicant has
never sent one event to a real SIEM; every timing and delivery claim is
loopback-only. This runbook is the copy-pasteable sequence to change that.

**Relationship to the UAT plan.** This does not replace `tasks/uat-plan.md`
Suites H and I; it operationalises them. Each phase below names the SIEM-nn /
TF-nn cases it produces evidence for. The UAT plan is the register of record;
paste your findings back into its Result column.

**What changed since the plan was written.** Three defects fixed on 2026-08-31
(`claude/replicant-validation-platform-h52f7k`) make three previously-awkward
cases into clean measurements:

- **Run id** in every manifest, and on the wire with `--mark-synthetic`. This is
  how SIEM-13 (manifest reconciles with what arrived) stops being an eyeballed
  time-window guess.
- **`--mark-synthetic`** stamps `flexString1=RUN-...` on every line, so a full-text
  search in LogRhythm isolates exactly this run's events (SIEM-01, SIEM-13) and
  labels the data synthetic (SIEM-12).
- **`--controls {positive,negative}`** emits the attack alone or the benign foil
  alone, which is precisely SIEM-08 (a detection fires) vs SIEM-09 (its benign
  baseline does not).

**One caution, stated up front.** The marker adds a non-standard CEF extension
field (`flexString1`). The parsing and field-mapping cases (SIEM-02/03/04/10) must
be run **without** the marker, against the reference the FortiGate MPE expects.
Since v0.10.0 a send to a non-loopback collector is marked **by default**, so
leaving out `--mark-synthetic` no longer leaves a line unmarked: the parsing
commands below pass `--no-marker`. Use the marker for the count and detection
phases. If the marker itself changes how LogRhythm parses a line, that is itself a
finding worth recording.

**Implementation note (2026-10-19).** This runbook was written on 2026-09-06 and
had drifted from the code. Every offline command in section 0 was re-run on
`main` at `1c1a2d3` with an isolated `REPLICANT_CONFIG_DIR`, and the lab commands
were checked against the plans they produce. What changed:

- **Marker default.** As above: the parsing phases now pass `--no-marker`.
- **Run length.** A send to a collector defaults to `--pace plan`, so an event
  leaves when its own timestamp says it happened. REP-001 spans 240 minutes at low
  and at medium, so each Phase 1 to 5 command as written took about four hours,
  and the whole runbook more than a day. Every command outside Phase 6 now carries
  `--duration`, which shortens the span and keeps the interval (the property a
  cadence rule reads), so the event count falls instead.
- **Foils.** 26 of 31 techniques emit a benign foil, REP-001 included (and
  REP-001 already did when this runbook was written), so the pilot pair in Phase
  4 is REP-001 attack, then REP-001 foil.
- **Signature IDs.** Phase 1.3 ran REP-007 at low, which emits only the confirmed
  39426 (`ssl-login-fail`); 39947 appears in REP-007 only at high, once. Two more
  `[Unverified]` IDs exist since 2026-10-07 (32001, 44547). Phase 1.3 now names
  a short run that emits each.
- **New since the runbook:** the per-run validation card (`<manifest>.card.md`)
  prints the pivot and the emitted window to search on; `replicant validate`
  checks the plan offline; inbound records (REP-021, REP-043's inbound stage,
  REP-053) render with reversed zones and interfaces on every vendor since
  2026-10-19.

---

## 0. Before you touch the lab (offline pre-flight)

Run these on the Replicant host. They cost nothing and catch the embarrassing
failures before a lab window is burning.

```bash
# The build runs and the catalog loads.
replicant --version
replicant list | head -20

# The generator contract holds offline (Tier 0; proves nothing about a SIEM).
replicant validate REP-001 --tier plan

# The marker: forced on for a file, off by default for a file.
replicant run REP-001 --intensity low --no-send --mark-synthetic --to-file /tmp/pf-mark.log
grep -c 'flexString1Label=ReplicantSynthetic' /tmp/pf-mark.log      # expect: all lines (98)
grep -o 'flexString1=RUN-[0-9A-Za-z-]*' /tmp/pf-mark.log | sort -u  # expect: one run id
replicant run REP-001 --intensity low --no-send --to-file /tmp/pf-plain.log
grep -c 'flexString1' /tmp/pf-plain.log                             # expect: 0

# The Phase 4 pilot pair, rehearsed offline with the same bounded window.
replicant run REP-001 --intensity medium --duration 15m --no-send --controls both     --to-file /tmp/pf-both.log
replicant run REP-001 --intensity medium --duration 15m --no-send --controls positive --to-file /tmp/pf-pos.log
replicant run REP-001 --intensity medium --duration 15m --no-send --controls negative --to-file /tmp/pf-neg.log
wc -l /tmp/pf-both.log /tmp/pf-pos.log /tmp/pf-neg.log   # both == pos + neg (measured 32 = 16 + 16)
```

Pre-flight passes when: `validate` reports pass, the marked file carries one run
id on every line and the plain file none, and the control counts add up. If they
do not, stop here; nothing in the lab will be interpretable. Each run prints its
manifest and validation card path; the card is what Phase 4 searches on.

---

## Lab prerequisites (from Suite H entry criteria)

- A LogRhythm deployment you control and are authorised to send test data into.
  Suite H writes synthetic events into a real store; they are indistinguishable
  from production to anyone who did not run the test, so this must be a lab, not
  a shared or production estate.
- A syslog collector reachable from the Replicant host. Note its IP; it is
  `<COLLECTOR>` below.
- Ability to search ingested events and inspect the assigned log source and MPE
  policy in the LogRhythm console.
- `tcpdump` on the Replicant host for the safety and timing captures.
- An operator-owned LogRhythm AIE rule or alarm corresponding to UC-001. The lab
  owner authors or enables it from `docs/detection-specs/REP-001.md` before the
  detection phases. Replicant does not generate, install, or tune AIE content. If
  no matching rule is available, parsing can still be measured, but the detection
  gate remains blocked.

**Run length.** Sending defaults to `--pace plan`: events leave on the plan's own
timeline, which is what makes timing measurable and what makes an unbounded
REP-001 run take four hours. Every command below outside Phase 6 carries
`--duration`; Phase 6 is the one place a long run is the point.

Set once, for every command below:

```bash
COLLECTOR=10.20.0.50     # your lab collector IP
PORT=514
```

## Using the web UI during the lab  (added 2026-10-20)

Every phase below is driven from the CLI, and stays that way: two of the switches
the phases depend on do not exist in the web run form. The web UI (the operations
console since 2026-10-19, `docs/webui-silver-red-design.md`) is still useful beside
the CLI, as a reader and as a connectivity check.

**What the web UI cannot do, so these phases must use the CLI:**

- **Phase 1 (unmarked parsing).** A web run has no `--no-marker`. The marker
  follows the destination, so a web run to a non-loopback collector always carries
  `flexString1`, which is exactly what SIEM-02/03/04/10 must not see.
- **Phase 4 (`--controls`).** A web run has no `--controls` and always emits both
  streams, the attack and its benign foil. SIEM-08 and SIEM-09 need each stream
  alone.
- **The send slot is shared.** A web run and a CLI run that send to a collector
  under the same `REPLICANT_CONFIG_DIR` cannot run at the same time; the second is
  refused. Finish or stop one before starting the other.

**Where it helps:**

- **Phase 0.1, connectivity.** The **Collector** tab's *Send test log* runs the same
  probe as `replicant connect --test` and prints the source, route and destination
  beside its result. As with the CLI, a UDP send that reports no error still does
  not prove arrival; only the LogRhythm search does.
- **Phase 1.2 and Phase 3, reading what left.** After a web run, the run
  workspace's **Wire** view lists the streamed events and dissects the selected
  line into syslog prefix, CEF header and extension fields, with the profile's held
  keys marked, and shows the same line as bytes. Use it to read the exact field
  values and the `flexString1` run id of a marked run, then search LogRhythm for
  that id. It only shows runs started from that browser, and it is parsed from the
  emitted line, so it says what Replicant sent, never what LogRhythm received.
- **Choosing what to test.** The **Coverage** tab's dossier for each technique
  lists the held and varied fields on the selected profile and the benign baseline,
  which is the field list a rule should key on and the foil it must not fire on.

The banner on every screen reads `detection unverified`. That stays true until
Phase 4.1 produces the first observed rule fire.

---

## Phase 0 — Connectivity and clock

**Do this first. Everything downstream is meaningless if the clock is off.**

### 0.1 One benign line arrives  (SIEM-01)

```bash
replicant connect --host "$COLLECTOR" --port "$PORT" --transport udp --test
```

Expect exactly **one** benign `traffic:forward accept` line searchable in
LogRhythm. Record the ingestion lag. Zero means it never arrived; several means
something is wrong with the test path.

> The connect test proves a route exists. It does **not** prove parsing. The word
> "verified" was removed from this project for exactly that reason: a UDP `sendto`
> succeeding only means a route exists. Read the source-beside-destination output
> the command prints; do not treat a clean send as a green light for anything below.

### 0.2 Host clock offset  (TF-08)

```bash
# On the Replicant host AND the LogRhythm host, within the same few seconds:
date -u +%s
timedatectl | sed -n '1,4p'   # or: chronyc tracking
```

Offset must be under 2s. A ~19-minute offset was seen once and never explained; if
it reproduces, fix NTP before continuing and subtract the measured offset from
every timing reading in Phase 2 and Suite I.

---

## Phase 1 — Identity and parsing  (unmarked, FortiGate)

Run **without** `--mark-synthetic` so LogRhythm sees exactly what the FortiGate MPE
expects.

### 1.1 Log source is FortiGate, and the MPE parses  (SIEM-02, SIEM-03)

```bash
replicant run REP-001 --intensity low --anchor now --duration 15m --no-marker \
  --host "$COLLECTOR" --port "$PORT" --transport udp
```

- SIEM-02: the log source must resolve as a **Fortinet FortiGate** syslog source,
  not Unknown and not a generic catch-all. Record the exact log source type and
  MPE policy. Unknown is a High defect: the framing does not look like FortiGate.
- SIEM-03: the message must be **parsed and classified**, not shelved as
  Unidentified. Record the Common Event. Ingested-but-unparsed is a fail: it is
  invisible to every rule that keys on a field.

### 1.2 Field mapping matches the oracle  (SIEM-04)

Compare LogRhythm's parsed metadata for the REP-001 events, **field by field**,
against the table in `docs/fortigate-cef-reference.md`: src/dst IP, src/dst port,
protocol, action, bytes in/out, device identity. Any mismatch is a defect against
the reference doc; record which side is wrong before changing either. REP-001 is
egress. An inbound technique (REP-021, REP-043's inbound stage, REP-053) carries
the reversed interface pair, and on PAN-OS and Check Point the reversed zones,
since 2026-10-19; compare those against the inbound notes in each vendor
reference, not the egress table.

### 1.3 Resolve the `[Unverified]` signature IDs  (SIEM-10)

```bash
NM="--anchor now --no-marker --host $COLLECTOR --port $PORT"
replicant run REP-004 --intensity low --duration 1m $NM  # dns-query 54803 (about 2,400 lines)
replicant run REP-011 --intensity low --duration 2m $NM  # event:vpn tunnel-up 39947 (2 lines)
replicant run REP-028 --intensity low --duration 5m $NM  # event:system login success 32001, config change 44547
replicant run REP-007 --intensity low --duration 2m $NM  # control: login-fail 39426 (confirmed)
```

Read what the parser makes of signatures **54803**, **39947**, **32001** and
**44547**. Either the parser accepts them (the `[Unverified]` markers on
`LOGID_DNS_QUERY`, `LOGID_VPN_SUCCESS`, `LOGID_EVENT_SYSTEM_LOGIN_SUCCESS` and the
config-change logid in `replicant/profiles/fortigate.py` come off) or it does not
(record the correct values and correct the code, the reference doc and the
CHANGELOG together). 54802 and 39426 are already confirmed and serve as the
control. Until 2026-10-19 this step ran REP-007 at low for 39947, which REP-007
emits only at high.

---

## Phase 2 — Event time  (the reason this suite exists)

### 2.1 `--anchor now` yields a current event time  (SIEM-05)

```bash
replicant run REP-001 --intensity low --duration 15m --no-marker --anchor now --host "$COLLECTOR" --port "$PORT"   # then, for contrast:
replicant run REP-001 --intensity low --duration 15m --no-marker              --host "$COLLECTOR" --port "$PORT"   # default fixed anchor
```

With `--anchor now`: event time within minutes of receipt. With the default:
event time roughly a year in the past. **This is the case the whole suite exists
for.** That exact condition once made every recent-window rule silent, which is
indistinguishable from a detection that does not work.

### 2.2 The stale-anchor warning prints before sending  (SIEM-06)

The default-anchor run above must print the stale-anchor warning **before** any
event leaves the host (`STALE_ANCHOR_DAYS = 2`). A warning after the fact does not
count.

---

## Phase 3 — Count reconciliation  (uses the run id + marker)

This is where defect 1 and defect 2 pay off. Before, reconciling the manifest
against the SIEM meant guessing a time window. Now the run labels itself.

```bash
replicant run REP-001 --intensity low --duration 15m --anchor now --mark-synthetic \
  --host "$COLLECTOR" --port "$PORT" --transport udp
```

`--mark-synthetic` is the default for this send and is kept explicit. The CLI
prints the run id (`run id : RUN-...`), the manifest path and the validation card
path, and writes the run id into the manifest filename. In LogRhythm, full-text search the raw message for that exact run id
string.

- **SIEM-01 / SIEM-13:** the count of events carrying this run id must equal the
  manifest's `event_count` for the window. A shortfall is loss (revisit Phase 5
  rate); an excess means the search caught something else.
- **SIEM-12:** every matched event's src/dst must be RFC1918 or a documentation
  range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), and every domain string
  must stay under an IANA documentation domain or `.invalid`. Documentation
  domains can resolve; Replicant must perform no DNS lookup or connection to
  any emitted name.

> If the FortiGate MPE does not map `flexString1` into a named, searchable field,
> full-text search the raw log for the `RUN-` string instead. Whether the marker
> lands in a named field is itself worth recording for SIEM-03.

---

## Phase 4 — Does the detection work?  (uses `--controls`)

Pick a technique whose `ndr_uc` maps to a rule that exists in your lab
(`replicant list` prints the mapping; e.g. UC-001 for REP-001). This phase is the
product's entire reason for existing. For the REP-001 pilot, the lab owner must
have implemented or enabled the AIE rule from `docs/detection-specs/REP-001.md`
before starting this phase. That rule remains lab-owned detection content, not an
artifact Replicant generates or tunes.

### 4.1 The attack fires the rule  (SIEM-08)

```bash
replicant run REP-001 --intensity medium --duration 15m --anchor now --controls positive \
  --host "$COLLECTOR" --port "$PORT" --transport udp
```

`--duration 15m` keeps REP-001's real 60 s cadence and emits about 16 callbacks
(measured: 16), above the reference spec's `min_callbacks = 8`; the spec states
that a run shorter than the full window still fires. Search on the `(src, dst,
dpt)` pivot and the emitted window the run's validation card prints.

> [Inference] The reference spec's own example uses `--pace plan --speed 60` at
> medium, which divides the 60 s interval to about 1 s. Event times are whole
> seconds, so at that compression the cadence is quantised and an inter-arrival
> CV rule may not behave as it does at the real interval. `--duration` avoids the
> question. Whether to change the spec's example is the spec author's call.

`--controls positive` sends the attack pattern **without** its benign foil, so a
rule that fires here is firing on the signal and not on the foil. Record the
technique, rule, intensity, and time to alarm.

### 4.2 The benign foil does NOT fire it  (SIEM-09)

```bash
replicant run REP-001 --intensity medium --duration 15m --anchor now --controls negative \
  --host "$COLLECTOR" --port "$PORT" --transport udp
```

`--controls negative` sends **only** the benign foil. The rule must stay quiet. A
rule that fires on both 4.1 and 4.2 has a false-positive problem the lab should
know about; that is a finding about the rule, not about Replicant.

> 26 of the 31 techniques emit a negative stream, REP-001 included (a
> same-count, same-window irregular callback foil). The five without one are
> REP-008, REP-011, REP-017, REP-020 and REP-021; REP-008 and REP-020 embed their
> history in the positive stream instead. REP-006 and REP-007 carry the structural
> foils (shared-IP fan-out, NAT source-collapse) that break the aggregation key.
> Asking for the negative stream on a foil-less technique emits nothing and the
> CLI says so. (Until 2026-10-19 this note listed twelve and said REP-001 had no
> foil. The catalog already marked REP-001 `emits_foil: true` on 2026-08-31, before
> this runbook was written, so the note was wrong from the start, not only stale.)

---

## Phase 5 — Safety, against real infrastructure  (SIEM-11, SIEM-12)

```bash
# In one terminal, capture the sending host for the duration of a run:
sudo tcpdump -n -i any host "$COLLECTOR" or not "$COLLECTOR" -w /tmp/replicant-egress.pcap &
# In another, run:
replicant run REP-001 --intensity low --duration 5m --anchor now --host "$COLLECTOR" --port "$PORT"
# Stop tcpdump, then inspect:
tcpdump -n -r /tmp/replicant-egress.pcap 'not host '"$COLLECTOR"' and not arp' | head
```

- **SIEM-11:** traffic to the configured collector only. No DNS resolution of the
  synthetic domains, no connection to any documentation-range address, no
  telemetry anywhere. Safety rule 1 tested against real infrastructure.
- **SIEM-12:** covered in Phase 3; confirm again here from the capture.

---

## Phase 6 — Timing fidelity  (Suite I, after Phase 1-3 pass)

Only meaningful once ingestion and parsing work. The headline cases:

```bash
# TF-01 control: burst reproduces the pre-v0.4.0 defect on the wire.
sudo tcpdump -tt -n -i any host "$COLLECTOR" -w /tmp/tf01.pcap &
replicant run REP-001 --intensity low --anchor now --pace burst --host "$COLLECTOR" --port "$PORT"

# TF-02: plan pacing delivers a stream. About 240 min, gaps track the plan.
# This is the one deliberately long run in the runbook.
replicant run REP-001 --intensity low --anchor now --pace plan  --host "$COLLECTOR" --port "$PORT"

# TF-05: speed compresses event times too, not just the schedule.
replicant run REP-001 --intensity low --anchor now --pace plan --speed 60 --host "$COLLECTOR" --port "$PORT"
```

- **TF-04 (core invariant):** every parsed event time stays within the Phase-0
  clock offset of its ingestion time. No event is ever stamped in the future.
- **TF-11 (the payoff):** an interval-keyed AIE rule fires on the plan-paced run
  (TF-02) and does **not** fire on the burst run (TF-01). This is the single case
  that justifies plan-timed pacing. The lab owner supplies this rule from the
  REP-001 reference spec; Replicant supplies only the synthetic telemetry.

Full case list, expected values and the scenario-duration cases (TF-06..TF-10):
`tasks/uat-plan.md` Suite I.

---

## What to bring back

For each case, record in the UAT plan's Result column: pass/fail, the exact values
observed (log source type, MPE policy, Common Event, field mismatches, ingestion
lag, alarm time), and the run id, so the run is reproducible from its manifest.

The three results that matter most, in order:

1. **SIEM-03** — does the FortiGate MPE parse the line at all. Everything keys on it.
2. **SIEM-05 / TF-04** — is the event time right on a live send. This is the bug
   the whole project has been unable to rule out.
3. **SIEM-08 + SIEM-09** — does a real detection fire on the attack and stay quiet
   on the foil. This is the product working, or not.

A failure at SIEM-03 makes everything after it unattributable, so stop and fix the
log-source/parsing setup before reading any later result. A pass through SIEM-08
and SIEM-09 is the first end-to-end evidence in this project's history that a
synthetic-telemetry-driven detection test does what it claims.

## What this runbook does not do

It cannot be executed from here; it needs the lab. It also cannot tell you whether
your LogRhythm rules are any good — SIEM-08/09 measure your detection content, and
a rule that fires on the foil is a finding about the rule. Replicant's job ends at
putting correct, labelled, correctly-timed telemetry on the wire; this runbook is
how you confirm it does, and hands the rest to the detection engineer.
