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
Introduce the marker only for the count and detection phases. If the marker itself
changes how LogRhythm parses a line, that is itself a finding worth recording.

---

## 0. Before you touch the lab (offline pre-flight)

Run these on the Replicant host. They cost nothing and catch the embarrassing
failures before a lab window is burning.

```bash
# The build runs and the catalog loads.
replicant --version
replicant list | head -20

# The three new capabilities actually work, offline, to a file.
replicant run REP-001 --intensity low --no-send --mark-synthetic --to-file /tmp/pf-mark.log
grep -c 'flexString1Label=ReplicantSynthetic' /tmp/pf-mark.log      # expect: all lines
grep -o 'flexString1=RUN-[0-9A-Za-z-]*' /tmp/pf-mark.log | sort -u  # expect: one run id

replicant run REP-014 --intensity medium --no-send --controls both     --to-file /tmp/pf-both.log
replicant run REP-014 --intensity medium --no-send --controls positive --to-file /tmp/pf-pos.log
replicant run REP-014 --intensity medium --no-send --controls negative --to-file /tmp/pf-neg.log
wc -l /tmp/pf-both.log /tmp/pf-pos.log /tmp/pf-neg.log   # both == pos + neg
```

Pre-flight passes when: the marked file carries one run id on every line, and the
control counts add up. If they do not, stop here; nothing in the lab will be
interpretable.

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

Set once, for every command below:

```bash
COLLECTOR=10.20.0.50     # your lab collector IP
PORT=514
```

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
replicant run REP-001 --intensity low --anchor now \
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
the reference doc; record which side is wrong before changing either.

### 1.3 Resolve the two `[Unverified]` signature IDs  (SIEM-10)

```bash
replicant run REP-004 --intensity low --anchor now --host "$COLLECTOR" --port "$PORT"  # dns-query 54803
replicant run REP-007 --intensity low --anchor now --host "$COLLECTOR" --port "$PORT"  # event:vpn 39947 (tunnel-up)
```

Read what the parser makes of signature **54803** and **39947**. Either the parser
accepts them (the `[Unverified]` markers in `replicant/profiles/fortigate.py`
around lines 53/55 come off) or it does not (record the correct values and correct
the code, the reference doc and the CHANGELOG together). 54802 and 39426 are
already confirmed and serve as the control.

---

## Phase 2 — Event time  (the reason this suite exists)

### 2.1 `--anchor now` yields a current event time  (SIEM-05)

```bash
replicant run REP-001 --intensity low --anchor now --host "$COLLECTOR" --port "$PORT"   # then, for contrast:
replicant run REP-001 --intensity low             --host "$COLLECTOR" --port "$PORT"    # default fixed anchor
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
replicant run REP-001 --intensity low --anchor now --mark-synthetic \
  --host "$COLLECTOR" --port "$PORT" --transport udp
```

The CLI prints the run id (`run id : RUN-...`) and writes it into the manifest
filename. In LogRhythm, full-text search the raw message for that exact run id
string.

- **SIEM-01 / SIEM-13:** the count of events carrying this run id must equal the
  manifest's `event_count` for the window. A shortfall is loss (revisit Phase 5
  rate); an excess means the search caught something else.
- **SIEM-12:** every matched event's src/dst must be RFC1918 or documentation
  range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), and any domain under an
  IANA documentation domain or `.invalid`. Nothing routable, nothing real.

> If the FortiGate MPE does not map `flexString1` into a named, searchable field,
> full-text search the raw log for the `RUN-` string instead. Whether the marker
> lands in a named field is itself worth recording for SIEM-03.

---

## Phase 4 — Does the detection work?  (uses `--controls`)

Pick a technique whose `ndr_uc` maps to a rule that exists in your lab
(`replicant list` prints the mapping; e.g. UC-001 for REP-001). This phase is the
product's entire reason for existing.

### 4.1 The attack fires the rule  (SIEM-08)

```bash
replicant run REP-001 --intensity medium --anchor now --controls positive \
  --host "$COLLECTOR" --port "$PORT" --transport udp
```

`--controls positive` sends the attack pattern **without** its benign foil, so a
rule that fires here is firing on the signal and not on the foil. Record the
technique, rule, intensity, and time to alarm.

### 4.2 The benign foil does NOT fire it  (SIEM-09)

```bash
replicant run REP-001 --intensity medium --anchor now --controls negative \
  --host "$COLLECTOR" --port "$PORT" --transport udp
```

`--controls negative` sends **only** the benign foil. The rule must stay quiet. A
rule that fires on both 4.1 and 4.2 has a false-positive problem the lab should
know about; that is a finding about the rule, not about Replicant.

> Only the ten techniques with `emits_foil` (REP-012, 013, 014, 015, 016, 018,
> 019, 022, 023, 024) have a negative stream. REP-001 does **not** — for 4.2, use
> one of those ten whose UC maps to a lab rule, or run REP-001's baseline peer per
> the SIEM-09 note in the UAT plan. Asking for the negative stream on a foil-less
> technique emits nothing and the CLI says so.

---

## Phase 5 — Safety, against real infrastructure  (SIEM-11, SIEM-12)

```bash
# In one terminal, capture the sending host for the duration of a run:
sudo tcpdump -n -i any host "$COLLECTOR" or not "$COLLECTOR" -w /tmp/replicant-egress.pcap &
# In another, run:
replicant run REP-001 --intensity low --anchor now --host "$COLLECTOR" --port "$PORT"
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

# TF-02: plan pacing delivers a stream. ~238 min, gaps track the plan.
replicant run REP-001 --intensity low --anchor now --pace plan  --host "$COLLECTOR" --port "$PORT"

# TF-05: speed compresses event times too, not just the schedule.
replicant run REP-001 --intensity low --anchor now --pace plan --speed 60 --host "$COLLECTOR" --port "$PORT"
```

- **TF-04 (core invariant):** every parsed event time stays within the Phase-0
  clock offset of its ingestion time. No event is ever stamped in the future.
- **TF-11 (the payoff):** an interval-keyed AIE rule fires on the plan-paced run
  (TF-02) and does **not** fire on the burst run (TF-01). This is the single case
  that justifies plan-timed pacing.

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
