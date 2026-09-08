# Offline detection validation

Replicant can evaluate its generated telemetry before a SIEM is available. The
offline track has two tiers with deliberately narrow claims:

| Tier | Command | What it proves | What it does not prove |
|---|---|---|---|
| Tier 0, plan | `replicant validate REP-001 --tier plan` | The deterministic plan satisfies the packaged contract for event families, signal fields, measurable axes, completeness, and declared control mode. | Collector receipt, parsing outside Replicant, or a detection alert. |
| Tier 1, ingest | `replicant validate REP-001 --tier ingest` | The real UDP or TCP emitter delivered the expected run-tagged records to Replicant's loopback receiver and the selected profile's required fields parsed back. | A live SIEM accepted the source, applied a parser, or fired a rule. |

Neither tier executes an attack. Both generate and inspect log records only.
Tier 1 binds only to `127.0.0.1`; it does not create a second network-egress
path. Live collector and detection validation remain manual, lab-gated work.

## Contract registry

`replicant/data/detection-contracts.yaml` contains one entry for each of the 26
catalog techniques. It declares validation semantics that are not already owned
by the technique catalog:

- observation-window derivation;
- deterministic measurable axes;
- negative-control mode and intended discriminator.

At load time, `replicant.validation.contract.load_contracts` resolves event
families, held and varied signal fields, preset values, foil presence, and
transferability from `technique-catalog.yaml`. Loading fails if coverage is not
exactly one contract per technique, a referenced preset key is absent, a signal
field is undeclared, or standalone-control mode disagrees with `emits_foil`.
This keeps the technique catalog as the source of truth.

The negative-control modes are:

- `standalone`: positive and negative streams can be selected separately;
- `embedded`: required history is part of the positive plan;
- `calibration`: the technique is a benign calibration stream;
- `unsupported`: Replicant cannot represent a credible control with its
  synthetic firewall telemetry.

REP-011 is explicitly `unsupported`. A credible geovelocity control depends on
observed GeoIP or ASN enrichment plus approved-travel context. Documentation
range addresses and supplied country strings cannot exercise that dependency,
so Replicant does not emit a weak foil.

## Tier 0 evaluation

The plan evaluator is deterministic and performs no file, clock, or network
I/O. It checks the positive stream, declared event families, signal-field
presence, preset completeness, standalone-control presence, and the contract's
measurable axes. The negative-control suite separately checks matched irrelevant
distributions and intended discriminators across all intensities and multiple
seeds.

Examples:

```bash
replicant validate show REP-005
replicant validate REP-005 --tier plan --intensity high
```

A Tier 0 `pass` means only that the plan satisfied this packaged generator
contract. It is not an observed delivery or alert result.

## Tier 1 ingestion

Tier 1 starts a minimal loopback UDP or TCP syslog receiver, emits the same plan
through `SyslogEmitter`, reads the captured file through `FileLogSource`, and
compares:

- the exact expected and observed run-tagged record counts;
- the synthetic run marker;
- required selected-profile native fields that can be mapped from the contract.

```bash
replicant validate REP-003 --tier ingest --transport udp
replicant validate REP-003 --tier ingest --transport tcp
```

`TelemetrySource` and `DetectionSource` are separate protocols. This prevents a
delivery failure from being reported as a missing alert. `FixtureSource` and
`FileLogSource` provide deterministic offline telemetry inputs. There is no
LogRhythm adapter in this track because no live LogRhythm behavior has been
observed.

`docs/rsyslog-receiver.conf` is a minimal operator reference for writing received
messages to a file. It is not used by the in-process loopback receiver and is not
evidence of a particular SIEM parser behavior.

## Verdicts and exit codes

`ValidationResult` carries a verdict plus separate plan, delivery, detection,
and negative-control dimensions. `NOT RUN` is a state, not a pass.

| Verdict | Meaning |
|---|---|
| `pass` | Every dimension executed at this tier passed. |
| `fail_no_events` | Expected telemetry was absent, incomplete, unparseable, or did not satisfy the plan contract. |
| `fail_no_alert` | Ingestion passed, a detection source was queried, and no alert was observed. Offline CLI tiers never manufacture this result. |
| `inconclusive` | No failure was observed, but the available evidence cannot decide the requested claim. |

CLI exit codes are `0` for pass, `1` for a named failure, `2` for inconclusive
without failure, and `3` for usage or configuration errors.

## Evidence directory

Every validation writes exactly these eight files under
`<manifest-dir>/evidence/<run-id>/`, or the directory selected with
`--evidence-dir`:

```text
manifest.json
contract.yaml
result.json
telemetry.cef
telemetry.json
mapping.md
REPORT.md
replay.json
```

The report is derived from the observed run. Its opening paragraph says when no
collector was configured. Tier 1 reports only the local receiver path it
observed. `mapping.md` contains catalog-to-renderer mappings only; it never
invents SIEM fields.

Telemetry is capped at 10,000 records. Larger observations use a deterministic
first, middle, and last sample. `telemetry.json` records the original count,
sample count, strategy, and truncation flag. A ZIP containing the same eight
files is available from the authenticated web UI.

## Deterministic replay

`replay.json` records the technique, intensity, seed, duration, control
selection, anchor, parameter overrides, vendor, event count, Replicant version,
and a SHA-256 digest of canonical event records.

```bash
replicant replay manifests/evidence/RUN-.../
replicant replay manifests/evidence/RUN-.../replay.json
```

Replay reconstructs the plan without sending or opening a collector. A matching
event count and digest prove byte-identical canonical event records for the
stored recipe. A version mismatch is reported as a warning and replay continues;
the digest remains the deciding comparison.

## Web API and UI

The authenticated API mirrors the Orchestrator path:

- `GET /api/validation/contracts/{technique_id}`;
- `POST /api/validate`;
- `GET /api/evidence/{run_id}`.

The technique detail view shows the contract, logical fields and families,
selected-profile native fields, control mode, observation window, measurable
axes, transfer limitations, tier, verdict dimensions, and evidence download.
Unexecuted dimensions use a neutral dashed `NOT RUN` treatment that is visually
different from green `PASS`.

## Remaining gate

Offline evidence must not be promoted into a live-detection claim. The next gate
still requires an operator-controlled LogRhythm lab to establish source
identification, parser behavior, field mapping, delivery loss, and rule alerts.
Palo Alto and Check Point mappings remain `[Unverified]` until real appliance
evidence supports changing them.
