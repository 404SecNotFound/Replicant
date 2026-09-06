# Reference detection specs

The blueprint's differentiator 5 promises that telemetry and detection *ship
together*. The technique catalog carries a `ndr_rule` and a `ndr_uc` label for
every entry, and a one-sentence `objective`, but a label is not a spec you can
build a rule from. These documents close that gap: for a technique, a
human-authored reference for the detection its telemetry is shaped to exercise.

## What these are, and are not

- **Written documentation, not generated rules.** Each spec describes the
  detection logic in SIEM-neutral pseudocode a detection engineer implements in
  their own platform (LogRhythm AIE, Splunk, Elastic, Sentinel, ...). Replicant
  does not auto-author Sigma/AIE rules at runtime, and neither do these specs;
  that constraint is deliberate (see the roadmap and the scenario advisory
  boundary).
- **Anchored to the emitted telemetry.** Every threshold ties to a catalog preset
  or distribution, so the spec and the stream `replicant run` produces stay in
  step. A spec that drifts from the catalog is a defect.
- **Honest about what a green result proves.** Each spec states its
  transferability (does exercising it exercise the *shipped* rule, or only its
  parser?) and repeats the standing delivery caveat: every timing and delivery
  claim in this project is loopback-only until the first observed rule fire.

## Logical families and vendor-native fields

Detection specs name the vendor-neutral logical event families the engine emits.
They do not treat one vendor's category, signature, action, or extension key as a
universal identifier. A spec may designate one pilot profile, but it must label that
profile's native mapping separately from the logical family.

For a mixed-family plan, the spec must list every entry in `logical_families` and
state required fields per family. The primary `native_*` metadata describes only the
primary family. The aggregate `native_cef_fields_held` and
`native_cef_fields_varied` values are unions across the plan, so they cannot prove
that one particular family carries a field. Use
`native_cef_fields_by_logical_family` for that assertion and preserve explicit
unavailable fields rather than substituting a plausible vendor key.

The older `log_type`, `subtype`, `signature_id`, `action`, and `cef_fields_*` API
fields remain compatibility views of the catalog and its FortiGate binding. They do
not change with the selected vendor. Selected-renderer documentation uses the
additive `logical_*` and `native_*` fields instead.

## Phasing

Authoring 24 specs up front, against a core whose delivery path has never been
observed end to end, would be effort ahead of proof. They land in the order the
roadmap sets:

1. **The pilot technique** the operational adoption gate runs first: **REP-001**
   ([`REP-001.md`](REP-001.md)).
2. The **parser-only** techniques next (REP-011, REP-016, REP-020), because their
   specs must state most sharply what a green result does *not* prove.
3. The rest, only after the first observed rule fire.

| Use case | Rule | Technique | Spec |
|---|---|---|---|
| UC-001 | NDR-C2-001 | REP-001 Periodic C2 callback | [REP-001.md](REP-001.md) |

Rows are added as specs are authored; the table is not the full catalog.
