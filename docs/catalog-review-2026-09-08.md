# Technique and scenario catalog review

**Date:** 2026-09-08

**Scope:** `replicant/data/technique-catalog.yaml` and
`replicant/data/scenario-catalog.yaml`

**Outcome:** all 24 technique presets and all three curated scenarios build, but
the review found and corrected runtime, metadata, ATT&CK, and scenario-definition
defects. Remaining limitations are listed below rather than treated as coverage.

## What was checked

- Every technique builds at low, medium, and high intensity without preset
  truncation.
- Every cataloged held or varied signal agrees with the positive events rendered
  by the FortiGate profile. This is now an executable all-technique regression
  test.
- Declared primary and additional log families agree with the event families the
  builders emit.
- Detection fields are either rendered by each vendor profile or reported as an
  explicit profile gap.
- Benign foils agree with `emits_foil` at every intensity and remain separable
  through the `control` label.
- ATT&CK identifiers and tactic relationships were compared with MITRE's official
  [Enterprise ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data).
- Every scenario stage resolves to a real technique, composes in time order, uses
  synthetic entities, omits technique-level negative controls, and avoids preset
  truncation.

This is a generator-contract review. It is not evidence that a SIEM ingested the
events or that a production detection fired. Palo Alto and Check Point references
also retain their `[Unverified]` markers until a live-vendor pass is completed.

## Corrections made

| Area | Defect | Correction |
|---|---|---|
| REP-005 | `dst` was declared held although medium and high use two and three destinations. | Moved `dst` to varied fields. |
| REP-010 | `cnt` was advertised although traffic records do not emit it. | Removed `cnt`; added the emitted, changing `proto` and `externalId` fields. |
| REP-017 | `dpt` and `proto` were declared held although the DNS-to-DoH transition changes 53/UDP to 443/TCP. | Moved both fields to varied. |
| REP-018 | The medium preset requested three causal users but emitted only two. | The builder now emits every feasible requested identity, beginning the first change at `switch_at_hop` and distributing later identities across the remaining path. |
| REP-019 | High intensity configured 1,500 total probes with two probes per destination but emitted 3,000 positive events. | `total_probes` now means total positive events. Repeated probes retain a destination and port while every probe receives the configured inter-probe gap. |
| REP-019 | Internal sources scanning internal targets were also mapped to pre-compromise Reconnaissance (`T1595.001`). | Narrowed the mapping to Discovery (`TA0007`) and Network Service Discovery (`T1046`). REP-021 remains the inbound perimeter-scanning case. |
| REP-004, REP-015 | Safety text called all documentation-domain parents non-resolvable even though `example.net` can resolve. | Stated the actual invariant: names stay under IANA documentation domains or `.invalid`, and Replicant performs no DNS lookup or connection. |
| SCEN-001 | An internal REP-003 horizontal sweep was named and labeled as perimeter or external reconnaissance. | Renamed it to “Internal discovery to exfiltration” and labeled the first stage “internal discovery.” |
| SCEN-003 | A stage labeled “password spray” selected REP-007 high intensity, whose preset mode is brute force. | Changed the stage to medium intensity, whose mode is spray. |
| Scenario loading | Empty chains, malformed offsets, and misspelled parameter override keys could survive catalog loading. | These now fail before composition with a targeted validation error. |

## Per-technique disposition

“No defect found” means the generated plan agrees with the current catalog
contract. It does not mean detection-validated.

| Technique | Review disposition | Remaining work |
|---|---|---|
| REP-001 | No generator-contract defect found. | Needs a genuine same-shape benign foil. |
| REP-002 | No generator-contract defect found. | Needs a sparse vertical-scan foil. |
| REP-003 | No generator-contract defect found. | Needs a sparse horizontal-sweep foil. |
| REP-004 | DNS safety wording corrected. | Needs a foil that prevents query volume alone from passing. |
| REP-005 | Destination signal metadata corrected. | Needs the host's own benign volume baseline as a negative control. |
| REP-006 | No generator-contract defect found; structural proxy foil is present. | Live detection validation only. |
| REP-007 | No generator-contract defect found; NAT/source-collapse foil is present. | Live detection validation only. |
| REP-008 | No generator-contract defect found; warm-up history establishes per-host novelty. | No standalone negative stream. |
| REP-009 | No generator-contract defect found. | Needs a steady benign IPS-rate foil. |
| REP-010 | Non-emitted signal metadata corrected. | Needs routine policy denials as a negative control. |
| REP-011 | No generator-contract defect found. | Parser-only until real GeoIP enrichment is exercised; also lacks a credible foil. |
| REP-012 | No generator-contract defect found; benign jittered traffic foil is present. | Live detection validation only. |
| REP-013 | No generator-contract defect found; admin fan-out foil is present. | Live detection validation only. |
| REP-014 | No generator-contract defect found; bursty benign long-session foil is present. | Live detection validation only. |
| REP-015 | DNS safety wording corrected; low-cardinality foil is present. | Live detection validation only. |
| REP-016 | No generator-contract defect found; benign NXDOMAIN foil is present. | Parser-only because `.invalid` cannot exercise reputation or registration enrichment. |
| REP-017 | DNS-to-DoH signal metadata corrected; pre-switch history is present. | No standalone negative stream. |
| REP-018 | Requested-user emission corrected; admin-star foil is present. | User continuity across curated scenarios remains a future refinement. |
| REP-019 | Probe count, timing semantics, and ATT&CK mapping corrected; sparse-denial foil is present. | Live detection validation only. |
| REP-020 | No generator-contract defect found; organization-wide history precedes first contact. | Parser-only because synthetic names cannot carry real registration age. |
| REP-021 | No generator-contract defect found. It is intentionally the inbound background-scan calibration case. | Treat it as a baseline, not a malicious positive-control claim. |
| REP-022 | No generator-contract defect found; unrelated alert noise is present. | Live detection validation only. |
| REP-023 | No generator-contract defect found; benign TLS flow foil is present. | Live detection validation only. |
| REP-024 | No generator-contract defect found; sanctioned-proxy foil is present. | Integer-second event time limits subsecond fidelity, as already disclosed. |

## Per-scenario disposition

| Scenario | Result | Known boundary |
|---|---|---|
| SCEN-001 | Corrected to an internal discovery, C2, and off-hours exfiltration chain. All stages share the pinned victim source; C2 and exfiltration share the synthetic external peer. | The exfiltration stage is aligned to the next off-hours window and cannot be compressed through that boundary. |
| SCEN-002 | Vertical discovery, per-host external novelty, and DNS exfiltration compose in order with the pinned victim source. | High-intensity REP-004 contributes 180,000 events, so plan pacing and the EPS cap matter operationally. |
| SCEN-003 | External IPS activity, a real password-spray preset, geovelocity, and a beacon compose in order. | It deliberately crosses IP, user, and host correlation domains. The advisory must be used; one identifier does not thread all four stages. |

## Recommended enhancement order

1. Build and machine-check the eight missing negative controls: REP-001 through
   REP-005, then REP-009 through REP-011. A trivially separable foil should remain
   absent rather than create false confidence.
2. Run the existing LogRhythm pilot and capture an observed ingest and rule-fire
   result before describing any technique as detection-validated.
3. Complete the live Palo Alto and Check Point appliance pass and remove
   `[Unverified]` markers only where captured output supports it.
4. Add user and victim continuity controls to SCEN-003 if it is promoted from a
   mixed-domain demonstration to a tightly correlated campaign replay.

The current `emits_foil` state remains honest: 12 techniques expose a separate
negative stream; REP-008, REP-017, and REP-020 carry required history inside the
positive plan; REP-021 is itself a calibration baseline; and the eight entries
listed above still need purpose-designed controls.
