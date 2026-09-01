# Deployment boundary: detection lab, not production SIEM

Replicant is a synthetic-telemetry generator for **detection engineering in a lab
or a pre-production detection pipeline**. It is not a production monitoring
component and must not be deployed as one. This boundary is part of the roadmap
2026-09 safety workstream (`docs/roadmap-2026-09.md`, item 3) and rides with the
destination-conditional synthetic marker.

## What that means in practice

- **Point it at a detection lab or a staging collector, not a live production SIEM
  ingestion pipeline.** Replicant injects fabricated, attack-shaped firewall logs.
  On a production collector those lines are indistinguishable from a real incident
  to anyone who has not been briefed: they page the on-call shift, skew dashboards,
  and pollute searchable history.

- **Every line on a non-loopback send is tagged by default.** Replicant stamps a
  `flexString1Label=ReplicantSynthetic` marker, carrying the run id, on every line
  it sends off loopback, so an analyst can filter lab data out of production views
  and de-conflict a "3am fake attack" against the run manifest. The marker is off
  for `--to-file` and loopback, where the golden line is the format oracle and
  fidelity is what matters. `--no-marker` removes it and the override is logged on
  a live send. `flexString1` is a flex slot none of the three vendor profiles
  populate, so marking corrupts no field a detection reads.

- **Authorize the run.** Before sending to any shared collector, tell the SOC the
  run id, the technique, the source and destination entities, and the window. The
  run manifest records all of this, and its `marker_attestation` line states the
  marking decision; treat the manifest as the authorization artifact.

- **The safety invariants still bind.** One fail-closed egress to the operator's
  configured collector, synthetic entities only, log strings only (never real
  attacks or traffic), the events-per-second cap, and a manifest per run. See the
  safety model in the README and the non-negotiable safety rules in `CLAUDE.md`.

## Why this is a boundary and not a suggestion

An enterprise will not, and should not, approve an unattested attack-log injector
near a production pipeline. Keeping Replicant on the lab side of the boundary,
with the marker on and the manifest as the authorization record, is what turns a
"fake attack incident" into an authorized, auditable, reversible test. It is the
hard precondition for any live operational pilot.
