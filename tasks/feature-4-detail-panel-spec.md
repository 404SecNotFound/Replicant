# Feature: use-case detail panel (web UI)

Status: implemented on branch `feature/usecase-detail-panel`, verified in a live browser.
Author: Claude Code (autonomous session, 2026-07-19), on DJR's spec.

## Requirement (DJR)

> Clicking a use case in the left rail opens a detail box: full technique details, what the
> detection is looking for, the rule specifics, and what the logs will show — with a good diagram
> to show visually.

## Design decision

Rather than a modal that pops on every click (disruptive to the run flow, since selecting a
technique also arms the run), the **main/right column became a technique dossier**. Clicking a use
case in the left rail selects it and swaps the whole dossier:

1. **Identity** — `REP-id · UC-id`, title, one-line description, ATT&CK tactics + technique chips.
2. **Signal-path diagram** — a data-driven SVG (the showpiece).
3. **What the detection looks for** — signal (varied) vs held-constant CEF field chips, plus the
   `benign_baseline` prose.
4. **Rule specifics** — NDR rule, use case, log type, signature id, action, intensities, and an
   intensity-preset table (the engine knobs per low/medium/high).
5. **What the logs will show** — up to 3 **real rendered CEF sample lines** for the selected vendor
   (fetched on demand), plus the `distributions` guidance.
6. Footer — references + safety notes.

The existing `RunPanel` (arm/run controls, eps signal readout, live CEF tail, manifest) sits beneath
the dossier; its now-duplicate identity header was removed.

## Diagram (`TechniqueDiagram.tsx`)

A shared `SOURCE → behavior → NDR match` signal path with a per-technique middle glyph. Amber marks
the emitted signal / anomaly (semantic, matching the signal-instrument system). Archetypes:

| Technique | Archetype | Glyph |
|---|---|---|
| REP-001 | periodic | evenly spaced amber pulses (Δt ± jitter) |
| REP-002 | scan | source → fan to many ports (one dst) |
| REP-003 | sweep | source → fan to many hosts (one port) |
| REP-004 | tunnel | encoded qname chip → resolver |
| REP-005 | volume | tapered amber arrow + byte gauge |
| REP-006 | fanout | radial burst to many dst |
| REP-007 | auth | fail ×N → success sequence (USER source) |
| REP-008 | newdest | dim known cluster + one amber "new" star |
| REP-009 | spike | baseline → amber IPS spike area |
| REP-010 | deny | denied-outbound burst into a wall |
| REP-011 | geo | two map pins + impossible-travel arc (USER source) |

Verified in-browser: REP-001, REP-002, REP-004, REP-009, REP-011. Theme-aware (uses CSS vars),
respects `prefers-reduced-motion` (global rule kills the subtle live-dot pulse).

## Backend changes

- `/api/catalog` (`_technique_json`) now also exposes `signature_id`, `action`, `cef_fields_held`,
  `cef_fields_varied`, `params`, `distributions`, `benign_baseline`, `references` (resolves UAT
  OBS-001).
- New endpoint `GET /api/catalog/{id}/sample?vendor=&intensity=` renders a few representative CEF
  lines via the active vendor profile (builds a deterministic plan, `no_send=True`, renders
  first/middle/last events). 400 on unknown vendor, 404 on unknown id, token-gated.
- `Orchestrator.render_line(event)` helper serializes one planned event to CEF.
- Tests: 6 added to `tests/test_web_api.py` (expanded fields + the sample endpoint).

## Defects folded in (from the UAT recon)

- **DEF-002 (fixed)** — `RunPanel` eps waveform cap now comes from `config.eps_cap` (was hardcoded
  `2000`); `App` threads `epsCap` through.
- **DEF-001 (fixed)** — README test-count comment corrected.
- **DEF-003** — the `soon`/`not-runnable` dead UI states were left in place as forward guards for
  future not-yet-implemented techniques (all 11 are currently implemented). Low value to remove.

## Files

New: `webui/src/components/TechniqueDetail.tsx`, `webui/src/components/TechniqueDiagram.tsx`.
Changed: `webui/src/App.tsx`, `webui/src/components/RunPanel.tsx`, `webui/src/lib/api.ts`,
`replicant/web/server.py`, `replicant/core/orchestrator.py`, `tests/test_web_api.py`, `README.md`.

## Verification

- Full Python suite + black + ruff + mypy green; `npm run build` (tsc + vite) clean.
- Live browser: dossier + diagram + real sample CEF lines render for multiple techniques; selection
  swaps content; USER vs HOST source switches; eps cap label reads from config.
- No backend safety change: the sample endpoint is `no_send=True` (no egress), token-gated, loopback.

## Follow-ups (not done here)

- Manual UAT of the panel by DJR (add to `tasks/uat-plan.md` Suite D).
- Optional: light-theme pass, responsive collapse of the dossier at tablet/mobile widths.
- Optional: per-vendor sample toggle inside the panel (currently follows the global vendor selector).
