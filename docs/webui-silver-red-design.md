# Replicant web UI: silver and red

This is the approved replacement for the Factory design. It follows the reviewed
clickable concept with an original implementation in Replicant. Keymaker v2 was
visual inspiration only; no Keymaker source or assets were copied.

## Visual system

| Role | Color |
| --- | --- |
| Canvas | `#101214` |
| Panels | `#181b1e` |
| Recessed controls and telemetry | `#121518` |
| Reading text | `#e0e3e8` |
| Secondary text | `#aab1bc` |
| Panel border | `#343a41` |
| Input outline | `#59616b` |
| Selection outline | `#db2020` |
| Selected surface | `#291515` |
| Selection glyphs and signal | `#ff3030` |
| Primary action | `#d71919`, white text |
| Keyboard focus | `#dce0e5` |
| Warnings and errors | `#efbc92`, with explanatory text |

Silver headings and reading text remain neutral. Saturated red marks the primary
action, selected controls, navigation, and signal diagrams. There are no pastel
red headings, gradients, glows, or background artwork. Cards use an 8px radius;
controls use 6px. Geist is the interface face, with JetBrains Mono for technical
values. Both remain self-hosted with their existing OFL licenses.

## Workspace

- A persistent sidebar contains Run workspace, Techniques, Process logs,
  Documentation, the server-permitted Terminal, and Collector.
- Run workspace has three numbered sections: Technique, Run settings, and Output.
  The run button names the actual destination and remains near the page title.
- The selected technique is compact. The full, filterable 24-entry catalog is on
  its own page. Selecting an entry returns to the draft.
- Vendor and intensity choices show a red outline and a checkmark. Intensity
  parameters come from the actual catalog. Duration is an event-time span;
  pacing and its consequences remain visible.
- Advanced settings disclose seed, rate, and event-time anchor. Fixed-anchor
  warnings remain visible even when the disclosure is closed.
- Collector and file remain independent switches, so simultaneous output still
  works. Connection tests retain their existing transport-specific limitations.
- The right column shows the catalog signal diagram, an on-demand real CEF sample,
  the current plan estimate, detection context, and the full technique reference.
  The sample is a representative catalog preset, not the operator's exact draft.
  Plan values clear while new settings are priced; errors do not invent estimates.
- Run results appear above the preview. Draft changes never relabel a completed
  run's profile, destination, stream, or manifest. CEF lines scroll horizontally
  so the complete line remains available.

## State and safety

The run component stays mounted across workspace navigation and vendor catalog
loading. Drafts and locally attached streams survive those transitions. Process
logs, documentation, and terminal remain lazy, with log polling only when open.

Admission, ownership recovery, vendor locking, stop confirmation, SSE fallback,
authentication, Host/Origin controls, collector limits, and the backend remain
unchanged. During admission the navigation lock also covers the new catalog and
collector routes. Terminal availability still comes from the server.

The UI shows measured or backend-reported data only. Emission is not evidence of
SIEM receipt or detection. A connection test never claims CEF certification,
compliance, or ArcSight validation.

## Responsive and accessible behavior

Below 1024px, navigation becomes a Menu disclosure and the workspace stacks into
one column. Desktop uses a 192px rail and two workspace columns. Grid children
have `min-width: 0`; tables, diagrams, CEF, and long file paths stay inside their
own containers. Keyboard focus is silver and distinct from a red selection.
Controls have accessible labels, hidden views leave the accessibility tree, and
reduced-motion preferences suppress transitions.

## Verification

The frontend suite covers admission and ownership recovery, collector semantics,
profile metadata, draft persistence, stream retention during navigation, immutable
completed-run identity, and stale-preview removal. Production builds type-check.
Python checks include the CEF golden tests, loopback transports, black, ruff, and
mypy. Browser verification uses an authenticated loopback server and synthetic
no-send runs, with temporary manifests outside the repository.

The README screenshots were refreshed on 2026-09-08 from the authenticated local
build: workspace, technique library, FortiGate reference, completed no-send run,
and embedded terminal, plus a narrow workspace captured with a 360px viewport.
The desktop captures use 1440x900. The run image shows an actual REP-004 medium
run that emitted 108,000 events and finalized its manifest. Screenshot data is
synthetic and does not establish collector receipt or detection.

`scripts/capture-webui-screenshots.py` documents the same view sequence for future
refreshes. This refresh used the browser automation interface; the standalone
capture script was checked with black and ruff, but was not executed.
