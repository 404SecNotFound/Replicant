# Replicant web UI: silver and red

This is the approved replacement for the Factory design. It follows the reviewed
clickable concept with an original implementation in Replicant. Keymaker v2 was
visual inspiration only; no Keymaker source or assets were copied.

## Visual system

| Role | Color |
| --- | --- |
| Canvas | `#0c0e10` (was `#101214`) |
| Panels | `#13161a` (was `#181b1e`) |
| Recessed controls and telemetry | `#0f1114` (was `#121518`) |
| Raised controls and hover | `#1b1f24` (was `#20252a`) |
| Reading text | `#e0e3e8` |
| Secondary text | `#aab1bc` |
| Panel border and hairlines | `#2a2f35` (was `#343a41`) |
| Input outline | `#59616b` |
| Selection outline | `#db2020` |
| Selected surface | `#291515` |
| Selection glyphs and signal | `#ff3030` |
| Primary action | `#d71919`, white text |
| Keyboard focus | `#dce0e5` |
| Warnings and errors | `#efbc92`, with explanatory text |

Silver headings and reading text remain neutral. Saturated red marks the primary
action, selected controls, navigation, and signal diagrams. There are no pastel
red headings, gradients, glows, or background artwork. Cards use a 4px radius and
controls 3px since the 2026-10-19 revision (8px and 6px before). Geist is the
interface face, with JetBrains Mono for technical values and field labels. Both
remain self-hosted with their existing OFL licenses.

## Revision 2026-10-19: operations console

The owner asked for the UI to read as a security tool rather than a generic
developer dashboard. Three directions were mocked from Refero screen research
(Fingerprint's detection views, Stripe's security history, Gladia's live
console) plus the conventions of packet analysers and the ATT&CK matrix; the
Coverage board and the Wire view were adopted. The third, an Operations
timeline for scenarios, is not built: web scenario support is deliberately
deferred (`tasks/uat-plan.md` CHAIN-16) and `docs/roadmap-2026-09.md` holds new
surface behind the first observed rule fire.

What changed, and the rules that now bind:

- **Frame.** A handling banner at the top and bottom of every screen reads
  `Synthetic telemetry // lab use only // detection unverified`. It borrows the
  shape of a classification banner and states facts instead; it never carries a
  real classification marking. A top command bar replaces the left rail: the
  brand mark, mono tab labels, and status cells for profile, egress and a UTC
  clock. A status footer repeats the catalog size, profile, rate cap, and that
  emission is not evidence of SIEM receipt.
- **Shape.** Panels are 4px, controls 3px. Hairlines separate regions; a card
  is used only where it groups controls. Palette changes are in the table above;
  the red roles are unchanged.
- **Labels.** `.u-label` is the instrument voice: JetBrains Mono, 11px,
  capitals, 0.06em tracking. It names a field. Sentences stay in Geist.
- **Coverage board** (the old technique library). Tactics are swimlanes in
  kill-chain order with the techniques as cells; a technique mapped to several
  tactics appears in each. Tactics no entry reaches are named, not drawn empty,
  because a firewall log cannot express them. A cell focuses the dossier; only
  the dossier's button loads a technique into the run workspace. "Rule fire"
  reads "Not visible to Replicant", because it is not.
- **Wire view** (the old event stream). After a run starts, the run evidence
  sits in a full-width band above the settings: the readout and manifest on
  the left, the wire on the right. The wire lists buffered events, dissects the
  selected line into syslog prefix, CEF header and extension, and shows the
  same line as UTF-8 bytes; selecting a field lights its bytes, and the
  profile's held keys are marked. Everything in it is parsed from the line
  itself (`webui/src/lib/cef.ts`), never inferred from the plan. A pinned
  selection follows the event, not its index, as the bounded buffer drops old
  lines. Held keys are shown only when the loaded technique and profile are
  the ones the stream was rendered with.
  Implementation note (2026-10-20): the byte view draws 16 bytes per row when
  a row fits its own box and 8 when it does not, measured with a
  ResizeObserver. A viewport breakpoint was the first idea and would have been
  wrong: the wire shares the evidence band with the readout, so at 1280 and
  1440 its byte box is 365 and 445px wide, a 16-byte row needs about 461, and
  the ASCII column was clipped on desktop as well as on a phone (it shows in
  the 2026-10-19 `webui-run.jpg`). Measured after the change in Chromium at
  390, 768, 1280, 1440 and 1920: no sideways scroll in the byte box or the
  page; 16 bytes per row at 768 and 1920, 8 at the others. The highlight is
  byte-addressed, so it is unaffected by the row width.
- **Full technique reference** spans both columns below the run form. Inside
  the right column, opening it left the left column ending above an empty half
  screen.

Verification for this revision: `tsc`, the vitest suite (new guards for the
dissector, the wire view and the coverage board, each run against deliberately
broken code and observed to fail), a rendered contrast audit of every text
node on the run, coverage, collector, logs and docs views (zero below AA, with
a planted low-contrast control confirmed to be caught), no horizontal page
overflow at 1440 and 390 wide, and the README screenshots regenerated with
`scripts/capture-webui-screenshots.py`, executed this time under a Linux
Chromium (`REPLICANT_CHROME`, `REPLICANT_CHROME_ARGS`).

The sections below describe the September layout; where they mention the
persistent sidebar, the catalog page or the event stream, read the revision
above.

## Workspace

- A persistent sidebar contains Run workspace, Techniques, Process logs,
  Documentation, the server-permitted Terminal, and Collector.
- Run workspace has three numbered sections: Technique, Run settings, and Output.
  The run button names the actual destination and remains near the page title.
- The selected technique is compact. The full, filterable 26-entry catalog is on
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
