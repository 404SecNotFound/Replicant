# Replicant web UI reskin - design spec

Status: direction approved from the v2 mockup (`signal-instrument` aesthetic). Target: the existing
`webui/` React + Vite + Tailwind + shadcn app. This is a **reskin plus missing states**: same
features and the same Orchestrator-backed behavior, a new visual system, and the interface states the
current UI does not yet show. No backend changes.

## 1. Concept

Replicant is treated as a precision **signal instrument**. A detection engineer arms a synthetic
telemetry source and emits a controlled CEF signal into their SIEM. The interface is an instrument
panel: calm warm-graphite surfaces, data rendered as first-class telemetry (monospace), and one
ownable idea that carries the identity - a live **events-per-second signal readout** showing the
emission rate over the run window against the eps cap. It appears in the run stage and as a micro
readout in the top bar. Recognizable without a logo.

## 2. Structure and hierarchy

Controlled asymmetry. Top bar; a quiet 336px left rail (Collector, then the technique list) against a
dominant run stage ("Emitter"). Terminal stays a separate tab. Reading order: (1) which technique and
is the collector connected, (2) run controls and the live signal, (3) the CEF tail and the run
manifest. Config lives left and stays subordinate; running dominates.

## 3. Visual system (tokens)

Colors (dark, warm graphite - deliberately not blue-black):

| Token | Value | Use |
|---|---|---|
| `--bg` | `#0e0e11` | app background (+ faint 34px grid at ~1.4% and a top vignette) |
| `--surface` / `--surface-2` / `--elev` | `#161619` / `#1c1c21` / `#24242b` | cards / inputs / raised |
| `--border` / `--border-2` | `rgba(255,255,255,.08)` / `.14` | quiet / stronger hairlines |
| `--text` / `--text-2` / `--text-3` | `#f1f0ec` / `#a3a29b` / `#8f8d84` | primary / secondary / tertiary (all pass AA on `--bg`) |
| `--text-4` | `#5f5e58` | decoration only (dashed lines), never body text |
| `--signal` | `#f4b23e` (amber) | **live signal only** |
| `--white` | `#ecebe6` | primary button / active / selected |
| `--red` | `#e5594f` | high severity + errors |

**Semantic rule (load-bearing):** amber means *signal is live* and nothing else - the eps readout,
waveform, "emitting" and connected dots, and run progress. Generic primary/active/selected states use
near-white; high severity and errors use red. This is what keeps the palette disciplined and the
concept ownable.

Type: **IBM Plex Sans** (400/500/600) for UI chrome; **IBM Plex Mono** (400/500) for all telemetry
(IPs, ports, CEF, seeds, eps, epochs). Both OFL. Scale: 23 hero / 14 titles / 13 body / 11 mono data /
10 uppercase micro-labels (letter-spacing .11em).

Spacing 8px base. Radii small and intentional: 4 (tags/segments), 6 (inputs/buttons), 10 (cards).
Borders quiet. Shadows only for elevation (primary button, active segment).

## 4. Components and the motif

- **Top bar:** waveform mark + `Replicant` + env chip; section nav (Emitter / Catalog / Runs /
  Terminal) with a near-white active underline; live `SIGNAL 182 eps` readout (amber) + collector
  status + user.
- **Collector card:** vendor as a 3-way segmented control (FortiGate / Palo Alto / Check Point),
  host/port/transport in mono, quiet "Send test log".
- **Technique list:** name + `REP-id . log-type` + a HIGH/MED severity tag (text, not color-only) +
  ATT&CK id; selected row gets a 2px near-white tick.
- **Run stage:** eyebrow `REP-001 . UC-001`, title, description, ATT&CK tags; a controls row
  (intensity / duration / seed + destination toggles).
- **Signal readout (the motif):** rate (`events/sec`, amber), cap + window, a waveform of eps over the
  run window with a dashed projection ahead of "now" and a dashed cap reference line, progress, and
  elapsed/emitted meta. Data is real: eps is derived from the SSE count deltas over wall-clock time,
  not a decorative chart.
- **Live CEF tail:** timestamped mono lines, amber `CEF:` prefix, capped to the last N.
- **Manifest:** plain check glyph + the run's audit fields (events, seed, duration, UC, target,
  transport, vendor, anchor epoch).

## 5. Interactions and responsive

Hover raises rows to `surface-2`; `:focus-visible` shows a neutral ring; toggles/tabs animate ~150ms;
the waveform advances and progress fills; one staggered reveal on load (120-240ms), gated by
`prefers-reduced-motion`. Responsive: at tablet the rail collapses to a top drawer; at mobile it
becomes a bottom sheet and the run stage goes full width with the waveform kept and the manifest
stacked to two columns.

## 6. States (the gap in today's UI)

Design and wire each, mapped to real Replicant conditions:
- **Empty** - no technique selected: idle flat readout, "Select a technique to arm a run."
- **Loading / emitting** - amber live dot, advancing waveform, progress.
- **Success** - manifest card with a plain check.
- **Disabled** - no collector and not writing to file: Start disabled with the fail-closed hint.
- **Error** - fail-closed refusal and transport-error on the test log, shown as a red banner with a
  Configure action.
- **Throttle** - run held at the eps cap: rate at cap with an "at cap" chip and a protect-the-collector note.
- Hover / focus / selected / disabled per section as above.

## 7. Distinctiveness

The eps signal readout and the mono-as-telemetry rule are derived from what Replicant does (emit a
rated synthetic signal). Warm graphite + a single semantic amber reads as instrument, not as another
indigo SaaS. No AI-slop tells: distinctive open fonts, no purple gradients, no nested rounded cards,
no fake charts, real product copy.

## 8. Accessibility and performance (non-negotiable)

WCAG AA contrast (tokens above verified). Real semantics: vendor = `radiogroup`, toggles = `switch`,
technique list = keyboard-navigable listbox, all with visible `:focus-visible` rings. Keyboard nav
throughout. `prefers-reduced-motion` disables the entrance and waveform motion. The CEF tail stays
capped/virtualized (the app already caps streamed lines) and SSE renders are batched.

## 9. Implementation plan (webui/)

Keep component logic and the API client intact; change styling, tokens, and markup; add the states and
the readout.

1. **Fonts:** add `@fontsource/ibm-plex-sans` + `@fontsource/ibm-plex-mono` (or self-host the woff2 in
   `webui/public/fonts`), import weights in `src/main.tsx`. No external CDN at runtime.
2. **Tokens:** rewrite the CSS-variable theme in `src/index.css` (the shadcn `--background` /
   `--foreground` / `--primary` ... variables) to the palette above, and add the semantic vars
   (`--signal`, `--signal-dim`, `--signal-line`, `--surface-2`, `--elev`). Point Tailwind font families
   at Plex in `tailwind.config`. Set the primary/accent so shadcn primitives inherit correctly.
3. **Restyle components** (logic unchanged): `App.tsx` (top bar, layout, tabs, the header signal
   readout), `ConnectionCard.tsx` (segmented vendor, inputs, test), `CatalogTable.tsx` (rows, severity
   tag, selected tick), `RunPanel.tsx` (run header, controls, stream, manifest). Adjust the shared
   `ui/` primitives (`button`, `select`, `switch`, `input`, `tabs`, `badge`, `card`) to the tokens.
4. **New component `SignalReadout.tsx`:** the eps waveform + rate + cap + progress. Compute eps from
   the run's count-over-time deltas (from the existing SSE `progress` items); keep a small ring buffer
   of recent samples for the waveform.
5. **States:** surface existing conditions - Start disabled when no destination is set; the
   fail-closed hint; the transport-error and run-error banners from the existing error items; a
   throttle indicator when the emitter holds at the eps cap.
6. **Verify:** `npm run build` (tsc + vite) clean, then drive the real app (`replicant web`) in the
   browser and confirm it matches the mockup and the states render. Existing `tests/test_web_api.py`
   and the API stay green (no backend change).

## Out of scope

No layout re-architecture beyond this reskin; the Terminal tab keeps xterm; no new product features;
light theme is optional (dark-first). Accent can be swapped from amber to a cool signal (cyan/teal) by
changing `--signal` alone if desired.
