# Replicant web UI - the Factory system

Status: implemented (v0.6.0). Supersedes `docs/webui-reskin-design.md` (the amber
"signal-instrument" system, kept for history). The design direction is the archived
dark-era factory.ai visual system ("terminal war room at midnight"), approved from
three standalone mocks that went through a builder/three-critic loop. The mocks and
the critics' bar live outside this repository on purpose; this document is the
contract the shipped code follows.

## 1. Concept

A terminal war room. One dark canvas, raised warm-graphite cards, machine text in
mono, human text in a grotesque sans, and exactly two chromatic colors that are
reserved for live data. Nothing glows, nothing is bold, nothing gradients. The
interface reads like an instrument that happens to be made of HTML.

## 2. Fonts

| Face | Weights | Role |
|---|---|---|
| Geist | 400, 500 | human sentences, hero numerics |
| JetBrains Mono | 400 | labels, tags, units, machine values, log text |

Both OFL 1.1, self-hosted under `webui/public/fonts` with the license texts beside
the woff2 files (they ship into the wheel via `webui_dist/fonts/*`). The approved
mocks used Switzer, but the ITF Free Font License v2.0 prohibits distributing the
font files through a repository or publicly accessible server, and this is a public
repo that publishes wheels. Geist is the closest OFL grotesque; the swap was DJR's
call. Do not link Fontshare (or any font CDN) at runtime: the CSP is
`font-src 'self'` and lab networks may be offline.

**The voice rule (load-bearing):** machine values take the mono voice - IPs, ports,
ids, log types, CEF text, status tags like `SENT, UNCONFIRMED`. Human sentences and
hero numerics take Geist. A human sentence set in mono is a violation in either
direction.

Weight 400 everywhere; 500 at most once per screen. Emphasis inside log lines is
brightness only (bone `#eeeeee` against the grays): bright-on-dark AA bloom reads
as bold in stem measurements, which is an artifact, not a defect.

## 3. Palette

Defined once on `:root` in `webui/src/index.css` as bare HSL triplets; each token
names its hex in a trailing comment and `theme.test.ts` asserts every documented
triplet encodes exactly that hex. Dark-only by decision: the light theme, its
toggle, pre-paint script and parity guard were removed with it.

| Hex | Token(s) | Use |
|---|---|---|
| `#101010` | `--background`, `--well` | canvas; recessed wells inside cards |
| `#0d0d0d` | `--frame` | the war-room dashboard frame (run panel) |
| `#1d1a18` | `--card`, `--secondary`, `--elev` | raised surface; inner hairlines |
| `#3d3a39` | `--border`, `--input` | outline hairlines, ghost borders |
| `#4d4947` | `--accent` | mid fill (terminal selection) |
| `#8a8380` | `--muted-foreground`, `--text-4`, `--ring` | muted text |
| `#b8b3b0` | `--secondary-foreground`, `--text-3` | tertiary text, eyebrows |
| `#eeeeee` | `--foreground` | primary text ("bone") |
| `#fafafa` | `--primary` | primary button fill (ink: `#101010`) |
| `#ee6018` | `--signal`, `--destructive` | signal orange: live data and status ONLY |
| `#a0ca92` | `--metric` | metric green: positive live data ONLY |

**The chromatic counting rule:** a connected data series (sparkline, pulse train,
progress track) counts as ONE chromatic element. Cap ~2 distinct chromatic elements
per card. Chromatic color never appears on buttons, navigation, headings, or
control states (an active filter recesses to the canvas instead). The palette has
no red; errors and warnings are status and speak in the signal orange
(5.7:1 on canvas, 5.1:1 on card, both AA).

## 4. Shape and space

- Cards: 10px radius (`rounded-lg`, `--radius`), padding 24px, no border by
  default - the surface color separates them. Outlined cards (`border` +
  `bg-background`) are for the diagram and event stream, which sit ON the canvas.
- Buttons, nav, inputs, chips: 3px radius (`rounded-btn`).
- 8px spacing scale. No box-shadow, no gradient, no glow, anywhere.
- **One sanctioned image** (operator request, added after the mocks): a
  near-black circuit backdrop on `body`, generated to this palette, under a flat
  `--background`/0.4 scrim. Cards are opaque, so it reads as texture on the
  canvas only. Any imagery goes through the same test: darker than every text
  pair's measured floor, or it does not ship.

  That test was stated here from v0.6.0 and nothing ran it, so the image that
  shipped until v0.8.0 did not pass it. Measured on the rendered page across five
  scroll positions, its brightest trace put the run panel's pacing hint at
  **1.77:1**, and two technique-list subtitles at **2.34:1** and **2.59:1**.

  **The rule is now total rather than positional, and the plate is bounded rather
  than merely dark.** `background-attachment` is `fixed`: the backdrop stands
  still while the columns scroll text across it. A measured occupancy map (8
  viewports x 4 tabs x 6 scroll positions) put canvas-level text over **61% of
  the plate**, and the remainder is slivers between lines, not a gutter. Since no
  region is reliably free, no region is allowed to exceed the ceiling.

  The ceiling is arithmetic. For the dimmest token that renders on the canvas
  (`--text-4` #8a8380) to hold AA, the composited background luminance may not
  exceed `(L_text + 0.05) / 4.5 - 0.05`. Everything else is a consequence: the
  plate's structure is tone-mapped into that band (peak RGB 35, about `#232323`),
  which is why it can be dense edge to edge instead of confined to a corner. On
  the rendered page every canvas-level node now measures at or above **4.67:1**
  at 1280, 1440, 1920 and 2560, at five scroll positions each.

  **The plate is achromatic.** The image it replaces had orange trace endpoints;
  they were decorative, and a warm dot on the canvas is the verified-badge lie in
  another costume, reading as status beside an interface whose only other orange
  IS status. Nothing was given up to say so, because the ceiling would have muted
  them to bronze anyway.

  Two things about producing one, both of which cost a cycle here:

  1. **Solve the amplitude against the encoded file, not the float composition.**
     A lossy WebP encode overshoots on sharp line art: at quality 80-95 it raised
     the peak from 36 to 45 and dropped the floor from 4.63:1 to 4.32:1, under
     the bar. The shipped amplitude is found by binary search on the compressed
     artifact.
  2. **Dense high-frequency detail reads as material; low-frequency shapes read
     as artifacts.** At this amplitude a plate of large concentric hubs looked
     like smudges on the screen, while fine routing at the same peak luminance
     looked like an intentional surface. Pick structure accordingly.

  Provenance: the shipped asset is a lighten blend of the original v0.6.0 plate
  with a dense circuit-routing plate generated for this palette (Higgsfield, Nano
  Banana Pro, 21:9 at 4K), tone-mapped and reduced to 1920x815 WebP. The blend
  and the mapping are deterministic post-processing, not part of the generation.

  `tests/test_webui_backdrop.py` is the guard: it bounds every pixel of the asset
  under the scrim, which bounds every viewport at once, since `cover` only scales
  and crops and neither creates a pixel brighter than the source. Positive
  control: against the previous asset it reports 1.69:1 and fails.

- Segmented controls: content-sized segments, `white-space: nowrap`, 10-12px
  horizontal padding. "Check Point" has wrapped or clipped three separate times in
  equal-width segments; do not reintroduce `flex-1` there.

## 5. Type scale

`webui/tailwind.config.js` `fontSize` is the scale; nothing renders below 11px in
CSS. `micro 11 / label 12 / data 12.5 / body 14 / lede 16 / stat 22 / title 36`.
`title` is the screen's one hero line (the technique name, the war-room tile
values); `stat` is the smaller metric-tile value on the detail screen. Labels and
eyebrows are `.u-label`: mono, uppercase, 12px, letter-spacing -0.24px, weight 400.

Two traps, both hit and guarded:

1. **tailwind-merge classifies unknown `text-*` classes as colors.** Stock
   `twMerge("text-label", "text-signal")` deleted the size and the element
   inherited its parent's; the vendor segmented control rendered 16px against a
   class list saying 12px. `cn()` in `webui/src/lib/utils.ts` extends the merge
   config with every rung, and `utils.test.ts` pins each rung the config declares.
2. **SVG `fontSize` attributes escape every Tailwind sweep**, and viewBox scaling
   changes their rendered size. The diagram and sparkline annotations (9-12 as
   attributes) are the only text outside the scale; the approved mock's smallest
   annotation is 9px.

## 6. Honesty rules carried into the design

These came out of the critic loop and the two end-to-end reviews; they bind future
changes to these screens.

- The status dot for `SENT, UNCONFIRMED` is neutral, never green or orange. A
  colored dot beside an unconfirmed state is the verified-badge lie again. The
  armed-collector dot in the header is bone for the same reason.
- No readout renders that the stream cannot measure: the mock's bytes tile does
  not ship because there is no byte counter behind it. Labels say "emitted", not
  "sent" or "delivered", where only rendering is measured; on UDP nothing in the
  UI claims delivery.
- Live-run numbers derive from the same counters (rate, count, progress), so they
  cannot contradict each other.
- The sparkline is an instrument, not decoration: scale hairlines labeled with the
  real ceiling, a dotted mean, a time axis. While the cap applies it floors the
  scale (DEF-002) so a small rate does not dramatically fill the band; uncapped,
  the printed scale value keeps autoscale self-describing.
- A grid or flex item needs `min-w-0` before `overflow-x-auto` inside it can work;
  one CEF line otherwise scrolls the whole page sideways (see section 5 of the
  superseded doc for the original 3452px measurement).

## 7. Verification method

The method that keeps finding what reviews miss, in order: `tsc` + vitest;
contrast AND size measured on the rendered page (walk text nodes, compute the
effective background, WCAG ratio per element), never on the token table; no
horizontal overflow at 1280 and 375; screenshots regenerated with
`scripts/capture-webui-screenshots.py`.
