# Replicant web UI - the Factory system

> 2026-09-08: superseded by [the silver-and-red design](webui-silver-red-design.md). This document records the previous visual system.

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
  near-black circuit/topology backdrop on `body`, generated to this palette,
  under a flat `--background`/0.4 scrim. Cards are opaque, so it reads as
  texture on the canvas only. Any future imagery goes through the same test:
  darker than every text pair's measured floor, or it does not ship.
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
- A selected vendor is part of the run's identity, not a cosmetic catalog
  filter. From the start-admission request through terminal owner confirmation,
  the vendor segmented control is disabled and names the technique holding it.
  Tab navigation cannot unmount the run panel during admission. The browser
  generates an idempotency key and waits for `POST /api/run-admissions` to
  acknowledge a `reserved` owner before the potentially slow plan preview.
  `POST /api/runs` claims the same handle as `admitting`, then promotes it in
  place to `running`. The status banner describes `reserved` as an unclaimed
  request awaiting start and `admitting` as plan preparation. A lost reserve
  response is retried with the same key, and
  a lost start response is read from `GET /api/run-admissions/{id}`. Ownership
  is therefore derived from a server state transition, not a fixed delay or a
  sequence of null snapshots. If the admission is already terminal, the browser
  retrieves `GET /api/runs/{run_id}` before ownership confirmation so a fast run
  retains its final count and manifest.
  The run handle stores the effective vendor, and start, active-run, status, and
  conflict responses return it. A restored view must select that profile and
  load its catalog before presenting the run; the page must never infer the
  owner from the current form or the configured default. The bootstrap owner
  seeds the lifecycle watcher, so a duplicate probe failure or React development
  effect replay cannot discard identity. Conversely, a successful start is the
  authoritative admission result and supersedes any older probe before its
  stream is attached. Initial discovery remains fail-closed when the active
  endpoint cannot answer.
  One watcher follows a server-discovered run through natural completion or a
  requested stop, keeps its latest rendered count visible, and retains the lock
  across transient status failures. A definitive missing old status handle is
  reconciled through the active endpoint, which transfers directly to a
  successor or releases the stale owner. The same recovery applies when a local
  SSE stream disconnected before its bounded status handle was evicted. A
  restored terminal snapshot also populates the final manifest panel. A stop
  request has a visible, disabled stopping state. Terminal status is followed by
  an active-owner probe, so the selector either transfers directly to a
  successor run and its vendor, or unlocks after the backend reports no owner.
  Local SSE completion and its dropped-stream status fallback use that same
  terminal handoff. The worker clears reusable stop state before the handle is
  published as running, so an early Stop survives worker scheduling. The SSE
  endpoint closes only after its terminal item is present in history and
  subscriber queues. A profile switch must never remount or relabel an in-flight
  stream, its native metadata, or its manifest.
- The SPA never owns the persistent launch token. The server exchanges a
  tokenized navigation for an httpOnly session cookie and returns a clean `303`
  before serving JavaScript. Browser API, EventSource, and WebSocket requests are
  cookie-only after that point; frontend URL cleanup is defense in depth.
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

Authentication-sensitive development also gets a live proxy pass. Run the
backend on port 8000, start Vite with
`VITE_PROXY=http://127.0.0.1:8000 npm run dev`, and open the Vite origin with the
printed launch token in its query. The tokenized root, `/api`, and `/ws` proxy
rules preserve the browser-facing `Host` with `changeOrigin: false`; changing
only `Host` would make legitimate cookie writes and terminal WebSockets fail the
backend's `Origin` comparison. The clean redirect must return to Vite, and the
vendor control must remain locked through both a local run and a reloaded active
run. A reload of a non-default vendor run must load that vendor's catalog before
showing the restored panel, then release on stop or completion.
