// Copyright 2026 Imran Hafeez (RZA)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import type { Technique } from "@/lib/api";

// A data-driven schematic: synthetic SOURCE -> the technique's behavior pattern
// -> NDR rule match. Signal orange is the emitted signal / the anomaly the
// detection keys on; everything else stays in the neutral ramp. The glyph plus
// the detection outline are the card's two chromatic elements, so nothing else
// in the drawing may take the orange. One archetype per technique.

const SIG = "hsl(var(--signal))";
const HAIR = "hsl(var(--border))";
const EDGE = "hsl(var(--text-4))";
const FG = "hsl(var(--foreground))";
const T3 = "hsl(var(--text-3))";
const T4 = "hsl(var(--text-4))";
// The palette has no red. A refusal mark is part of the neutral story the
// glyph tells; the chromatic element is the pattern, not each cross.
const RED = "hsl(var(--text-4))";
const CARD = "hsl(var(--card))";
const MONO = "'JetBrains Mono', ui-monospace, monospace";

type Arch =
  | "periodic"
  | "scan"
  | "sweep"
  | "fanout"
  | "tunnel"
  | "volume"
  | "auth"
  | "deny"
  | "newdest"
  | "spike"
  | "geo"
  | "fleet"
  | "dga"
  | "quiet"
  | "chain"
  | "spread"
  | "inbound"
  | "stages"
  | "relay";

const CAPTION: Record<Arch, string> = {
  periodic: "fixed interval ± jitter",
  scan: "one dst · many ports",
  sweep: "one port · many hosts",
  fanout: "one src · many dst (burst)",
  tunnel: "encoded labels in the qname",
  volume: "outbound bytes ≫ baseline",
  auth: "many fails → one success",
  deny: "repeated denied outbound",
  newdest: "first contact to a new dst",
  spike: "IPS events/sec spike",
  geo: "two logins, impossible travel",
  fleet: "same Δt across the fleet",
  dga: "NXDOMAIN cluster ≫ trickle",
  quiet: "resolver goes quiet",
  chain: "host → host login chain",
  spread: "spreading src population",
  inbound: "many external src · one dst",
  stages: "alerts in kill-chain order",
  relay: "in ≈ out through one host",
};

interface DiagramSpec {
  glyph: Arch;
  // Overrides the archetype's default caption when a technique reuses a glyph
  // shape but tells a different story with it. REP-019 reuses the scan fan,
  // but its signal is being SLOW, so the caption must not imply a burst.
  caption?: string;
  // Overrides the source chip. Defaults to a synthetic host; identity-driven
  // techniques show a user, and the inbound scan's source is the external
  // scanner pool, not an internal host.
  source?: readonly [string, string];
}

// Every catalog id maps here explicitly. There is deliberately no fallback:
// REP-012..024 used to inherit the periodic-beacon drawing, which presented a
// DGA or an inbound scan as a fixed-interval beacon with full confidence.
// TechniqueDiagram.test.tsx asserts this record covers the whole catalog, so
// adding a technique without deciding its diagram fails a test instead of
// silently drawing the wrong picture.
export const DIAGRAM_SPECS: Record<string, DiagramSpec> = {
  "REP-001": { glyph: "periodic" },
  "REP-002": { glyph: "scan" },
  "REP-003": { glyph: "sweep" },
  "REP-004": { glyph: "tunnel" },
  "REP-005": { glyph: "volume" },
  "REP-006": { glyph: "fanout" },
  "REP-007": { glyph: "auth", source: ["user", "jsmith"] },
  "REP-008": { glyph: "newdest" },
  "REP-009": { glyph: "spike" },
  "REP-010": { glyph: "deny" },
  "REP-011": { glyph: "geo", source: ["user", "jsmith"] },
  "REP-012": { glyph: "fleet" },
  "REP-013": { glyph: "spread" },
  "REP-014": { glyph: "periodic", caption: "metronomic pool submits" },
  "REP-015": { glyph: "tunnel", caption: "many unique qnames, normal rate" },
  "REP-016": { glyph: "dga" },
  "REP-017": { glyph: "quiet" },
  "REP-018": { glyph: "chain", source: ["user", "jsmith"] },
  "REP-019": { glyph: "scan", caption: "slow probes, long window" },
  "REP-020": { glyph: "newdest", caption: "org-wide first contact, new domain" },
  "REP-021": { glyph: "inbound", source: ["external", "192.0.2.x"] },
  "REP-022": { glyph: "stages" },
  "REP-023": { glyph: "periodic", caption: "regular flow timing, no payload" },
  "REP-024": { glyph: "relay" },
};
const YC = 112; // vertical center line of the signal path

function Cross({ x, y, s = 5, color = RED }: { x: number; y: number; s?: number; color?: string }) {
  return (
    <g stroke={color} strokeWidth={1.5} strokeLinecap="round">
      <line x1={x - s} y1={y - s} x2={x + s} y2={y + s} />
      <line x1={x - s} y1={y + s} x2={x + s} y2={y - s} />
    </g>
  );
}

function Check({ x, y, color = SIG }: { x: number; y: number; color?: string }) {
  return (
    <path
      d={`M${x - 5} ${y} L${x - 1.5} ${y + 4} L${x + 5.5} ${y - 5}`}
      fill="none"
      stroke={color}
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  );
}

function mono(
  x: number,
  y: number,
  text: string,
  fill = FG,
  size = 11.5,
  anchor: "start" | "middle" | "end" = "middle",
) {
  return (
    <text x={x} y={y} textAnchor={anchor} fontFamily={MONO} fontSize={size} fill={fill}>
      {text}
    </text>
  );
}

function Glyph({ arch }: { arch: Arch }) {
  switch (arch) {
    case "periodic": {
      const xs = [178, 226, 274, 322, 370, 418, 466];
      return (
        <g>
          {xs.map((x, i) => (
            <line key={i} x1={x} y1={YC - 14} x2={x} y2={YC + 14} stroke={SIG} strokeWidth={2} />
          ))}
          {/* Δt bracket under the first gap, as in the approved mock. */}
          <path
            d={`M178 ${YC + 22} L178 ${YC + 28} L226 ${YC + 28} L226 ${YC + 22}`}
            fill="none"
            stroke={HAIR}
            strokeWidth={1}
          />
          {mono(202, YC + 42, "Δt", T4, 11)}
        </g>
      );
    }
    case "scan": {
      const ys = [54, 74, 94, 114, 134, 154, 174];
      const src: [number, number] = [176, YC];
      const px = 452;
      return (
        <g>
          {ys.map((y, i) => (
            <g key={i}>
              <line x1={src[0]} y1={src[1]} x2={px} y2={y} stroke={SIG} strokeWidth={1} opacity={0.6} />
              <circle cx={px} cy={y} r={3} fill={i === 3 ? SIG : CARD} stroke={i === 3 ? SIG : EDGE} strokeWidth={1} />
            </g>
          ))}
          {mono(px + 34, YC + 3, "dpt↑", T3, 10.5)}
        </g>
      );
    }
    case "sweep": {
      const xs = [206, 250, 294, 338, 382, 426, 470];
      const src: [number, number] = [176, YC - 34];
      return (
        <g>
          {xs.map((x, i) => (
            <g key={i}>
              <line x1={src[0]} y1={src[1]} x2={x} y2={YC + 42} stroke={SIG} strokeWidth={1} opacity={0.6} />
              <circle cx={x} cy={YC + 42} r={3} fill={CARD} stroke={EDGE} strokeWidth={1} />
            </g>
          ))}
          {mono(338, YC + 62, "dst .1 → .254", T3, 10.5)}
        </g>
      );
    }
    case "fanout": {
      const cx = 320;
      const cy = YC;
      const n = 9;
      return (
        <g>
          {Array.from({ length: n }).map((_, i) => {
            const a = (i / n) * Math.PI * 2;
            const x = cx + Math.cos(a) * 78;
            const y = cy + Math.sin(a) * 58;
            return (
              <g key={i}>
                <line x1={cx} y1={cy} x2={x} y2={y} stroke={SIG} strokeWidth={1} opacity={0.55} />
                <circle cx={x} cy={y} r={3} fill={CARD} stroke={EDGE} strokeWidth={1} />
              </g>
            );
          })}
          <circle cx={cx} cy={cy} r={4} fill={SIG} />
        </g>
      );
    }
    case "tunnel": {
      return (
        <g>
          <line x1={168} y1={YC} x2={214} y2={YC} stroke={EDGE} strokeWidth={1.2} />
          <rect x={214} y={YC - 13} width={214} height={26} rx={3} fill="none" stroke={SIG} strokeWidth={1.3} />
          {mono(321, YC + 4, "kf7x…q4z.sync.example.net", SIG, 10)}
          <line x1={428} y1={YC} x2={474} y2={YC} stroke={EDGE} strokeWidth={1.2} />
          <circle cx={480} cy={YC} r={4} fill={CARD} stroke={EDGE} strokeWidth={1} />
          {mono(480, YC + 20, "resolver", T3, 10.5)}
        </g>
      );
    }
    case "volume": {
      return (
        // Flat fill: the system allows no gradients, and the widening shape
        // already says "growing volume" on its own.
        <g>
          <path d={`M176 ${YC - 4} L430 ${YC - 16} L430 ${YC - 22} L470 ${YC} L430 ${YC + 22} L430 ${YC + 16} L176 ${YC + 4} Z`} fill={SIG} opacity={0.8} />
          <rect x={200} y={YC + 30} width={240} height={9} rx={3} fill="none" stroke={HAIR} strokeWidth={1} />
          <rect x={202} y={YC + 32} width={206} height={5} rx={2} fill={SIG} />
          {mono(320, YC + 56, "out ≫ in, sustained", T3, 10.5)}
        </g>
      );
    }
    case "auth": {
      const xs = [196, 256, 316, 376, 436];
      return (
        <g>
          <line x1={176} y1={YC} x2={470} y2={YC} stroke={EDGE} strokeWidth={1} strokeDasharray="2 3" />
          {xs.map((x, i) =>
            i < 4 ? <Cross key={i} x={x} y={YC} s={5} color={RED} /> : <Check key={i} x={x} y={YC} color={SIG} />,
          )}
          {mono(436, YC + 22, "success", SIG, 10.5)}
          {mono(256, YC + 22, "fail ×N", T3, 10.5)}
        </g>
      );
    }
    case "deny": {
      const ys = [64, 88, 112, 136, 160];
      return (
        <g>
          <rect x={444} y={48} width={12} height={128} fill="none" stroke={EDGE} strokeWidth={1} />
          {[56, 72, 88, 104, 120, 136, 152, 168].map((y, i) => (
            <line key={i} x1={444} y1={y} x2={456} y2={y - 8} stroke={EDGE} strokeWidth={0.8} />
          ))}
          {ys.map((y, i) => (
            <g key={i}>
              <line x1={182} y1={YC} x2={430} y2={y} stroke={SIG} strokeWidth={1} opacity={0.5} />
              <Cross x={434} y={y} s={4} color={RED} />
            </g>
          ))}
          {mono(360, YC + 74, "act=deny burst", T3, 10.5)}
        </g>
      );
    }
    case "newdest": {
      const known: [number, number][] = [
        [250, 78],
        [300, 150],
        [340, 92],
        [270, 128],
        [360, 138],
      ];
      return (
        <g>
          {known.map(([x, y], i) => (
            <g key={i}>
              <line x1={176} y1={YC} x2={x} y2={y} stroke={T4} strokeWidth={1} opacity={0.5} />
              <circle cx={x} cy={y} r={3} fill={CARD} stroke={T4} strokeWidth={1} />
            </g>
          ))}
          <line x1={176} y1={YC} x2={452} y2={74} stroke={SIG} strokeWidth={1.4} />
          <path
            d={pointsStar(452, 74, 6.5, 3)}
            fill={SIG}
          />
          {mono(452, 56, "new dst", SIG, 10.5)}
          {mono(300, 172, "known baseline", T3, 10.5)}
        </g>
      );
    }
    case "spike": {
      const base = YC + 30;
      const d = `M172 ${base} L250 ${base} L300 ${base - 4} L344 ${base - 66} L372 ${base - 8} L430 ${base - 6} L482 ${base}`;
      return (
        <g>
          <path d={`${d} L482 ${base + 2} L172 ${base + 2} Z`} fill={SIG} opacity={0.13} />
          <path d={d} fill="none" stroke={SIG} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
          <line x1={172} y1={base} x2={482} y2={base} stroke={T4} strokeWidth={0.8} strokeDasharray="2 3" />
          {mono(344, base - 74, "×20 events/s", SIG, 10.5)}
        </g>
      );
    }
    case "geo": {
      return (
        <g>
          <path d={`M212 158 Q320 46 452 84`} fill="none" stroke={SIG} strokeWidth={1.6} strokeDasharray="4 4" />
          <Pin x={208} y={158} label="geo A" />
          <Pin x={452} y={84} label="geo B" accent />
          {mono(332, 150, "Δt ≪ travel time", T3, 10.5)}
        </g>
      );
    }
    case "fleet": {
      // Three hosts on the same interval, each row jittered differently. The
      // aggregate keeps the beat even where a single row would slip a rule.
      const base = [200, 255, 310, 365, 420];
      const rows: { y: number; jitter: number[] }[] = [
        { y: YC - 28, jitter: [0, 6, -4, 8, 0] },
        { y: YC, jitter: [12, -6, 4, -8, 6] },
        { y: YC + 28, jitter: [-8, 4, 10, -4, -10] },
      ];
      return (
        <g>
          {rows.map((row, r) =>
            base.map((x, i) => (
              <line
                key={`${r}-${i}`}
                x1={x + row.jitter[i]}
                y1={row.y - 9}
                x2={x + row.jitter[i]}
                y2={row.y + 9}
                stroke={SIG}
                strokeWidth={2}
              />
            )),
          )}
          {mono(310, YC + 56, "3 hosts, one Δt", T3, 10.5)}
        </g>
      );
    }
    case "dga": {
      // A steady benign NXDOMAIN trickle on the left, then the algorithm: a
      // dense cluster of lookups all failing at once.
      const cluster = [356, 375, 394, 413, 432, 451, 470];
      return (
        <g>
          {[180, 235, 290].map((x) => (
            <line key={x} x1={x} y1={YC - 6} x2={x} y2={YC + 6} stroke={EDGE} strokeWidth={1.5} />
          ))}
          {cluster.map((x) => (
            <g key={x}>
              <line x1={x} y1={YC - 14} x2={x} y2={YC + 14} stroke={SIG} strokeWidth={2} />
              <Cross x={x} y={YC - 22} s={3} color={T4} />
            </g>
          ))}
          {mono(235, YC + 34, "typo trickle", T3, 10.5)}
          {mono(413, YC + 34, "nxdomain ×N", T3, 10.5)}
        </g>
      );
    }
    case "quiet": {
      // The signal is an absence: the resolver queries stop. The dashed box
      // marks where the traffic should be and is not.
      return (
        <g>
          {[176, 204, 232, 260, 288, 316].map((x) => (
            <line key={x} x1={x} y1={YC - 10} x2={x} y2={YC + 10} stroke={EDGE} strokeWidth={1.5} />
          ))}
          <rect
            x={348}
            y={YC - 22}
            width={130}
            height={44}
            rx={3}
            fill="none"
            stroke={SIG}
            strokeWidth={1.2}
            strokeDasharray="4 4"
          />
          {mono(413, YC + 4, "no dns:dns-query", SIG, 10)}
          {mono(246, YC + 32, "was steady", T3, 10.5)}
        </g>
      );
    }
    case "chain": {
      // One identity hopping host to host to host; the staggered path is what
      // separates a chain from an admin star with the same login count.
      const hops: [number, number][] = [
        [185, YC - 24],
        [280, YC + 16],
        [375, YC - 16],
        [470, YC + 24],
      ];
      return (
        <g>
          {hops.slice(1).map(([x, y], i) => (
            <line
              key={i}
              x1={hops[i][0]}
              y1={hops[i][1]}
              x2={x}
              y2={y}
              stroke={SIG}
              strokeWidth={1.4}
            />
          ))}
          {hops.map(([x, y], i) => (
            <circle
              key={i}
              cx={x}
              cy={y}
              r={4}
              fill={CARD}
              stroke={i === hops.length - 1 ? SIG : EDGE}
              strokeWidth={1.3}
            />
          ))}
          {mono(328, YC + 58, "same identity, new host each hop", T3, 10.5)}
        </g>
      );
    }
    case "spread": {
      // Worm propagation: each infected host becomes a source, so the src
      // population grows generation by generation.
      const gen1: [number, number][] = [
        [300, YC - 34],
        [300, YC + 34],
      ];
      const gen2: [number, number][] = [
        [430, YC - 56],
        [430, YC - 14],
        [430, YC + 14],
        [430, YC + 56],
      ];
      return (
        <g>
          {gen1.map(([x, y], i) => (
            <line key={`a${i}`} x1={190} y1={YC} x2={x} y2={y} stroke={SIG} strokeWidth={1.2} opacity={0.7} />
          ))}
          {gen2.map(([x, y], i) => (
            <line
              key={`b${i}`}
              x1={gen1[i < 2 ? 0 : 1][0]}
              y1={gen1[i < 2 ? 0 : 1][1]}
              x2={x}
              y2={y}
              stroke={SIG}
              strokeWidth={1.2}
              opacity={0.7}
            />
          ))}
          <circle cx={190} cy={YC} r={4} fill={SIG} />
          {[...gen1, ...gen2].map(([x, y], i) => (
            <circle key={`n${i}`} cx={x} cy={y} r={3.5} fill={CARD} stroke={EDGE} strokeWidth={1} />
          ))}
          {mono(310, YC + 76, "1 → 2 → 4 sources", T3, 10.5)}
        </g>
      );
    }
    case "inbound": {
      // The mirror of a scan: many external sources converging on one
      // perimeter address. Emitted as a false-positive source on purpose.
      const ys = [54, 74, 94, 114, 134, 154, 174];
      return (
        <g>
          {ys.map((y) => (
            <g key={y}>
              <line x1={190} y1={y} x2={452} y2={YC} stroke={SIG} strokeWidth={1} opacity={0.6} />
              <circle cx={190} cy={y} r={3} fill={CARD} stroke={EDGE} strokeWidth={1} />
            </g>
          ))}
          <circle cx={452} cy={YC} r={4} fill={CARD} stroke={EDGE} strokeWidth={1.2} />
          {mono(452, YC + 22, "perimeter", T3, 10.5)}
        </g>
      );
    }
    case "stages": {
      // Kill-chain order is the signal: the same three alerts shuffled would
      // not fire the rule, so the arrows matter more than the counts.
      const arrow = (x1: number, x2: number) => (
        <g stroke={EDGE} strokeWidth={1.2} fill="none">
          <line x1={x1} y1={YC} x2={x2} y2={YC} />
          <path d={`M${x2 - 5} ${YC - 3} L${x2} ${YC} L${x2 - 5} ${YC + 3}`} />
        </g>
      );
      return (
        <g>
          {[176, 190, 204].map((x) => (
            <line key={x} x1={x} y1={YC - 6} x2={x} y2={YC + 6} stroke={SIG} strokeWidth={2} />
          ))}
          {arrow(220, 300)}
          <line x1={316} y1={YC - 9} x2={316} y2={YC + 9} stroke={SIG} strokeWidth={2} />
          {arrow(332, 412)}
          <line x1={428} y1={YC - 12} x2={428} y2={YC + 12} stroke={SIG} strokeWidth={2} />
          {mono(190, YC + 30, "recon", T3, 10.5)}
          {mono(316, YC + 30, "exploit", T3, 10.5)}
          {mono(428, YC + 30, "c2", T3, 10.5)}
        </g>
      );
    }
    case "relay": {
      // Traffic in, the same traffic out, through one internal host that has
      // no business being a proxy.
      return (
        <g>
          <circle cx={180} cy={YC} r={3.5} fill={CARD} stroke={EDGE} strokeWidth={1} />
          {mono(180, YC + 20, "src", T3, 10)}
          <line x1={190} y1={YC} x2={276} y2={YC} stroke={SIG} strokeWidth={1.5} />
          {mono(233, YC - 10, "in", T4, 10)}
          <rect x={280} y={YC - 16} width={76} height={32} rx={3} fill="none" stroke={EDGE} strokeWidth={1.2} />
          {mono(318, YC + 4, "relay", FG, 10.5)}
          <line x1={360} y1={YC} x2={448} y2={YC} stroke={SIG} strokeWidth={1.5} />
          {mono(404, YC - 10, "out", T4, 10)}
          <circle cx={456} cy={YC} r={3.5} fill={CARD} stroke={EDGE} strokeWidth={1} />
          {mono(456, YC + 20, "dst", T3, 10)}
        </g>
      );
    }
  }
  return null;
}

function pointsStar(cx: number, cy: number, r: number, ri: number): string {
  const pts: string[] = [];
  for (let i = 0; i < 10; i++) {
    const rr = i % 2 === 0 ? r : ri;
    const a = (Math.PI / 5) * i - Math.PI / 2;
    pts.push(`${cx + Math.cos(a) * rr},${cy + Math.sin(a) * rr}`);
  }
  return `M${pts.join(" L")} Z`;
}

function Pin({ x, y, label, accent }: { x: number; y: number; label: string; accent?: boolean }) {
  const c = accent ? SIG : EDGE;
  return (
    <g>
      <path d={`M${x} ${y + 8} C${x - 8} ${y - 2} ${x - 6} ${y - 12} ${x} ${y - 12} C${x + 6} ${y - 12} ${x + 8} ${y - 2} ${x} ${y + 8} Z`} fill={CARD} stroke={c} strokeWidth={1.3} />
      <circle cx={x} cy={y - 5} r={2.4} fill={c} />
      {mono(x, y + 22, label, accent ? SIG : T3, 10.5)}
    </g>
  );
}

export function TechniqueDiagram({ technique }: { technique: Technique }) {
  const spec = DIAGRAM_SPECS[technique.id];

  // No fallback drawing. The old `?? "periodic"` rendered a DGA and an inbound
  // scan as fixed-interval beacons for months; a wrong diagram presented
  // confidently is worse than an honest gap. The coverage test keeps this
  // branch unreachable for catalog entries.
  if (!spec) {
    return (
      <svg viewBox="0 0 640 200" className="w-full" style={{ maxHeight: 240 }} role="img" aria-label={`${technique.name}: no diagram drawn yet`}>
        <line x1={24} y1={YC} x2={616} y2={YC} stroke={HAIR} strokeWidth={1} strokeDasharray="2 4" />
        {mono(320, YC - 12, "NO DIAGRAM DRAWN FOR THIS TECHNIQUE YET", T4, 11)}
      </svg>
    );
  }

  const caption = spec.caption ?? CAPTION[spec.glyph];
  const source = spec.source ?? ["host", "10.20.30.x"];

  return (
    <svg
      viewBox="0 0 640 200"
      className="w-full"
      style={{ maxHeight: 240 }}
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-label={`${technique.name} · ${caption}`}
    >
      <title>{`${technique.name}: ${caption}`}</title>

      {/* zone labels, in the machine voice */}
      <text x={24} y={26} fontFamily={MONO} fontSize={12} letterSpacing="-0.24" fill={T3}>
        SOURCE
      </text>
      <text x={320} y={26} textAnchor="middle" fontFamily={MONO} fontSize={12} letterSpacing="-0.24" fill={T3}>
        {caption.toUpperCase()}
      </text>
      <text x={616} y={26} textAnchor="end" fontFamily={MONO} fontSize={12} letterSpacing="-0.24" fill={T3}>
        DETECTION
      </text>

      {/* guide line */}
      <line x1={128} y1={YC} x2={506} y2={YC} stroke={HAIR} strokeWidth={1} strokeDasharray="2 4" />

      {/* source chip: an outline, not a fill, like every node in the mock */}
      <rect x={22} y={YC - 18} width={104} height={36} rx={3} fill="none" stroke={HAIR} strokeWidth={1} />
      {mono(74, YC - 2, source[0].toUpperCase(), FG, 11.5)}
      {mono(74, YC + 12, source[1], T4, 10)}

      {/* behavior glyph */}
      <Glyph arch={spec.glyph} />

      {/* detection chip: the orange outline is the card's second chromatic
          element; no fill wash and no pulsing dot behind it */}
      <rect x={512} y={YC - 20} width={106} height={40} rx={3} fill="none" stroke={SIG} strokeWidth={1.2} />
      {mono(565, YC - 4, technique.ndr_uc, FG, 11)}
      {mono(565, YC + 12, technique.ndr_rule, T3, 10.5)}
    </svg>
  );
}
