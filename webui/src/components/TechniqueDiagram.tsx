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
  | "geo";

const ARCH: Record<string, Arch> = {
  "REP-001": "periodic",
  "REP-002": "scan",
  "REP-003": "sweep",
  "REP-004": "tunnel",
  "REP-005": "volume",
  "REP-006": "fanout",
  "REP-007": "auth",
  "REP-008": "newdest",
  "REP-009": "spike",
  "REP-010": "deny",
  "REP-011": "geo",
};

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
};

const USER_ARCH = new Set<Arch>(["auth", "geo"]);
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
  const arch = ARCH[technique.id] ?? "periodic";
  const source = USER_ARCH.has(arch) ? ["user", "jsmith"] : ["host", "10.20.30.x"];

  return (
    <svg
      viewBox="0 0 640 200"
      className="w-full"
      style={{ maxHeight: 240 }}
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-label={`${technique.name} — ${CAPTION[arch]}`}
    >
      <title>{`${technique.name}: ${CAPTION[arch]}`}</title>

      {/* zone labels, in the machine voice */}
      <text x={24} y={26} fontFamily={MONO} fontSize={12} letterSpacing="-0.24" fill={T3}>
        SOURCE
      </text>
      <text x={320} y={26} textAnchor="middle" fontFamily={MONO} fontSize={12} letterSpacing="-0.24" fill={T3}>
        {CAPTION[arch].toUpperCase()}
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
      <Glyph arch={arch} />

      {/* detection chip: the orange outline is the card's second chromatic
          element; no fill wash and no pulsing dot behind it */}
      <rect x={512} y={YC - 20} width={106} height={40} rx={3} fill="none" stroke={SIG} strokeWidth={1.2} />
      {mono(565, YC - 4, technique.ndr_uc, FG, 11)}
      {mono(565, YC + 12, technique.ndr_rule, T3, 10.5)}
    </svg>
  );
}
