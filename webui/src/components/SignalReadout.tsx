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

// The war-room frame: Replicant's live instrument. A darker dashboard panel
// holding the run's metric tiles, an instrumented sparkline of the emission
// rate, and the plan progress track.
//
// Every number here derives from the same counters the run reports; nothing is
// invented for the display. The mock's bytes tile does not ship because the
// stream carries no byte counter, and a readout that cannot be measured must
// not render. All values are RENDERED/EMITTED counts: on UDP nothing here
// proves delivery, which is why no wording in this frame claims it.

interface Props {
  eps: number;
  cap: number;
  // Whether the cap is actually governing this run. The events-per-second cap is
  // only enforced where there is an emitter to throttle, so a dry run or a
  // file-only run is not limited at all. Printing "cap 2000" next to a measured
  // rate ten times that is a true number under a false label, which reads as the
  // cap being broken.
  capApplies: boolean;
  samples: number[];
  pct: number;
  running: boolean;
  count: number;
  total: number;
  elapsedLabel: string;
  // Seconds of history the waveform actually covers. Passed in rather than
  // hardcoded: the label read "window 30s" while the plot held 48 samples at
  // 220ms, which is 10.6s.
  windowSeconds: number;
}

const W = 220;
const H = 44;
const TOP = 4;
const BOTTOM = 32;
const LEFT = 16; // room for the scale labels

export function SignalReadout({
  eps,
  cap,
  capApplies,
  samples,
  pct,
  running,
  count,
  total,
  elapsedLabel,
  windowSeconds,
}: Props) {
  // When the cap applies it puts a floor under the scale, so a small rate sits
  // near the baseline instead of dramatically filling the band (DEF-002's
  // guard). The top hairline is labeled with the real scale value either way,
  // so the plot always says what its own ceiling is.
  const scale = Math.max(...samples, capApplies ? cap * 0.25 : 0, 1);
  const mean = samples.length > 0 ? samples.reduce((a, b) => a + b, 0) / samples.length : 0;
  const yFor = (v: number) => BOTTOM - (Math.min(v, scale) / scale) * (BOTTOM - TOP);
  const pts = samples.map((v, i) => {
    const x = LEFT + (i / Math.max(samples.length - 1, 1)) * (W - LEFT - 4);
    return [x, yFor(v)] as const;
  });
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  const last = pts[pts.length - 1];

  return (
    <div className="my-6 overflow-hidden rounded-lg border bg-frame">
      {/* frame bar */}
      <div className="flex items-center gap-4 border-b border-elev px-6 py-4">
        <div className="flex gap-2" aria-hidden="true">
          <span className="block h-2 w-2 rounded-full bg-border" />
          <span className="block h-2 w-2 rounded-full bg-border" />
          <span className="block h-2 w-2 rounded-full bg-border" />
        </div>
        <span className="font-mono text-label uppercase tracking-[-0.24px] text-text-4">
          Replicant — emission
        </span>
        {running ? (
          <span className="ml-auto flex items-center gap-2 font-mono text-label uppercase tracking-[-0.24px] text-signal">
            <span className="block h-1.5 w-1.5 rounded-full bg-signal" />
            emitting
          </span>
        ) : (
          <span className="ml-auto flex items-center gap-2 font-mono text-label uppercase tracking-[-0.24px] text-text-4">
            <span className="block h-1.5 w-1.5 rounded-full bg-text-4" />
            idle
          </span>
        )}
      </div>

      {/* metric tiles */}
      <div className="flex flex-col sm:flex-row">
        <div className="flex-1 border-b border-elev p-5 sm:border-b-0">
          <div className="mb-3 font-mono text-label uppercase tracking-[-0.24px] text-text-4">
            Events emitted
          </div>
          <div className="text-title tracking-[-0.9px] text-foreground">
            {count.toLocaleString()}
          </div>
          <div className="mt-2 font-mono text-label uppercase tracking-[-0.24px] text-text-4">
            {total > 0 ? `of ${total.toLocaleString()} planned` : "no plan armed"}
          </div>
        </div>

        <div className="flex-1 border-b border-elev p-5 sm:border-b-0 sm:border-l">
          <div className="mb-3 font-mono text-label uppercase tracking-[-0.24px] text-text-4">
            Rate
          </div>
          <div className="text-title tracking-[-0.9px] text-foreground">
            {eps.toLocaleString()}{" "}
            <span className="font-mono text-label uppercase tracking-[-0.24px] text-text-4">
              eps
            </span>
          </div>
          {/* The instrumented sparkline: scale hairlines with real values, the
              dotted mean, a time axis. A line on its own is decoration; the
              scale is what makes it a reading. */}
          <svg
            className="mt-2 block h-11 w-full max-w-[220px]"
            viewBox={`0 0 ${W} ${H}`}
            preserveAspectRatio="none"
            role="img"
            aria-label={`Emission rate over the last ${windowSeconds} seconds`}
          >
            <line x1={LEFT} y1={TOP} x2={W} y2={TOP} stroke="hsl(var(--elev))" strokeWidth="1" />
            <line x1={LEFT} y1={BOTTOM} x2={W} y2={BOTTOM} stroke="hsl(var(--elev))" strokeWidth="1" />
            <text x="0" y={TOP + 3} fontFamily="'JetBrains Mono',monospace" fontSize="8" fill="hsl(var(--text-4))">
              {Math.round(scale)}
            </text>
            <text x="0" y={BOTTOM + 2.5} fontFamily="'JetBrains Mono',monospace" fontSize="8" fill="hsl(var(--text-4))">
              0
            </text>
            {samples.length > 1 && (
              <line
                x1={LEFT}
                y1={yFor(mean)}
                x2={W}
                y2={yFor(mean)}
                stroke="hsl(var(--border))"
                strokeWidth="1"
                strokeDasharray="1.5 3.5"
              />
            )}
            {samples.length > 0 && (
              <path d={line} fill="none" stroke="hsl(var(--signal))" strokeWidth="1.5" />
            )}
            {last && <circle cx={last[0]} cy={last[1]} r="2.5" fill="hsl(var(--signal))" />}
            <text x={LEFT} y={H - 1} fontFamily="'JetBrains Mono',monospace" fontSize="8" fill="hsl(var(--text-4))">
              T-{windowSeconds}S
            </text>
            <text x={W} y={H - 1} textAnchor="end" fontFamily="'JetBrains Mono',monospace" fontSize="8" fill="hsl(var(--text-4))">
              NOW
            </text>
          </svg>
        </div>

        <div className="flex-1 p-5 sm:border-l sm:border-elev">
          <div className="mb-3 font-mono text-label uppercase tracking-[-0.24px] text-text-4">
            Elapsed
          </div>
          <div className="font-mono text-title tracking-[-0.9px] text-foreground">
            {elapsedLabel}
          </div>
          <div
            className="mt-2 font-mono text-label uppercase tracking-[-0.24px] text-text-4"
            title={
              capApplies
                ? `Sends are held to ${cap} events per second.`
                : "The events-per-second cap governs sending. This run has no collector, " +
                  "so nothing throttles it and the rate can exceed the configured cap."
            }
          >
            {capApplies ? `cap ${cap} eps` : "uncapped"} · window {windowSeconds}s
          </div>
        </div>
      </div>

      {/* progress track */}
      <div className="px-6 pb-5 pt-2">
        <div className="relative mb-3 h-0.5 bg-elev">
          <div
            className="absolute inset-y-0 left-0 bg-signal transition-[width]"
            style={{ width: `${pct}%` }}
          />
        </div>
        <div className="font-mono text-label uppercase tracking-[-0.24px] text-text-4">
          {pct}%{total > 0 ? ` · ${count.toLocaleString()} of ${total.toLocaleString()}` : ""}
        </div>
      </div>
    </div>
  );
}
