// The signal readout: Replicant's ownable motif. Shows the live emission rate
// (events per second) over the run window as a waveform, against the eps cap.
// Data is real: `samples` are eps values sampled from the run's count deltas.

interface Props {
  eps: number;
  cap: number;
  samples: number[];
  pct: number;
  running: boolean;
  count: number;
  total: number;
  elapsedLabel: string;
}

const W = 900;
const H = 76;
const TOP = 14;
const BOTTOM = 66;

export function SignalReadout({ eps, cap, samples, pct, running, count, total, elapsedLabel }: Props) {
  const scale = Math.max(cap * 0.25, ...samples, 1);
  const span = W * 0.66; // the emitted portion; the rest is the projection lane
  const pts =
    samples.length > 0
      ? samples.map((v, i) => {
          const x = (i / Math.max(samples.length - 1, 1)) * span;
          const y = BOTTOM - (Math.min(v, scale) / scale) * (BOTTOM - TOP);
          return `${x.toFixed(1)} ${y.toFixed(1)}`;
        })
      : [`0 ${BOTTOM}`];
  const line = "M" + pts.join(" L");
  const area = `${line} L${span.toFixed(1)} ${H} L0 ${H} Z`;

  return (
    <div className="my-5 overflow-hidden rounded-[10px] border bg-[linear-gradient(180deg,hsl(var(--signal)_/_0.03),transparent_40%)]">
      <div className="flex items-center justify-between px-4 pb-1.5 pt-3.5">
        <div className="flex items-baseline gap-2">
          <span className="font-mono text-[25px] font-medium leading-none tracking-tight text-signal">
            {eps}
          </span>
          <span className="font-mono text-[11px] text-text-3">events / sec</span>
          {running && (
            <span className="ml-1.5 inline-flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-signal">
              <span className="h-[5px] w-[5px] rounded-full bg-signal" />
              emitting
            </span>
          )}
        </div>
        <span className="font-mono text-[11px] text-text-3">cap {cap} · window 30s</span>
      </div>

      <svg className="block h-[76px] w-full" viewBox="0 0 900 76" preserveAspectRatio="none">
        <line
          x1="0"
          y1="15"
          x2="900"
          y2="15"
          stroke="hsl(var(--foreground) / 0.06)"
          strokeWidth="1"
          strokeDasharray="3 5"
        />
        <path d={area} fill="url(#sig-fill)" />
        <path
          d={line}
          fill="none"
          stroke="hsl(var(--signal))"
          strokeWidth="1.7"
          strokeLinejoin="round"
        />
        <path
          d={`M${span} ${pts.length ? pts[pts.length - 1].split(" ")[1] : BOTTOM} L900 ${
            pts.length ? pts[pts.length - 1].split(" ")[1] : BOTTOM
          }`}
          fill="none"
          stroke="hsl(var(--text-4))"
          strokeWidth="1.3"
          strokeDasharray="2 3"
        />
        <defs>
          <linearGradient id="sig-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="hsl(var(--signal))" stopOpacity="0.15" />
            <stop offset="1" stopColor="hsl(var(--signal))" stopOpacity="0" />
          </linearGradient>
        </defs>
      </svg>

      <div className="relative h-[3px] bg-black">
        <div className="absolute inset-y-0 left-0 bg-signal transition-[width]" style={{ width: `${pct}%` }} />
      </div>

      <div className="flex justify-between border-t px-4 py-2.5 font-mono text-[11px] text-text-3">
        <span>
          elapsed <b className="font-medium text-muted-foreground">{elapsedLabel}</b>
        </span>
        <span>
          emitted <b className="font-medium text-muted-foreground">{count}</b>
          {total ? ` / est ${total}` : ""}
        </span>
      </div>
    </div>
  );
}
