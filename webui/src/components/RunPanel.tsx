import { useEffect, useRef, useState } from "react";
import { Play, Square } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SignalReadout } from "@/components/SignalReadout";
import { cn } from "@/lib/utils";
import { startRun, stopRun, runEventsUrl, type Collector, type Manifest, type Technique } from "@/lib/api";

interface Props {
  technique: Technique | null;
  defaultSeed: number;
  collector: Collector | null;
  vendor: string;
}

const MAX_VISIBLE = 800;
const SAMPLE_MS = 220;

function fmtDur(sec: number): string {
  const s = Math.max(0, Math.floor(sec));
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${String(s % 60).padStart(2, "0")}s` : `${s}s`;
}

export function RunPanel({ technique, defaultSeed, collector, vendor }: Props) {
  const [intensity, setIntensity] = useState("medium");
  const [duration, setDuration] = useState("");
  const [seed, setSeed] = useState(String(defaultSeed));
  const [sendToCollector, setSendToCollector] = useState(false);
  const [toFile, setToFile] = useState(false);
  const [filePath, setFilePath] = useState("./out/replicant.log");

  const [running, setRunning] = useState(false);
  const [count, setCount] = useState(0);
  const [total, setTotal] = useState(0);
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [eps, setEps] = useState(0);
  const [samples, setSamples] = useState<number[]>([]);
  const [elapsed, setElapsed] = useState("0s");

  const linesRef = useRef<string[]>([]);
  const esRef = useRef<EventSource | null>(null);
  const runIdRef = useRef<string | null>(null);
  const logRef = useRef<HTMLDivElement | null>(null);
  const countRef = useRef(0);
  const startRef = useRef(0);
  const lastRef = useRef({ t: 0, c: 0 });

  useEffect(() => setSeed(String(defaultSeed)), [defaultSeed]);
  useEffect(() => {
    if (technique && !technique.intensities.includes(intensity)) {
      setIntensity(technique.intensities.includes("medium") ? "medium" : technique.intensities[0]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [technique]);
  useEffect(() => {
    if (collector === null) setSendToCollector(false);
  }, [collector]);

  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => {
      const now = performance.now();
      const dt = (now - lastRef.current.t) / 1000;
      const dc = countRef.current - lastRef.current.c;
      if (dt > 0) {
        const inst = Math.max(0, dc / dt);
        setEps(Math.round(inst));
        setSamples((s) => [...s.slice(-47), inst]);
        lastRef.current = { t: now, c: countRef.current };
      }
      setElapsed(fmtDur((now - startRef.current) / 1000));
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, SAMPLE_MS);
    return () => clearInterval(timer);
  }, [running]);

  useEffect(() => () => esRef.current?.close(), []);

  function reset() {
    linesRef.current = [];
    setCount(0);
    setTotal(0);
    setManifest(null);
    setError(null);
    setEps(0);
    setSamples([]);
    setElapsed("0s");
    countRef.current = 0;
    startRef.current = performance.now();
    lastRef.current = { t: performance.now(), c: 0 };
  }

  async function handleStart() {
    if (!technique) return;
    reset();
    const body = {
      technique_id: technique.id,
      intensity,
      duration: duration.trim() || null,
      seed: Number(seed),
      to_file: toFile ? filePath : null,
      no_send: !(sendToCollector && collector),
      collector: sendToCollector ? collector : null,
      vendor,
    };
    try {
      const { run_id, total: est } = await startRun(body);
      runIdRef.current = run_id;
      setTotal(est);
      setRunning(true);
      const es = new EventSource(runEventsUrl(run_id));
      esRef.current = es;
      es.onmessage = (evt) => {
        const item = JSON.parse(evt.data);
        if (item.type === "line") {
          const arr = linesRef.current;
          arr.push(item.data);
          if (arr.length > MAX_VISIBLE) arr.splice(0, arr.length - MAX_VISIBLE);
          countRef.current = Math.max(countRef.current, arr.length);
          setCount((c) => Math.max(c, arr.length));
        } else if (item.type === "progress") {
          countRef.current = item.count;
          setCount(item.count);
        } else if (item.type === "done") {
          countRef.current = item.count;
          setCount(item.count);
          setManifest(item.manifest);
          setRunning(false);
          es.close();
        } else if (item.type === "error") {
          setError(item.message);
          setRunning(false);
          es.close();
        }
      };
      es.onerror = () => {
        setRunning(false);
        es.close();
      };
    } catch (err) {
      setError((err as Error).message);
      setRunning(false);
    }
  }

  async function handleStop() {
    if (runIdRef.current) await stopRun(runIdRef.current).catch(() => undefined);
  }

  if (!technique) {
    return (
      <div className="flex h-full min-h-[320px] items-center justify-center">
        <div className="max-w-xs text-center">
          <svg viewBox="0 0 200 22" preserveAspectRatio="none" className="mx-auto mb-4 h-5 w-40">
            <line x1="0" y1="17" x2="200" y2="17" stroke="hsl(var(--text-4))" strokeWidth="1.4" strokeDasharray="2 3" />
          </svg>
          <p className="text-sm text-muted-foreground">Select a technique to arm a run.</p>
        </div>
      </div>
    );
  }

  const canRun = technique.implemented && !running;
  const pct = total > 0 ? Math.min(100, Math.round((count / total) * 100)) : running ? 5 : 0;

  return (
    <div className="mx-auto max-w-[900px]">
      {/* run header */}
      <div className="font-mono text-[11.5px] font-medium tracking-wide text-muted-foreground">
        {technique.id} · {technique.ndr_uc}
      </div>
      <h1 className="mt-1 text-[23px] font-semibold tracking-[-0.028em]">{technique.name}</h1>
      <p className="mt-1.5 max-w-[580px] text-[13px] leading-relaxed text-muted-foreground">
        Exercises the detection <span className="text-foreground">{technique.ndr_rule}</span> over{" "}
        {technique.log_type}:{technique.subtype} telemetry.
      </p>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {technique.attack.map((a) => (
          <span key={a} className="rounded border px-1.5 py-0.5 font-mono text-[10.5px] text-text-3">
            {a}
          </span>
        ))}
        {!technique.implemented && (
          <span className="rounded border border-signal/40 px-1.5 py-0.5 font-mono text-[10.5px] text-signal">
            not runnable yet
          </span>
        )}
      </div>

      {/* controls */}
      <div className="mt-[18px] grid grid-cols-[148px_104px_104px_1fr] items-end gap-3 border-y py-[18px]">
        <div>
          <label className="u-label mb-1.5 block">Intensity</label>
          <Select value={intensity} onValueChange={setIntensity}>
            <SelectTrigger className="h-9 text-[13px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {(technique.intensities.length ? technique.intensities : ["low", "medium", "high"]).map((i) => (
                <SelectItem key={i} value={i}>
                  {i}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="u-label mb-1.5 block" htmlFor="duration">
            Duration
          </label>
          <Input
            id="duration"
            className="h-9 font-mono text-[13px]"
            placeholder="preset"
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
          />
        </div>
        <div>
          <label className="u-label mb-1.5 block" htmlFor="seed">
            Seed
          </label>
          <Input
            id="seed"
            className="h-9 font-mono text-[13px]"
            value={seed}
            onChange={(e) => setSeed(e.target.value)}
          />
        </div>
        <div className="flex flex-col items-end gap-2">
          <span className="u-label">Destination</span>
          <div className="flex gap-4">
            <label className={cn("flex items-center gap-2 text-[12.5px]", collector ? "text-muted-foreground" : "text-text-4")}>
              <Switch checked={sendToCollector} onCheckedChange={setSendToCollector} disabled={!collector} />
              Collector
            </label>
            <label className="flex items-center gap-2 text-[12.5px] text-muted-foreground">
              <Switch checked={toFile} onCheckedChange={setToFile} />
              File
            </label>
          </div>
        </div>
      </div>

      {!collector && (
        <p className="mt-2.5 font-mono text-[11px] leading-relaxed text-text-3">
          No collector configured. Sends fail closed. Connect one, or write to file.
        </p>
      )}
      {toFile && (
        <Input
          className="mt-2.5 h-8 max-w-xs font-mono text-[12px]"
          value={filePath}
          onChange={(e) => setFilePath(e.target.value)}
        />
      )}

      {/* run controls */}
      <div className="mt-4 flex gap-2">
        <button
          onClick={handleStart}
          disabled={!canRun}
          className="inline-flex h-9 items-center gap-2 rounded-md bg-primary px-4 text-[13px] font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Play className="h-3.5 w-3.5" />
          Start run
        </button>
        <button
          onClick={handleStop}
          disabled={!running}
          className="inline-flex h-9 items-center gap-2 rounded-md border px-4 text-[13px] font-medium text-muted-foreground transition-colors hover:text-foreground disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Square className="h-3 w-3" />
          Stop
        </button>
      </div>

      {error && (
        <div className="mt-4 rounded-md border border-destructive/40 bg-destructive/10 p-2.5 text-[12px] text-destructive">
          {error}
        </div>
      )}

      <SignalReadout
        eps={eps}
        cap={2000}
        samples={samples}
        pct={pct}
        running={running}
        count={count}
        total={total}
        elapsedLabel={elapsed}
      />

      {/* live stream */}
      <div className="mb-2 mt-[22px] flex items-center justify-between">
        <span className="u-label">Live CEF · {vendor}</span>
        <span className="font-mono text-[10.5px] text-text-3">tail · last {MAX_VISIBLE}</span>
      </div>
      <div
        ref={logRef}
        className="scroll-thin h-[132px] overflow-y-auto rounded-lg border bg-black/40 p-3 font-mono text-[11px] leading-[1.85] text-text-3"
      >
        {linesRef.current.length === 0 ? (
          <div className="grid h-full place-items-center text-text-4">
            {running ? "waiting for events…" : "Streamed CEF appears here on run."}
          </div>
        ) : (
          linesRef.current.map((line, i) => (
            <div key={i} className="truncate">
              {line}
            </div>
          ))
        )}
      </div>

      {/* manifest */}
      {manifest && (
        <div className="mt-4 rounded-lg border p-4">
          <div className="mb-3 flex items-center gap-2 text-[12.5px] font-semibold">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-muted-foreground">
              <path d="M2.5 7.5 L5.5 10.5 L11.5 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            Run complete · manifest written
          </div>
          <div className="grid grid-cols-4 gap-x-5 gap-y-3">
            {[
              ["events", manifest.event_count],
              ["seed", manifest.seed],
              ["intensity", manifest.intensity],
              ["use case", manifest.ndr_uc],
              ["target", manifest.target],
              ["transport", manifest.transport],
              ["anchor", manifest.anchor_epoch],
            ].map(([k, v]) => (
              <div key={k} className="u-label">
                {k}
                <b className="mt-0.5 block font-mono text-[12.5px] font-medium normal-case tracking-normal text-foreground">
                  {String(v)}
                </b>
              </div>
            ))}
          </div>
          {manifest.warmup_note && (
            <div className="mt-3 font-mono text-[11px] text-text-3">note: {manifest.warmup_note}</div>
          )}
        </div>
      )}
    </div>
  );
}
