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
import { startRun, stopRun, getRunStatus, runEventsUrl, type Collector, type Manifest, type Technique } from "@/lib/api";
import { pollRunUntilTerminal } from "@/lib/runLifecycle";
import { anchorNotice, defaultAnchor, type AnchorChoice } from "@/lib/anchor";

interface Props {
  technique: Technique | null;
  defaultSeed: number;
  collector: Collector | null;
  vendor: string;
  epsCap: number;
  anchorEpoch: number;
}

const MAX_VISIBLE = 800;
const SAMPLE_MS = 220;
// Number of plotted samples. Exported alongside SAMPLE_MS so the readout can
// label the real window instead of a hardcoded guess.
const SAMPLE_WINDOW = 48;
// Report the rate over at least one full limiter period.
//
// The emitter is a FIXED-WINDOW limiter: it sends at full speed until a
// one-second window fills, then sleeps out the remainder. Sampling that every
// 220ms aliases badly, because a sample lands either inside a burst or inside a
// sleep. Observed live: the readout alternated between ~5300/s and 0/s while the
// run was steadily delivering ~1660/s, and it displayed "0 events / sec" next to
// an "EMITTING" indicator.
//
// Averaging over a trailing second spans a whole burst-plus-sleep cycle, so the
// number shown is the rate actually being delivered.
const RATE_WINDOW_MS = 1000;

function fmtDur(sec: number): string {
  const s = Math.max(0, Math.floor(sec));
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${String(s % 60).padStart(2, "0")}s` : `${s}s`;
}

export function RunPanel({ technique, defaultSeed, collector, vendor, epsCap, anchorEpoch }: Props) {
  const [intensity, setIntensity] = useState("medium");
  const [duration, setDuration] = useState("");
  const [seed, setSeed] = useState(String(defaultSeed));
  const [sendToCollector, setSendToCollector] = useState(false);
  const [toFile, setToFile] = useState(false);
  const [filePath, setFilePath] = useState("./out/replicant.log");
  const [anchor, setAnchor] = useState<AnchorChoice>(defaultAnchor(false));

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
  const mountedRef = useRef(true);
  // Trailing observations of (timestamp, cumulative count), used to average the
  // emission rate over RATE_WINDOW_MS instead of over a single 220ms tick.
  const historyRef = useRef<{ t: number; c: number }[]>([]);

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

  // Follow the destination. Changing where the events go changes which anchor is
  // correct, so the control resets to the right default for the new destination
  // rather than silently carrying the previous choice into a run where it is wrong.
  useEffect(() => {
    setAnchor(defaultAnchor(sendToCollector && collector !== null));
  }, [sendToCollector, collector]);

  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => {
      const now = performance.now();
      const history = historyRef.current;
      history.push({ t: now, c: countRef.current });

      // Drop observations older than the rate window, but always keep the one
      // immediately preceding it so the window stays a full RATE_WINDOW_MS wide
      // rather than collapsing toward the newest sample.
      const cutoff = now - RATE_WINDOW_MS;
      let firstFresh = 0;
      while (firstFresh < history.length && history[firstFresh].t < cutoff) firstFresh++;
      if (firstFresh > 0) history.splice(0, firstFresh - 1);

      const oldest = history[0];
      const dt = (now - oldest.t) / 1000;
      if (dt > 0) {
        const rate = Math.max(0, (countRef.current - oldest.c) / dt);
        setEps(Math.round(rate));
        setSamples((s) => [...s.slice(-(SAMPLE_WINDOW - 1)), rate]);
      }
      setElapsed(fmtDur((now - startRef.current) / 1000));
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, SAMPLE_MS);
    return () => clearInterval(timer);
  }, [running]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      esRef.current?.close();
    };
  }, []);

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
    historyRef.current = [{ t: performance.now(), c: 0 }];
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
      anchor,
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
        es.close();
        // A dropped SSE stream is not run completion: the backend worker may still
        // be emitting. Keep the run active (Stop stays available) and poll the
        // authoritative status until the backend itself reports terminal.
        setError("live stream interrupted; polling run status…");
        void pollRunUntilTerminal({
          getStatus: () => getRunStatus(run_id),
          onProgress: (c) => {
            if (!mountedRef.current) return;
            countRef.current = Math.max(countRef.current, c);
            setCount((x) => Math.max(x, c));
          },
          onTerminal: (snap) => {
            if (!mountedRef.current) return;
            countRef.current = Math.max(countRef.current, snap.event_count);
            setCount((x) => Math.max(x, snap.event_count));
            if (snap.manifest) setManifest(snap.manifest as Manifest);
            setError(snap.status === "error" ? "run failed" : null);
            setRunning(false);
          },
          sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
          // Stop polling if the view unmounts or a newer run supersedes this one.
          isCancelled: () => !mountedRef.current || runIdRef.current !== run_id,
        });
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
      <div className="u-label mb-3">Arm run</div>

      {/* controls */}
      <div className="mt-[18px] grid grid-cols-[132px_92px_92px_112px_1fr] items-end gap-3 border-y py-[18px]">
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
        <div>
          <label className="u-label mb-1.5 block">Anchor</label>
          <Select value={anchor} onValueChange={(v) => setAnchor(v as AnchorChoice)}>
            <SelectTrigger className="h-9 text-[13px]" aria-label="Event time anchor">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="now">now</SelectItem>
              <SelectItem value="fixed">fixed</SelectItem>
            </SelectContent>
          </Select>
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
      {anchorNotice(anchor, sendToCollector && collector !== null, anchorEpoch) && (
        <div
          role="status"
          className="mt-2.5 rounded-md border border-signal/40 bg-signal/10 p-2.5 text-[12px] leading-relaxed text-signal"
        >
          {anchorNotice(anchor, sendToCollector && collector !== null, anchorEpoch)}
        </div>
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
        cap={epsCap}
        samples={samples}
        windowSeconds={Math.round((SAMPLE_WINDOW * SAMPLE_MS) / 1000)}
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
