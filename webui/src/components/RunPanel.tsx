import { useEffect, useRef, useState } from "react";
import { Play, Square, FileText, Radio } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  startRun,
  stopRun,
  runEventsUrl,
  type Collector,
  type Manifest,
  type Technique,
} from "@/lib/api";

interface Props {
  technique: Technique | null;
  defaultSeed: number;
  collector: Collector | null;
  vendor: string;
}

const MAX_VISIBLE = 800;

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
  const [, setTick] = useState(0);

  const linesRef = useRef<string[]>([]);
  const esRef = useRef<EventSource | null>(null);
  const runIdRef = useRef<string | null>(null);
  const logRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => setSeed(String(defaultSeed)), [defaultSeed]);
  useEffect(() => {
    if (technique && !technique.intensities.includes(intensity)) {
      setIntensity(technique.intensities.includes("medium") ? "medium" : technique.intensities[0]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [technique]);

  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => {
      setTick((t) => t + 1);
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, 120);
    return () => clearInterval(timer);
  }, [running]);

  useEffect(() => () => esRef.current?.close(), []);

  function reset() {
    linesRef.current = [];
    setCount(0);
    setTotal(0);
    setManifest(null);
    setError(null);
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
          setCount((c) => Math.max(c, arr.length));
        } else if (item.type === "progress") {
          setCount(item.count);
        } else if (item.type === "done") {
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

  const canRun = technique?.implemented && !running;
  const pct = total > 0 ? Math.min(100, Math.round((count / total) * 100)) : running ? 5 : 0;

  return (
    <Card className="flex min-h-0 flex-1 flex-col">
      <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-base">
          {technique ? `${technique.id} · ${technique.name}` : "Select a technique"}
        </CardTitle>
        {technique && !technique.implemented && <Badge variant="muted">Phase 2 (not runnable)</Badge>}
      </CardHeader>
      <CardContent className="flex min-h-0 flex-1 flex-col gap-3">
        <div className="grid grid-cols-3 gap-2">
          <div className="space-y-1">
            <Label>Intensity</Label>
            <Select value={intensity} onValueChange={setIntensity} disabled={!technique}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(technique?.intensities ?? ["low", "medium", "high"]).map((i) => (
                  <SelectItem key={i} value={i}>
                    {i}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="duration">Duration</Label>
            <Input
              id="duration"
              placeholder="2m · blank=preset"
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="seed">Seed</Label>
            <Input id="seed" value={seed} onChange={(e) => setSeed(e.target.value)} />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-4 rounded-md border p-2 text-sm">
          <label className="flex items-center gap-2">
            <Switch
              checked={sendToCollector}
              onCheckedChange={setSendToCollector}
              disabled={!collector}
            />
            <Radio className="h-3.5 w-3.5" />
            Send to collector
            {!collector && <span className="text-xs text-muted-foreground">(none set)</span>}
          </label>
          <label className="flex items-center gap-2">
            <Switch checked={toFile} onCheckedChange={setToFile} />
            <FileText className="h-3.5 w-3.5" />
            Write to file
          </label>
          {toFile && (
            <Input
              className="h-7 w-56 font-mono text-xs"
              value={filePath}
              onChange={(e) => setFilePath(e.target.value)}
            />
          )}
        </div>

        <div className="flex items-center gap-2">
          <Button onClick={handleStart} disabled={!canRun}>
            <Play className="h-4 w-4" /> Start
          </Button>
          <Button variant="destructive" onClick={handleStop} disabled={!running}>
            <Square className="h-4 w-4" /> Stop
          </Button>
          <div className="ml-2 flex-1">
            <div className="h-2 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full bg-primary transition-all"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
          <span className="font-mono text-xs text-muted-foreground">
            {count}
            {total ? ` / ${total}` : ""}
          </span>
        </div>

        {error && (
          <div className="rounded-md border border-destructive/40 p-2 text-xs text-destructive">
            {error}
          </div>
        )}

        <div
          ref={logRef}
          className="min-h-0 flex-1 overflow-y-auto scroll-thin rounded-md border bg-background/60 p-2 font-mono text-[11px] leading-relaxed"
        >
          {linesRef.current.length === 0 && !manifest ? (
            <div className="p-4 text-center text-muted-foreground">
              Streamed CEF lines appear here.
            </div>
          ) : (
            linesRef.current.map((line, i) => (
              <div key={i} className="whitespace-pre-wrap break-all text-muted-foreground">
                {line}
              </div>
            ))
          )}
        </div>

        {manifest && (
          <div className="rounded-md border bg-card p-3 text-xs">
            <div className="mb-1 font-semibold text-primary">Run complete</div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 font-mono">
              <span>events: {manifest.event_count}</span>
              <span>target: {manifest.target}</span>
              <span>seed: {manifest.seed}</span>
              <span>uc: {manifest.ndr_uc}</span>
              <span className="col-span-2 truncate">manifest: {String(manifest.target)}</span>
            </div>
            {manifest.warmup_note && (
              <div className="mt-1 text-muted-foreground">note: {manifest.warmup_note}</div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
