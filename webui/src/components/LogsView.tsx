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

// The Logs tab.
//
// Built after a live run reported 921 events per second sent while the collector
// received nothing, and the tool had no way to say anything more useful than
// "sent". The mode selector is the point: WARNING for what is wrong, INFO for
// per-second throughput, VERBOSE for a line per datagram, DEBUG for the socket
// and pacing detail underneath.
//
// Polling rather than SSE. The stream endpoint exists and works, but an
// EventSource cannot carry the token header, and the run stream already relies
// on the session cookie for that. Polling a cursor is a few lines, survives a
// dropped connection with no reconnect logic, and at 1s is well inside what an
// operator watching a run needs. The volume is bounded by the same ring buffer
// the server holds, so a long run cannot grow this without limit.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getLogs, setLogLevel, type LogEntry, type LogLevel } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const POLL_MS = 1000;

// Keep the client buffer at the server's capacity. Beyond that the page is
// holding history the server has already dropped, which is memory spent on
// something no reload can reproduce.
const MAX_ENTRIES = 5000;

const LEVELS: { id: LogLevel; label: string; hint: string }[] = [
  { id: "debug", label: "Debug", hint: "Sockets, pacing, and burst width" },
  { id: "verbose", label: "Verbose", hint: "One line per datagram sent" },
  { id: "info", label: "Informational", hint: "Per-second throughput and totals" },
  { id: "warning", label: "Warning", hint: "Only what is going wrong" },
];

const LEVEL_STYLE: Record<LogLevel, string> = {
  debug: "text-text-4",
  verbose: "text-text-3",
  // Was "text-text-2", a token that does not exist, so the class compiled to
  // nothing and the color was whatever the container happened to inherit.
  info: "text-foreground",
  warning: "text-signal",
};

function formatTime(ts: number): string {
  const date = new Date(ts * 1000);
  const hh = String(date.getHours()).padStart(2, "0");
  const mm = String(date.getMinutes()).padStart(2, "0");
  const ss = String(date.getSeconds()).padStart(2, "0");
  const ms = String(date.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms}`;
}

export function LogsView() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [level, setLevel] = useState<LogLevel>("info");
  const [error, setError] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const [follow, setFollow] = useState(true);

  const cursorRef = useRef(0);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  const poll = useCallback(async () => {
    if (pausedRef.current) return;
    try {
      const body = await getLogs(cursorRef.current);
      cursorRef.current = body.cursor;
      setLevel(body.level);
      setError(null);
      if (body.entries.length > 0) {
        setEntries((prev) => {
          const next = prev.concat(body.entries);
          return next.length > MAX_ENTRIES ? next.slice(next.length - MAX_ENTRIES) : next;
        });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void poll();
    const timer = setInterval(() => void poll(), POLL_MS);
    return () => clearInterval(timer);
  }, [poll]);

  // Follow the tail unless the operator has scrolled up. Yanking someone back to
  // the bottom while they are reading a warning is how a log view becomes
  // unusable during the exact incident it was built for.
  useEffect(() => {
    if (!follow) return;
    const node = bodyRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [entries, follow]);

  const onScroll = () => {
    const node = bodyRef.current;
    if (!node) return;
    const atBottom = node.scrollHeight - node.scrollTop - node.clientHeight < 40;
    setFollow(atBottom);
  };

  const changeLevel = async (next: LogLevel) => {
    setLevel(next);
    try {
      await setLogLevel(next);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const counts = useMemo(() => {
    const warnings = entries.filter((entry) => entry.level === "warning").length;
    return { total: entries.length, warnings };
  }, [entries]);

  const copyAll = () => {
    const text = entries
      .map((entry) => `${formatTime(entry.ts)} ${entry.level.padEnd(7)} ${entry.logger} ${entry.message}`)
      .join("\n");
    void navigator.clipboard?.writeText(text);
  };

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-wrap gap-1" role="group" aria-label="Log level">
          {LEVELS.map((option) => (
            <button
              key={option.id}
              onClick={() => void changeLevel(option.id)}
              title={option.hint}
              aria-pressed={level === option.id}
              className={cn(
                "rounded-btn border px-2.5 py-1 font-mono text-label uppercase tracking-[-0.24px] transition-colors",
                level === option.id
                  ? "border-muted-foreground bg-background text-foreground"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {option.label}
            </button>
          ))}
        </div>

        <div className="ml-auto flex items-center gap-2">
          <span className="font-mono text-micro text-text-3">
            {counts.total} line{counts.total === 1 ? "" : "s"}
            {counts.warnings > 0 && (
              <span className="text-signal"> · {counts.warnings} warning</span>
            )}
          </span>
          <Button variant="outline" size="sm" onClick={() => setPaused((value) => !value)}>
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button variant="outline" size="sm" onClick={copyAll} disabled={entries.length === 0}>
            Copy
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setEntries([]);
              setFollow(true);
            }}
            disabled={entries.length === 0}
          >
            Clear
          </Button>
        </div>
      </div>

      {error && (
        <p className="rounded-sm border border-destructive/40 px-2.5 py-1.5 text-body text-destructive">
          {error}
        </p>
      )}

      <div
        ref={bodyRef}
        onScroll={onScroll}
        // min-w-0 so one long line scrolls inside this box instead of stretching
        // the page. See docs/webui-factory-design.md section 5.
        className="min-w-0 flex-1 overflow-auto rounded-sm border bg-card p-2.5 font-mono text-data leading-[1.55]"
      >
        {entries.length === 0 ? (
          <p className="text-text-3">
            No records yet. Set the mode above, then start a run. Warnings about event-time
            drift and oversize datagrams appear here as they happen.
          </p>
        ) : (
          entries.map((entry) => (
            <div key={entry.seq} className="flex gap-2 whitespace-pre-wrap break-words">
              <span className="flex-none text-text-4">{formatTime(entry.ts)}</span>
              {/* Wide enough for WARNING in JetBrains Mono at text-data; 52px
                  fit the old face and wrapped this one mid-word. */}
              <span className={cn("w-[68px] flex-none uppercase", LEVEL_STYLE[entry.level])}>
                {entry.level}
              </span>
              <span className="flex-none text-text-4">{entry.logger.replace("replicant.", "")}</span>
              <span className={cn("min-w-0", entry.level === "warning" && "text-signal")}>
                {entry.message}
              </span>
            </div>
          ))
        )}
      </div>

      {!follow && (
        <button
          onClick={() => {
            setFollow(true);
            const node = bodyRef.current;
            if (node) node.scrollTop = node.scrollHeight;
          }}
          className="self-center rounded-sm border px-2.5 py-1 text-body text-muted-foreground hover:text-foreground"
        >
          Jump to latest
        </button>
      )}
    </div>
  );
}
