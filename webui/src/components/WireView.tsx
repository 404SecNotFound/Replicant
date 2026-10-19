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

// The wire view: the emitted stream as a packet analyst reads it. An event list,
// the selected line dissected into syslog prefix, CEF header and extension, and
// the same line as bytes. Selecting a field lights its bytes. Everything shown
// is parsed from the line itself; nothing here is inferred from the plan.

import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";
import {
  byteSpan,
  describePri,
  dissectCef,
  eventClock,
  extensionValue,
  hexRows,
  type CefDissection,
  type Span,
} from "@/lib/cef";

interface WireViewProps {
  lines: string[];
  running: boolean;
  /** Bumps on every stream update; the line buffer itself is mutated in place. */
  revision: number;
  /** The selected profile's held signal keys, marked in the dissection. */
  heldFields: string[];
  bufferLimit: number;
  /** The profile the stream was rendered with, never the current draft's. */
  profile: string;
}

interface Field extends Span {
  id: string;
  group: "syslog" | "header" | "extension";
  key: string;
  value: string;
  note?: string;
}

function fieldsOf(d: CefDissection, held: Set<string>): Field[] {
  const fields: Field[] = [];
  if (d.prefix) {
    const pri = d.prefix.pri === null ? null : describePri(d.prefix.pri);
    fields.push({ id: "syslog", group: "syslog", key: "prefix", value: d.prefix.text.trim(),
      note: pri ? `PRI ${d.prefix.pri} ${pri}` : undefined, start: d.prefix.start, end: d.prefix.end });
  }
  d.header.forEach((h, i) => fields.push({ id: `h${i}`, group: "header", key: h.key, value: h.value, start: h.start, end: h.end }));
  d.extension.forEach((e, i) => fields.push({ id: `e${i}`, group: "extension", key: e.key, value: e.value,
    note: held.has(e.key) ? "held" : undefined, start: e.start, end: e.end }));
  return fields;
}

/** The CEF name, plus the action when the name does not already say it. */
function summary(d: CefDissection | null): string {
  const name = d?.header[5]?.value ?? "";
  const act = extensionValue(d, "act") ?? "";
  if (!act || name.toLowerCase().includes(act.toLowerCase())) return name;
  return name ? `${name} · ${act}` : act;
}

const GROUP_LABELS: Record<Field["group"], string> = {
  syslog: "Syslog prefix",
  header: "CEF header",
  extension: "Extension",
};

export function WireView({ lines, running, revision, heldFields, bufferLimit, profile }: WireViewProps) {
  const [pinned, setPinned] = useState<string | null>(null);
  const [fieldId, setFieldId] = useState<string | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const parsed = useRef(new Map<string, CefDissection | null>());

  const dissect = (line: string) => {
    const cache = parsed.current;
    if (!cache.has(line)) {
      if (cache.size > bufferLimit * 2) cache.clear();
      cache.set(line, dissectCef(line));
    }
    return cache.get(line) ?? null;
  };

  // Pin the line itself, not its index: the buffer drops its oldest lines, so an
  // index would slide onto a different event. Once the pinned line has left the
  // buffer, fall back to the live end.
  const pinnedIndex = pinned === null ? -1 : lines.lastIndexOf(pinned);
  const following = pinnedIndex === -1;
  const selectedIndex = following ? lines.length - 1 : pinnedIndex;

  useEffect(() => {
    if (following && listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [revision, following]);

  if (lines.length === 0) {
    return (
      <div className="flex min-h-40 items-center justify-center border bg-well p-6 font-mono text-label text-muted-foreground">
        {running ? "Waiting for the first event…" : "No streamed events captured in this browser."}
      </div>
    );
  }

  const line = lines[selectedIndex];
  const dissection = dissect(line);
  const held = new Set(heldFields);
  const fields = dissection ? fieldsOf(dissection, held) : [];
  const defaultField = fields.find((f) => f.note === "held") ?? fields.find((f) => f.group === "extension") ?? null;
  const field = fields.find((f) => f.id === fieldId) ?? defaultField;
  const highlight = field ? byteSpan(line, field) : null;
  const rows = hexRows(line);
  const totalBytes = new TextEncoder().encode(line).length;

  return (
    <div className="min-w-0 border bg-well">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-b px-3 py-2">
        <span className="u-label text-foreground">Wire · {profile}</span>
        <span className="font-mono text-micro text-muted-foreground">{lines.length} in buffer, last {bufferLimit}</span>
        <span className="font-mono text-micro text-muted-foreground">#{selectedIndex + 1} · {totalBytes} bytes</span>
        <button type="button" onClick={() => setPinned(null)} disabled={following}
          className="ml-auto rounded-btn border px-2.5 py-1 font-mono text-micro uppercase tracking-[0.06em] text-foreground enabled:hover:bg-secondary disabled:border-transparent disabled:text-muted-foreground">
          {following ? (running ? "Following live" : "Latest event") : "Follow live"}
        </button>
      </div>

      <div ref={listRef} tabIndex={0} aria-label="Event stream" className="scroll-thin h-52 overflow-auto border-b font-mono text-data">
        <div className="min-w-[760px]">
          <div className="sticky top-0 grid grid-cols-[52px_76px_150px_190px_minmax(0,1fr)] gap-3 border-b bg-frame px-3 py-1.5 text-micro uppercase tracking-[0.06em] text-muted-foreground">
            <span>#</span><span>Time</span><span>Source</span><span>Destination</span><span>Name / action</span>
          </div>
          {lines.map((row, i) => {
            const d = dissect(row);
            const dpt = extensionValue(d, "dpt");
            const dst = extensionValue(d, "dst");
            const selected = i === selectedIndex;
            return (
              <button type="button" key={i} onClick={() => setPinned(row)} aria-pressed={selected}
                className={cn("grid w-full grid-cols-[52px_76px_150px_190px_minmax(0,1fr)] gap-3 px-3 py-[3px] text-left leading-[1.6]",
                  selected ? "bg-selected text-foreground shadow-[inset_2px_0_0_hsl(var(--signal))]" : "text-text-3 hover:bg-card")}>
                <span className="text-muted-foreground">{i + 1}</span>
                <span>{eventClock(d) ?? "-"}</span>
                <span className="truncate">{extensionValue(d, "src") ?? "-"}</span>
                <span className="truncate">{dst ? (dpt ? `${dst}:${dpt}` : dst) : "-"}</span>
                <span className="truncate">{summary(d) || row.slice(0, 80)}</span>
              </button>
            );
          })}
        </div>
      </div>

      <div className="grid min-w-0 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div aria-label="Dissection" role="group" className="scroll-thin max-h-80 min-w-0 overflow-auto border-b py-2 font-mono text-data xl:border-b-0 xl:border-r">
          {!dissection && <p className="px-3 text-muted-foreground">This line is not CEF; shown as bytes only.</p>}
          {(["syslog", "header", "extension"] as const).map((group) => {
            const members = fields.filter((f) => f.group === group);
            if (members.length === 0) return null;
            return (
              <div key={group} className="mb-1">
                <div className="flex items-baseline gap-2 px-3 py-1 text-foreground">
                  <span aria-hidden="true" className="text-muted-foreground">▾</span>{GROUP_LABELS[group]}
                  <span className="text-micro text-muted-foreground">{members.length} {members.length === 1 ? "field" : "fields"}</span>
                </div>
                {members.map((f) => {
                  const active = field?.id === f.id;
                  return (
                    <button type="button" key={f.id} onClick={() => setFieldId(f.id)} aria-pressed={active}
                      className={cn("grid w-full grid-cols-[minmax(0,150px)_minmax(0,1fr)_auto] items-baseline gap-3 py-[2px] pl-8 pr-3 text-left leading-[1.6]",
                        active ? "bg-selected shadow-[inset_2px_0_0_hsl(var(--signal))]" : "hover:bg-card")}>
                      <span className="truncate text-muted-foreground">{f.key}</span>
                      <span className="break-all text-foreground">{f.value || "(empty)"}</span>
                      <span className="text-micro uppercase tracking-[0.06em] text-muted-foreground">{f.note ?? ""}</span>
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>

        <div aria-label="Bytes" role="group" className="scroll-thin max-h-80 min-w-0 overflow-auto px-3 py-2 font-mono text-micro leading-[1.75]">
          {rows.map((row) => (
            <div key={row.offset} className="flex gap-4 whitespace-pre">
              <span className="text-muted-foreground">{row.offset.toString(16).padStart(4, "0")}</span>
              <span className="flex gap-[0.45em]">
                {row.bytes.map((b, j) => {
                  const lit = highlight !== null && row.offset + j >= highlight.start && row.offset + j < highlight.end;
                  return <span key={j} className={cn(lit ? "bg-selected text-signal" : "text-foreground")}>{b.toString(16).padStart(2, "0")}</span>;
                })}
              </span>
              <span>
                {row.bytes.map((b, j) => {
                  const lit = highlight !== null && row.offset + j >= highlight.start && row.offset + j < highlight.end;
                  return <span key={j} className={cn(lit ? "bg-selected text-signal" : "text-muted-foreground")}>{b >= 32 && b < 127 ? String.fromCharCode(b) : "."}</span>;
                })}
              </span>
            </div>
          ))}
          {field && highlight && <p className="mt-2 border-t pt-2 text-muted-foreground">
            {field.key} · bytes {highlight.start}-{highlight.end - 1} of {totalBytes}
          </p>}
        </div>
      </div>
    </div>
  );
}
