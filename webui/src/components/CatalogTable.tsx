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

import { useMemo, useState } from "react";
import { ChevronRight, Search } from "lucide-react";
import { cn } from "@/lib/utils";
import { filterTechniques, groupByTactic, LOG_TYPES, logTypeOf } from "@/lib/catalogView";
import type { Technique } from "@/lib/api";

interface Props {
  techniques: Technique[];
  selectedId: string | null;
  onSelect: (t: Technique) => void;
}

/** Drop the "TA0011 " prefix for display; the number is noise once grouped. */
const tacticLabel = (tactic: string) => tactic.replace(/^TA\d{4}\s+/, "");

export function CatalogTable({ techniques, selectedId, onSelect }: Props) {
  const [query, setQuery] = useState("");
  const [logTypes, setLogTypes] = useState<string[]>([]);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const groups = useMemo(
    () => groupByTactic(filterTechniques(techniques, { query, logTypes })),
    [techniques, query, logTypes],
  );

  const shown = useMemo(
    () => new Set(groups.flatMap((g) => g.techniques.map((t) => t.id))).size,
    [groups],
  );
  const filtering = query.trim().length > 0 || logTypes.length > 0;

  const toggleLogType = (value: string) =>
    setLogTypes((current) =>
      current.includes(value) ? current.filter((v) => v !== value) : [...current, value],
    );

  const toggleGroup = (tactic: string) =>
    setCollapsed((current) => {
      const next = new Set(current);
      if (next.has(tactic)) next.delete(tactic);
      else next.add(tactic);
      return next;
    });

  return (
    <section className="flex min-h-0 flex-col">
      <div className="mb-3 flex items-baseline justify-between">
        <span className="text-body font-semibold">Techniques</span>
        <span className="font-mono text-label text-text-3">
          {filtering ? `${shown} of ${techniques.length}` : `${techniques.length} · ATT&CK`}
        </span>
      </div>

      <div className="relative mb-2.5">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-4" />
        <input
          type="text"
          aria-label="Filter techniques"
          placeholder="id, name, use case, ATT&CK"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="h-8 w-full rounded-md border bg-transparent pl-8 pr-2.5 font-mono text-micro placeholder:text-text-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
      </div>

      <div className="mb-3 flex flex-wrap gap-1">
        {LOG_TYPES.map((value) => {
          const on = logTypes.includes(value);
          return (
            <button
              key={value}
              onClick={() => toggleLogType(value)}
              aria-pressed={on}
              className={cn(
                "rounded border px-1.5 py-0.5 font-mono text-micro transition-colors",
                on
                  ? "border-signal/50 bg-signal/10 text-signal"
                  : "text-text-3 hover:text-muted-foreground",
              )}
            >
              {value}
            </button>
          );
        })}
      </div>

      <div className="-mx-2 flex min-h-0 flex-col overflow-y-auto scroll-thin">
        {groups.length === 0 && (
          <p className="px-2.5 py-4 text-body text-muted-foreground">
            No techniques match that filter.
          </p>
        )}

        {groups.map((group) => {
          const open = !collapsed.has(group.tactic);
          return (
            <div key={group.tactic} className="mb-1">
              <button
                onClick={() => toggleGroup(group.tactic)}
                aria-expanded={open}
                className="flex w-full items-center gap-1 rounded px-2.5 py-1.5 text-left transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <ChevronRight
                  className={cn("h-3 w-3 text-text-4 transition-transform", open && "rotate-90")}
                />
                <span className="u-label flex-1">{tacticLabel(group.tactic)}</span>
                <span className="font-mono text-micro text-text-3">
                  {group.techniques.length}
                </span>
              </button>

              {open &&
                group.techniques.map((t) => {
                  const sel = t.id === selectedId;
                  return (
                    <button
                      key={`${group.tactic}:${t.id}`}
                      aria-current={sel ? "true" : undefined}
                      onClick={() => onSelect(t)}
                      className={cn(
                        "relative grid w-full grid-cols-[1fr_auto] items-center gap-x-2.5 gap-y-0.5 rounded-md py-2 pl-6 pr-2.5 text-left transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                        sel && "bg-secondary",
                      )}
                    >
                      {sel && (
                        <span className="absolute bottom-2 left-0 top-2 w-0.5 rounded bg-foreground" />
                      )}
                      <span className="col-start-1 row-start-1 text-body font-medium">
                        {t.name}
                      </span>
                      <span className="col-start-2 row-start-1 justify-self-end font-mono text-micro text-text-3">
                        {t.attack[0] ?? ""}
                      </span>
                      <span className="col-start-1 row-start-2 font-mono text-label text-text-3">
                        {t.id} · {logTypeOf(t)}
                      </span>
                      {!t.implemented && (
                        <span className="col-start-2 row-start-2 justify-self-end font-mono text-micro font-semibold uppercase tracking-wide text-signal">
                          soon
                        </span>
                      )}
                    </button>
                  );
                })}
            </div>
          );
        })}
      </div>
    </section>
  );
}
