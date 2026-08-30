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
import { ChevronRight } from "lucide-react";
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
        <span className="u-label">Techniques</span>
        <span className="font-mono text-label uppercase tracking-[-0.24px] text-text-4">
          {filtering ? `${shown} of ${techniques.length}` : `${techniques.length} · ATT&CK`}
        </span>
      </div>

      <div className="mb-2.5">
        <input
          type="text"
          aria-label="Filter techniques"
          placeholder="id, name, use case, ATT&CK"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="w-full rounded-btn border bg-transparent px-3 py-2 font-mono text-label tracking-[-0.24px] placeholder:uppercase placeholder:text-text-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
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
                // An active filter is a control state, not live data, so it never
                // takes the signal color: it recesses to the canvas like the
                // active vendor segment.
                "rounded-btn border px-1.5 py-0.5 font-mono text-micro uppercase tracking-[-0.24px] transition-colors",
                on
                  ? "border-muted-foreground bg-background text-foreground"
                  : "text-text-4 hover:text-foreground",
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
                        "relative grid w-full grid-cols-[1fr_auto] items-center gap-x-2.5 gap-y-1 rounded-btn border-b border-elev py-3 pl-6 pr-2.5 text-left transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                        sel && "bg-secondary",
                      )}
                    >
                      {sel && (
                        <span className="absolute bottom-2 left-0 top-2 w-0.5 rounded bg-foreground" />
                      )}
                      <span className="col-start-1 row-start-1 text-body">{t.name}</span>
                      <span className="col-start-2 row-start-1 justify-self-end font-mono text-micro text-text-4">
                        {t.attack[0] ?? ""}
                      </span>
                      <span className="col-start-1 row-start-2 font-mono text-label uppercase tracking-[-0.24px] text-text-4">
                        {t.id} · {logTypeOf(t)}
                      </span>
                      {!t.implemented && (
                        <span className="col-start-2 row-start-2 justify-self-end font-mono text-micro uppercase tracking-[-0.24px] text-text-3">
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
