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

// The catalog as an ATT&CK coverage matrix: one column per tactic in kill-chain
// order, one cell per technique, and a dossier for the cell in focus. Tactics no
// technique reaches are named, not drawn as empty columns, because a firewall log
// cannot express them. The board reports catalog facts only; whether a rule fired
// is not something Replicant can see.

import { useMemo, useRef, useState } from "react";
import { ArrowRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { absentTactics, filterTechniques, groupByTactic, logTypeOf, logTypesOf } from "@/lib/catalogView";
import type { Technique } from "@/lib/api";

interface Props {
  techniques: Technique[];
  selectedId: string | null;
  onSelect: (t: Technique) => void;
}

const tacticId = (tactic: string) => tactic.match(/^TA\d{4}/)?.[0] ?? "";
const tacticName = (tactic: string) => tactic.replace(/^TA\d{4}\s+/, "");

function FieldList({ values, empty }: { values: string[]; empty: string }) {
  if (values.length === 0) return <span className="text-muted-foreground">{empty}</span>;
  return <span className="flex flex-wrap gap-1">{values.map((v) => <span key={v} className="border bg-well px-1.5 py-px font-mono text-micro text-foreground">{v}</span>)}</span>;
}

function Dossier({ technique, isLoaded, onLoad }: { technique: Technique; isLoaded: boolean; onLoad: () => void }) {
  return (
    <div className="flex min-w-0 flex-col">
      <div className="border-b p-5">
        <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-micro uppercase tracking-[0.06em] text-muted-foreground">
          <span>Dossier</span><span>{technique.ndr_uc} / {technique.ndr_rule}</span>
        </div>
        <h2 className="mt-3 text-lede leading-snug">
          <span className="mr-2 font-mono text-signal">{technique.id}</span>{technique.name}
        </h2>
        <p className="mt-2 text-body leading-relaxed text-text-3">{technique.objective}</p>
      </div>
      <dl className="grid grid-cols-[96px_minmax(0,1fr)] gap-x-4 gap-y-3 border-b p-5 text-body">
        <dt className="u-label pt-0.5">Tactics</dt>
        <dd className="font-mono text-data">{technique.tactics.join(", ") || "Unmapped"}</dd>
        <dt className="u-label pt-0.5">ATT&amp;CK</dt>
        <dd className="font-mono text-data">{technique.attack.join(", ")}</dd>
        <dt className="u-label pt-0.5">Record</dt>
        <dd className="break-all font-mono text-data">{logTypeOf(technique)} · {technique.native_signature_id}</dd>
        <dt className="u-label pt-0.5">Held</dt>
        <dd><FieldList values={technique.native_cef_fields_held} empty="None on this profile" /></dd>
        <dt className="u-label pt-0.5">Varied</dt>
        <dd><FieldList values={technique.native_cef_fields_varied} empty="None on this profile" /></dd>
      </dl>
      <div className="border-b p-5">
        <div className="u-label">Benign baseline</div>
        <p className="mt-2 text-body leading-relaxed text-text-3">{technique.benign_baseline ?? "No benign baseline is documented for this entry."}</p>
        {technique.transferability === "parser-only" && <p className="mt-3 text-body leading-relaxed text-destructive">
          Parser-only: a pass exercises field mapping, not the shipped rule.{technique.transferability_note ? ` ${technique.transferability_note}` : ""}
        </p>}
      </div>
      <div className="p-5">
        <button type="button" onClick={onLoad} disabled={!technique.implemented} className="action-button w-full">
          {isLoaded ? "Open in run workspace" : "Load into run workspace"}<ArrowRight aria-hidden="true" className="h-4 w-4" />
        </button>
        {!technique.implemented && <p className="mt-2 text-label text-muted-foreground">This catalog entry is not available to run yet.</p>}
      </div>
    </div>
  );
}

export function CoverageBoard({ techniques, selectedId, onSelect }: Props) {
  const [query, setQuery] = useState("");
  const [logTypes, setLogTypes] = useState<string[]>([]);
  const [focusId, setFocusId] = useState<string | null>(null);
  const dossierRef = useRef<HTMLElement | null>(null);

  const availableLogTypes = useMemo(() => logTypesOf(techniques), [techniques]);
  const groups = useMemo(
    () => groupByTactic(filterTechniques(techniques, { query, logTypes })),
    [techniques, query, logTypes],
  );
  const missing = useMemo(() => absentTactics(techniques), [techniques]);
  const tacticCount = useMemo(() => groupByTactic(techniques).length, [techniques]);
  const shown = new Set(groups.flatMap((g) => g.techniques.map((t) => t.id))).size;
  const filtering = query.trim().length > 0 || logTypes.length > 0;

  const focus = techniques.find((t) => t.id === (focusId ?? selectedId)) ?? techniques[0] ?? null;

  // Below the two-pane width the dossier sits under the matrix; bring it into
  // view so a tap on a cell visibly does something.
  const focusTechnique = (id: string) => {
    setFocusId(id);
    if (typeof window.matchMedia === "function" && window.matchMedia("(max-width: 1279px)").matches) {
      dossierRef.current?.scrollIntoView({ block: "start" });
    }
  };

  const toggleLogType = (value: string) =>
    setLogTypes((current) => current.includes(value) ? current.filter((v) => v !== value) : [...current, value]);

  return (
    <div className="flex min-w-0 flex-col border bg-card xl:flex-row">
      <div className="flex min-w-0 flex-1 flex-col xl:border-r">
        <div className="flex flex-wrap items-end gap-x-8 gap-y-4 border-b px-5 py-4">
          <div className="min-w-0">
            <div className="u-label">ATT&amp;CK coverage · firewall-observable</div>
            <h1 className="mt-1 text-stat font-normal">{techniques.length} techniques across {tacticCount} tactics</h1>
          </div>
          <dl className="ml-auto flex flex-wrap">
            <div className="border-l px-4"><dt className="u-label">Shown</dt><dd className="mt-0.5 font-mono text-stat">{filtering ? shown : techniques.length}</dd></div>
            <div className="border-l px-4"><dt className="u-label">Log families</dt><dd className="mt-0.5 font-mono text-stat">{availableLogTypes.length}</dd></div>
            <div className="border-l px-4"><dt className="u-label">Rule fire</dt><dd className="mt-2 font-mono text-label text-muted-foreground">Not visible to Replicant</dd></div>
          </dl>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b px-5 py-3">
          <input type="text" aria-label="Filter techniques" placeholder="Filter by ID, name, ATT&CK, objective or alias"
            value={query} onChange={(e) => setQuery(e.target.value)}
            className="min-w-0 flex-[1_1_280px] rounded-btn border border-input bg-well px-3 py-2 font-mono text-data placeholder:font-sans placeholder:text-muted-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring" />
          <div role="group" aria-label="Log types" className="flex flex-wrap gap-1">
            {availableLogTypes.map((value) => {
              const on = logTypes.includes(value);
              return <button key={value} type="button" onClick={() => toggleLogType(value)} aria-pressed={on}
                className={cn("rounded-btn border px-2.5 py-1.5 font-mono text-micro transition-colors",
                  on ? "border-selection bg-selected text-foreground" : "bg-well text-muted-foreground hover:text-foreground")}>{value}</button>;
            })}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-b px-5 py-2.5 font-mono text-micro uppercase tracking-[0.06em] text-muted-foreground">
          <span className="flex items-center gap-1.5"><span aria-hidden="true" className="h-2.5 w-2.5 border border-input" />Available</span>
          <span className="flex items-center gap-1.5"><span aria-hidden="true" className="h-2.5 w-2.5 border border-foreground/70 bg-accent" />In run workspace</span>
          <span className="flex items-center gap-1.5"><span aria-hidden="true" className="h-2.5 w-2.5 border border-selection bg-selected" />In focus</span>
          {missing.length > 0 && <span className="normal-case tracking-normal lg:ml-auto">No firewall signal: {missing.join(", ")}</span>}
        </div>

        {groups.length === 0
          ? <p className="px-5 py-10 text-body text-muted-foreground">No techniques match that filter.</p>
          : <div className="min-w-0">
            {groups.map((group) => (
              <section key={group.tactic} aria-label={tacticName(group.tactic)}
                className="grid min-w-0 border-b last:border-b-0 md:grid-cols-[164px_minmax(0,1fr)]">
                <header className="flex items-baseline gap-3 border-b bg-frame px-4 py-2.5 md:block md:border-b-0 md:border-r md:py-3">
                  <div className="font-mono text-micro text-muted-foreground">{tacticId(group.tactic) || "—"}</div>
                  <h2 className="text-body leading-snug md:mt-0.5">{tacticName(group.tactic)}</h2>
                  <div className="ml-auto font-mono text-micro text-muted-foreground md:ml-0 md:mt-1">{group.techniques.length} {group.techniques.length === 1 ? "entry" : "entries"}</div>
                </header>
                <div className="grid min-w-0 grid-cols-[repeat(auto-fill,minmax(150px,1fr))] gap-1.5 p-2">
                  {group.techniques.map((t) => {
                    const inFocus = t.id === focus?.id;
                    const loaded = t.id === selectedId;
                    return (
                      <button key={`${group.tactic}:${t.id}`} type="button" title={t.name}
                        aria-pressed={inFocus} aria-current={loaded ? "true" : undefined}
                        onClick={() => focusTechnique(t.id)} onDoubleClick={() => t.implemented && onSelect(t)}
                        className={cn("flex min-h-[56px] min-w-0 flex-col gap-1 rounded-btn border px-2.5 py-2 text-left transition-colors",
                          inFocus ? "border-selection bg-selected" : loaded ? "border-foreground/70 bg-accent" : "border-border bg-background/40 hover:border-input hover:bg-secondary",
                          !t.implemented && "opacity-60")}>
                        <span className="flex justify-between gap-2 font-mono text-micro">
                          <span className={inFocus ? "text-signal" : "text-muted-foreground"}>{t.id}</span>
                          <span className="truncate text-muted-foreground">{t.native_log_type}</span>
                        </span>
                        <span className="line-clamp-2 text-label leading-snug text-foreground">{t.name}</span>
                      </button>
                    );
                  })}
                </div>
              </section>
            ))}
          </div>}
      </div>

      {focus && <aside ref={dossierRef} aria-label="Technique dossier" className="min-w-0 scroll-mt-4 border-t bg-frame xl:sticky xl:top-0 xl:w-[360px] xl:flex-none xl:self-start xl:border-t-0">
        <Dossier technique={focus} isLoaded={focus.id === selectedId} onLoad={() => onSelect(focus)} />
      </aside>}
    </div>
  );
}
