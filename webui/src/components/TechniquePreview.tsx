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

import { useState } from "react";
import { Activity, FileCode2 } from "lucide-react";
import { TechniqueDiagram } from "@/components/TechniqueDiagram";
import { SampleLines, TechniqueDetail } from "@/components/TechniqueDetail";
import { vendorShortLabel, type Technique } from "@/lib/api";
import { fmtSpan, type PlanPreview } from "@/lib/pacing";
import { cn } from "@/lib/utils";

interface Props { technique: Technique; vendor: string; preview: PlanPreview | null; pending?: boolean }

export function TechniquePreview({ technique, vendor, preview, pending = false }: Props) {
  const [view, setView] = useState("signal");
  const [referenceOpen, setReferenceOpen] = useState(false);
  const missing = pending ? "Calculating…" : "Unavailable";
  return (
    <div className="space-y-4">
      <section className="panel">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-sm font-medium">Signal preview</h2>
          <div role="group" aria-label="Preview view" className="flex rounded-btn border bg-well p-1">
            {([['signal', 'Signal', Activity], ['cef', 'Sample CEF', FileCode2]] as const).map(([id, label, Icon]) => (
              <button key={id} aria-pressed={view === id} onClick={() => setView(id)}
                className={cn("flex items-center gap-1.5 rounded px-2 py-1 text-label", view === id ? "bg-secondary text-foreground" : "text-muted-foreground")}>
                <Icon aria-hidden="true" className="h-3.5 w-3.5" />{label}
              </button>
            ))}
          </div>
        </div>
        {view === "signal" ? <>
          <div className="min-w-0 rounded-btn border bg-well p-4">
            <TechniqueDiagram technique={technique} compact />
          </div>
          <p className="mt-2 text-label text-muted-foreground">Illustrative pattern. The plan below reflects your current settings.</p>
        </> : <>
          <SampleLines technique={technique} vendor={vendor} />
          <p className="mt-2 text-label text-muted-foreground">Representative {vendorShortLabel(vendor)} sample from the catalog preset. Your run uses the current settings.</p>
        </>}
        <dl className="mt-4 grid grid-cols-2 gap-4 border-t pt-4">
          {[["Planned events", preview?.event_count.toLocaleString() ?? missing],
            ["Estimated run time", preview ? fmtSpan(preview.projected_s) : missing],
            ["Event-time span", preview ? fmtSpan(preview.compressed_span_s) : missing],
            ["Detection rule", technique.ndr_rule]].map(([label, value]) => <div key={label} className="min-w-0">
              <dt className="u-label">{label}</dt><dd className="mt-1 break-words font-mono text-data">{value}</dd>
            </div>)}
        </dl>
      </section>
      <section className="panel">
        <h2 className="mb-3 text-sm font-medium">Detection context</h2>
        <p className="text-body text-muted-foreground">{technique.objective}</p>
        <div className="u-label mb-2 mt-4">Fields that vary</div>
        <div className="flex flex-wrap gap-1.5">
          {technique.native_cef_fields_varied.map((field) => <span key={field} className="rounded border bg-well px-2 py-1 font-mono text-micro">{field}</span>)}
        </div>
        {technique.benign_baseline && <p className="mt-4 text-label leading-relaxed text-muted-foreground"><span className="font-medium text-foreground">Baseline: </span>{technique.benign_baseline}</p>}
        {technique.transferability_note && <p className="mt-4 rounded border border-destructive/40 p-3 text-label leading-relaxed text-destructive">{technique.transferability_note}</p>}
        <div className="mt-4 border-t pt-3 text-label text-muted-foreground">
          <p>{technique.native_metadata_semantics}</p>
          <p className="mt-1 font-mono">{technique.native_log_type}:{technique.native_subtype}</p>
        </div>
      </section>
      <details className="panel" open={referenceOpen} onToggle={(event) => setReferenceOpen(event.currentTarget.open)}>
        <summary className="text-sm font-medium">Full technique reference</summary>
        {referenceOpen && <div className="mt-5"><TechniqueDetail technique={technique} vendor={vendor} /></div>}
      </details>
    </div>
  );
}
