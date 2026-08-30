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

import { useEffect, useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { CefLine } from "@/components/CefLine";
import { TechniqueDiagram } from "@/components/TechniqueDiagram";
import { getSample, vendorLabel, type Technique, type TechniqueSample } from "@/lib/api";

interface Props {
  technique: Technique;
  vendor: string;
}

const fmt = (v: unknown): string =>
  v == null
    ? "—"
    : Array.isArray(v)
      ? `[${v.join("–")}]`
      : typeof v === "object"
        ? JSON.stringify(v)
        : String(v);

// Varied fields read in the text color, held fields recede to muted; neither
// takes the signal color. In this system a chip is a fact, not live data, and
// the critic loop pinned the varied/held distinction to brightness alone.
function Chip({ label, tone = "default" }: { label: string; tone?: "varied" | "held" | "default" }) {
  return (
    <span
      className={cn(
        "rounded-btn border px-2 py-1 font-mono text-label uppercase tracking-[-0.24px]",
        tone === "varied" ? "text-foreground" : tone === "held" ? "text-text-4" : "text-text-3",
      )}
    >
      {label}
    </span>
  );
}

// `min-w-0` is load-bearing, not tidiness. A grid item defaults to
// `min-width: auto`, so it refuses to shrink below its content's intrinsic
// width. A single 3376px CEF sample line inside an `overflow-x-auto` therefore
// stretched the whole column track and the page scrolled sideways to 3452px on a
// 375px viewport, instead of the sample scrolling inside its own box.
function Card({
  title,
  className,
  children,
}: {
  title: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section className={cn("min-w-0 rounded-lg bg-card p-6", className)}>
      <div className="u-label mb-4">{title}</div>
      {children}
    </section>
  );
}

// A metric tile from the mock: mono label, 22px weight-400 value in the text
// face, optional mono context line. Dividers are the canvas color showing
// between cells, not drawn borders in the outline gray.
function Tile({ k, v, context }: { k: string; v: string; context?: string }) {
  return (
    <div className="min-w-0 border-b border-background p-4 odd:border-r [&:nth-last-child(-n+2)]:border-b-0">
      <span className="mb-2 block font-mono text-label uppercase tracking-[-0.24px] text-text-4">
        {k}
      </span>
      <span className="block break-words text-stat tracking-[-0.025em] text-foreground">{v}</span>
      {context && (
        <span className="mt-1 block font-mono text-micro uppercase tracking-[-0.24px] text-text-4">
          {context}
        </span>
      )}
    </div>
  );
}

function SampleLines({ technique, vendor }: Props) {
  const [sample, setSample] = useState<TechniqueSample | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setSample(null);
    setErr(null);
    getSample(technique.id, vendor)
      .then((s) => live && setSample(s))
      .catch((e) => live && setErr((e as Error).message));
    return () => {
      live = false;
    };
  }, [technique.id, vendor]);

  return (
    <div className="scroll-thin overflow-x-auto rounded-btn bg-well p-3 font-mono text-micro leading-[1.9] text-text-3">
      {err ? (
        <span className="text-destructive">sample unavailable: {err}</span>
      ) : !sample ? (
        <span className="text-text-3">rendering sample for {vendorLabel(vendor)}…</span>
      ) : sample.lines.length === 0 ? (
        <span className="text-text-3">no representative event for this preset</span>
      ) : (
        sample.lines.map((line, i) => <CefLine key={i} line={line} className="whitespace-pre" />)
      )}
    </div>
  );
}

export function TechniqueDetail({ technique, vendor }: Props) {
  const intens = technique.intensities.length ? technique.intensities : ["low", "medium", "high"];
  const paramKeys = Array.from(
    new Set(intens.flatMap((i) => Object.keys(technique.params[i] ?? {}))),
  );
  const distEntries = Object.entries(technique.distributions ?? {});

  return (
    <div className="mx-auto max-w-[900px] pb-2">
      {/* identity */}
      <div className="font-mono text-label uppercase tracking-[-0.24px] text-text-4">
        {technique.id} · {technique.ndr_uc}
      </div>
      {/* Weight 400 at 36px: the hero line is size, not boldness. */}
      <h1 className="mt-3 text-title tracking-[-1px]">{technique.name}</h1>

      {/* The objective, first and in the reading colour.
          This slot used to hold "Emits synthetic <log type> telemetry that
          exercises <rule>", which is true of every entry in the catalog and so
          answered none of the question the operator actually has, which is which
          one to pick. The templated sentence survives below it, demoted to the
          mechanical detail it always was. */}
      {technique.objective && (
        <p
          data-testid="technique-objective"
          className="mt-4 max-w-[640px] text-lede tracking-[-0.025em] text-foreground"
        >
          {technique.objective}
        </p>
      )}
      <p className="mt-2 max-w-[600px] text-body leading-relaxed text-text-4">
        Emits synthetic <span className="font-mono text-data text-foreground">{technique.log_type}:{technique.subtype}</span>{" "}
        telemetry that exercises <span className="font-mono text-data text-foreground">{technique.ndr_rule}</span>.
      </p>
      <div className="mt-4 flex flex-wrap items-center gap-2">
        {technique.tactics.map((t) => (
          <Chip key={t} label={t} />
        ))}
        {technique.attack.map((a) => (
          <Chip key={a} label={a} />
        ))}
      </div>

      {/* signal-path diagram: the one outlined card, canvas-colored so the
          drawing sits on the page rather than on a raised surface */}
      <div className="mt-8 rounded-lg border bg-background p-6">
        <div className="u-label mb-2">Signal path</div>
        <TechniqueDiagram technique={technique} />
        <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-elev pt-4">
          <span className="font-mono text-label uppercase tracking-[-0.24px] text-text-3">
            Signal fields
          </span>
          <div className="flex flex-wrap gap-2">
            {technique.cef_fields_varied.map((f) => (
              <Chip key={f} label={f} tone="varied" />
            ))}
          </div>
        </div>
      </div>

      {/* detail cards */}
      <div className="mt-6 grid gap-6 md:grid-cols-2">
        <Card title="What the detection looks for">
          <p className="mb-4 text-body leading-relaxed text-foreground">
            The rule keys on the fields that move against a steady baseline.
          </p>
          <div className="mb-2 font-mono text-label uppercase tracking-[-0.24px] text-text-3">
            Signal (varied)
          </div>
          <div className="mb-4 flex flex-wrap gap-2">
            {technique.cef_fields_varied.map((f) => (
              <Chip key={f} label={f} tone="varied" />
            ))}
          </div>
          <div className="mb-2 font-mono text-label uppercase tracking-[-0.24px] text-text-3">
            Held constant
          </div>
          <div className="mb-4 flex flex-wrap gap-2">
            {technique.cef_fields_held.map((f) => (
              <Chip key={f} label={f} tone="held" />
            ))}
          </div>
          {technique.benign_baseline && (
            <p className="border-t pt-4 text-body leading-relaxed text-text-4">
              <span className="text-text-3">Baseline · </span>
              {technique.benign_baseline}
            </p>
          )}
        </Card>

        <Card title="Rule specifics">
          <div className="grid grid-cols-2">
            <Tile k="NDR rule" v={technique.ndr_rule} />
            <Tile k="Use case" v={technique.ndr_uc} />
            <Tile k="Log type" v={`${technique.log_type}:${technique.subtype}`} />
            <Tile k="Signature ID" v={technique.signature_id} />
            <Tile k="Action" v={technique.action ?? "—"} />
            <Tile k="Intensities" v={intens.join(" · ")} />
          </div>
        </Card>

        {paramKeys.length > 0 && (
          <Card title="Intensity presets" className="md:col-span-2">
            <div className="min-w-0 overflow-x-auto">
              <table className="w-full border-collapse">
                <thead>
                  <tr>
                    <th className="border-b border-background px-3 py-2 text-left font-mono text-label font-normal uppercase tracking-[-0.24px] text-text-4">
                      Param
                    </th>
                    {intens.map((i) => (
                      <th
                        key={i}
                        className="border-b border-background px-3 py-2 text-left font-mono text-label font-normal uppercase tracking-[-0.24px] text-text-4"
                      >
                        {i}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {paramKeys.map((k) => (
                    <tr key={k}>
                      <td className="border-b border-background px-3 py-2.5 font-mono text-data text-text-3">
                        {k}
                      </td>
                      {intens.map((i) => (
                        <td
                          key={i}
                          className="border-b border-background px-3 py-2.5 font-mono text-data text-foreground"
                        >
                          {fmt(technique.params[i]?.[k])}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        <section className="min-w-0 rounded-lg bg-card p-6 md:col-span-2">
          <div className="mb-4 flex items-center justify-between gap-3">
            <div className="u-label">What the logs will show · {vendorLabel(vendor)}</div>
            <span className="font-mono text-label uppercase tracking-[-0.24px] text-text-4">
              {technique.log_type}:{technique.subtype} · sig {technique.signature_id}
            </span>
          </div>
          <SampleLines technique={technique} vendor={vendor} />
          {distEntries.length > 0 && (
            <div className="mt-3 grid gap-x-6 gap-y-1.5 sm:grid-cols-2">
              {distEntries.map(([k, v]) => (
                <div key={k} className="flex items-baseline gap-2 text-label">
                  <span className="shrink-0 font-mono text-text-3">{k}</span>
                  <span className="text-muted-foreground">{fmt(v)}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {(technique.references.length > 0 || technique.safety_notes) && (
        <div className="mt-4 flex flex-wrap items-start gap-x-8 gap-y-2 px-1 text-label text-text-3">
          {technique.references.length > 0 && (
            <div>
              <span className="font-mono uppercase tracking-[-0.24px] text-text-3">Refs · </span>
              {technique.references.join("  ·  ")}
            </div>
          )}
          {technique.safety_notes && (
            <div className="max-w-[520px]">
              <span className="font-mono uppercase tracking-[-0.24px] text-text-3">Safety · </span>
              {technique.safety_notes}
            </div>
          )}
        </div>
      )}

      <div className="mt-6 border-t" />
    </div>
  );
}
