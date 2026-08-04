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

function Chip({ label, signal }: { label: string; signal?: boolean }) {
  return (
    <span
      className={
        signal
          ? "rounded border border-signal/40 px-1.5 py-0.5 font-mono text-label text-signal"
          : "rounded border px-1.5 py-0.5 font-mono text-label text-text-3"
      }
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
function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="min-w-0 rounded-lg border bg-card p-4">
      <div className="u-label mb-3">{title}</div>
      {children}
    </section>
  );
}

function Field({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/60 py-1.5 last:border-0">
      <span className="text-label text-muted-foreground">{k}</span>
      <span className="text-right font-mono text-micro text-foreground">{v}</span>
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
    <div className="scroll-thin overflow-x-auto rounded-lg border bg-well p-3 font-mono text-micro leading-[1.9] text-text-3">
      {err ? (
        <span className="text-destructive">sample unavailable: {err}</span>
      ) : !sample ? (
        <span className="text-text-3">rendering sample for {vendorLabel(vendor)}…</span>
      ) : sample.lines.length === 0 ? (
        <span className="text-text-3">no representative event for this preset</span>
      ) : (
        sample.lines.map((line, i) => (
          <div key={i} className="whitespace-pre">
            {line.startsWith("CEF:") ? (
              <>
                <span className="text-signal">CEF:</span>
                {line.slice(4)}
              </>
            ) : (
              line
            )}
          </div>
        ))
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
      <div className="font-mono text-micro font-medium tracking-wide text-muted-foreground">
        {technique.id} · {technique.ndr_uc}
      </div>
      <h1 className="mt-1 text-title font-semibold tracking-[-0.028em]">{technique.name}</h1>

      {/* The objective, first and in the reading colour.
          This slot used to hold "Emits synthetic <log type> telemetry that
          exercises <rule>", which is true of every entry in the catalog and so
          answered none of the question the operator actually has, which is which
          one to pick. The templated sentence survives below it, demoted to the
          mechanical detail it always was. */}
      {technique.objective && (
        <p
          data-testid="technique-objective"
          className="mt-2 max-w-[640px] text-lede leading-relaxed text-foreground"
        >
          {technique.objective}
        </p>
      )}
      <p className="mt-1.5 max-w-[600px] text-body leading-relaxed text-muted-foreground">
        Emits synthetic <span className="text-foreground">{technique.log_type}:{technique.subtype}</span>{" "}
        telemetry that exercises <span className="text-foreground">{technique.ndr_rule}</span>.
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        {technique.tactics.map((t) => (
          <span key={t} className="rounded bg-secondary px-1.5 py-0.5 text-label text-secondary-foreground">
            {t}
          </span>
        ))}
        {technique.attack.map((a) => (
          <Chip key={a} label={a} />
        ))}
      </div>

      {/* signal-path diagram */}
      <div className="mt-5 rounded-lg border bg-card px-4 pb-3 pt-3.5">
        <div className="u-label mb-1">Signal path</div>
        <TechniqueDiagram technique={technique} />
      </div>

      {/* detail cards */}
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <Card title="What the detection looks for">
          <p className="mb-3 text-body leading-relaxed text-muted-foreground">
            The rule keys on the fields that move against a steady baseline.
          </p>
          <div className="mb-1 text-label font-semibold uppercase tracking-wide text-signal/90">Signal (varied)</div>
          <div className="mb-3 flex flex-wrap gap-1.5">
            {technique.cef_fields_varied.map((f) => (
              <Chip key={f} label={f} signal />
            ))}
          </div>
          <div className="mb-1 text-label font-semibold uppercase tracking-wide text-text-3">Held constant</div>
          <div className="mb-3 flex flex-wrap gap-1.5">
            {technique.cef_fields_held.map((f) => (
              <Chip key={f} label={f} />
            ))}
          </div>
          {technique.benign_baseline && (
            <p className="border-t border-border/60 pt-2.5 text-body leading-relaxed text-muted-foreground">
              <span className="text-text-3">Baseline · </span>
              {technique.benign_baseline}
            </p>
          )}
        </Card>

        <Card title="Rule specifics">
          <Field k="NDR rule" v={technique.ndr_rule} />
          <Field k="Use case" v={technique.ndr_uc} />
          <Field k="Log type" v={`${technique.log_type}:${technique.subtype}`} />
          <Field k="Signature ID" v={technique.signature_id} />
          <Field k="Action" v={technique.action ?? "—"} />
          <Field k="Intensities" v={intens.join(" · ")} />
          {paramKeys.length > 0 && (
            <div className="mt-3">
              <div className="mb-1.5 text-label font-semibold uppercase tracking-wide text-text-3">
                Intensity presets
              </div>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse font-mono text-micro">
                  <thead>
                    <tr className="text-text-3">
                      <th className="py-1 text-left font-medium"> </th>
                      {intens.map((i) => (
                        <th key={i} className="px-2 py-1 text-right font-medium">
                          {i}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {paramKeys.map((k) => (
                      <tr key={k} className="border-t border-border/50">
                        <td className="py-1 pr-2 text-text-3">{k}</td>
                        {intens.map((i) => (
                          <td key={i} className="px-2 py-1 text-right text-foreground">
                            {fmt(technique.params[i]?.[k])}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </Card>

        <section className="min-w-0 rounded-lg border bg-card p-4 md:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <div className="u-label">What the logs will show · {vendorLabel(vendor)}</div>
            <span className="font-mono text-label text-text-3">
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
              <span className="font-semibold uppercase tracking-wide text-text-3">Refs · </span>
              {technique.references.join("  ·  ")}
            </div>
          )}
          {technique.safety_notes && (
            <div className="max-w-[520px]">
              <span className="font-semibold uppercase tracking-wide text-text-3">Safety · </span>
              {technique.safety_notes}
            </div>
          )}
        </div>
      )}

      <div className="mt-6 border-t" />
    </div>
  );
}
