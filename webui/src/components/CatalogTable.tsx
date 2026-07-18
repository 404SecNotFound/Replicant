import { cn } from "@/lib/utils";
import type { Technique } from "@/lib/api";

interface Props {
  techniques: Technique[];
  selectedId: string | null;
  onSelect: (t: Technique) => void;
}

export function CatalogTable({ techniques, selectedId, onSelect }: Props) {
  return (
    <section className="flex min-h-0 flex-col">
      <div className="mb-3 flex items-baseline justify-between">
        <span className="text-[13px] font-semibold">Techniques</span>
        <span className="font-mono text-[10.5px] text-text-3">{techniques.length} · ATT&CK</span>
      </div>
      <div
        role="listbox"
        aria-label="Techniques"
        className="-mx-2 flex min-h-0 flex-col gap-px overflow-y-auto scroll-thin"
      >
        {techniques.map((t) => {
          const sel = t.id === selectedId;
          return (
            <button
              key={t.id}
              role="option"
              aria-selected={sel}
              onClick={() => onSelect(t)}
              className={cn(
                "relative grid grid-cols-[1fr_auto] items-center gap-x-2.5 gap-y-0.5 rounded-md px-2.5 py-2 text-left transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                sel && "bg-secondary",
              )}
            >
              {sel && (
                <span className="absolute bottom-2 left-0 top-2 w-0.5 rounded bg-foreground" />
              )}
              <span className="col-start-1 row-start-1 text-[13px] font-medium">{t.name}</span>
              <span className="col-start-2 row-start-1 justify-self-end font-mono text-[9.5px] text-text-4">
                {t.attack[0] ?? ""}
              </span>
              <span className="col-start-1 row-start-2 font-mono text-[10.5px] text-text-3">
                {t.id} · {t.log_type}:{t.subtype}
              </span>
              {!t.implemented && (
                <span className="col-start-2 row-start-2 justify-self-end font-mono text-[9px] font-semibold uppercase tracking-wide text-signal">
                  soon
                </span>
              )}
            </button>
          );
        })}
      </div>
    </section>
  );
}
