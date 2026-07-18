import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";
import { ConnectionCard } from "@/components/ConnectionCard";
import { CatalogTable } from "@/components/CatalogTable";
import { RunPanel } from "@/components/RunPanel";
import { TerminalView } from "@/components/TerminalView";
import { cn } from "@/lib/utils";
import {
  getCatalog,
  getConfig,
  type CatalogResponse,
  type Collector,
  type ConfigResponse,
  type Technique,
} from "@/lib/api";

const MARK = (
  <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden="true">
    <rect x="1.2" y="1.2" width="19.6" height="19.6" rx="5.4" className="stroke-muted-foreground" strokeWidth="1.3" opacity="0.5" />
    <path
      d="M4 12.5 L7.6 12.5 L9 7 L11.4 15.5 L13 11 L15 11 L16.4 13 L18 13"
      className="stroke-signal"
      strokeWidth="1.5"
      strokeLinejoin="round"
      strokeLinecap="round"
    />
  </svg>
);

export default function App() {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [collector, setCollector] = useState<Collector | null>(null);
  const [vendor, setVendor] = useState("fortigate");
  const [selected, setSelected] = useState<Technique | null>(null);
  const [tab, setTab] = useState<"emitter" | "terminal">("emitter");
  const [dark, setDark] = useState(true);

  useEffect(() => {
    Promise.all([getCatalog(), getConfig()])
      .then(([cat, cfg]) => {
        setCatalog(cat);
        setConfig(cfg);
        setVendor(cfg.vendor);
        setSelected(cat.techniques.find((t) => t.implemented) ?? cat.techniques[0] ?? null);
      })
      .catch((err) => setLoadError((err as Error).message));
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  if (loadError) {
    return (
      <div className="flex h-screen items-center justify-center p-8 text-center">
        <div className="max-w-md space-y-2">
          <h1 className="text-lg font-semibold text-destructive">Could not reach the API</h1>
          <p className="text-sm text-muted-foreground">{loadError}</p>
          <p className="text-sm text-muted-foreground">
            Open the URL printed by <code className="font-mono">replicant web</code>, which includes
            the session token.
          </p>
        </div>
      </div>
    );
  }

  if (!catalog || !config) {
    return (
      <div className="flex h-screen items-center justify-center font-mono text-sm text-muted-foreground">
        Loading Replicant…
      </div>
    );
  }

  const navItem = (id: "emitter" | "terminal", label: string) => (
    <button
      onClick={() => setTab(id)}
      className={cn(
        "py-[17px] text-[13px] font-medium transition-colors",
        tab === id
          ? "text-foreground shadow-[inset_0_-2px_0_hsl(var(--foreground))]"
          : "text-muted-foreground hover:text-foreground",
      )}
    >
      {label}
    </button>
  );

  return (
    <div className="app-surface flex h-screen flex-col overflow-hidden">
      {/* top bar */}
      <header className="flex h-[54px] flex-none items-center justify-between border-b px-5">
        <div className="flex items-center gap-2.5">
          {MARK}
          <span className="text-sm font-semibold tracking-tight">Replicant</span>
          <span className="ml-1 border-l pl-2.5 font-mono text-[11px] text-text-3">
            lab · 10.20.0.0/16
          </span>
        </div>
        <nav className="flex gap-6">
          {navItem("emitter", "Emitter")}
          {navItem("terminal", "Terminal")}
        </nav>
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-2 font-mono text-[11.5px] text-text-3">
            {collector ? (
              <>
                <span className="h-1.5 w-1.5 rounded-full bg-signal" />
                {collector.host}:{collector.port} · {collector.transport}
              </>
            ) : (
              <>
                <span className="h-1.5 w-1.5 rounded-full bg-text-4" />
                no collector
              </>
            )}
          </span>
          <button
            onClick={() => setDark((d) => !d)}
            className="flex h-[26px] w-[26px] items-center justify-center rounded-md border text-muted-foreground transition-colors hover:text-foreground"
            aria-label="Toggle theme"
          >
            {dark ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
          </button>
        </div>
      </header>

      {tab === "emitter" ? (
        <div className="grid min-h-0 flex-1 grid-cols-[336px_minmax(0,1fr)]">
          <aside className="flex min-h-0 animate-rise flex-col gap-6 overflow-y-auto scroll-thin border-r p-5">
            <ConnectionCard
              epsCap={config.eps_cap}
              collector={collector}
              onCollectorChange={setCollector}
              vendor={vendor}
              vendors={config.vendors}
              onVendorChange={setVendor}
            />
            <CatalogTable
              techniques={catalog.techniques}
              selectedId={selected?.id ?? null}
              onSelect={setSelected}
            />
          </aside>
          <main className="min-h-0 animate-rise overflow-y-auto scroll-thin px-7 py-6 [animation-delay:0.1s]">
            <RunPanel
              technique={selected}
              defaultSeed={config.default_seed}
              collector={collector}
              vendor={vendor}
            />
          </main>
        </div>
      ) : (
        <div className="min-h-0 flex-1 p-4">
          <div className="h-full overflow-hidden rounded-lg border bg-card p-2">
            <TerminalView />
          </div>
        </div>
      )}
    </div>
  );
}
