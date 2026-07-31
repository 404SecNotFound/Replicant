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

import { lazy, Suspense, useEffect, useState } from "react";
import { ChevronDown, Moon, Sun } from "lucide-react";
import { ConnectionCard } from "@/components/ConnectionCard";
import { CatalogTable } from "@/components/CatalogTable";
import { RunPanel } from "@/components/RunPanel";
import { TechniqueDetail } from "@/components/TechniqueDetail";
import { cn } from "@/lib/utils";
import {
  applyTheme,
  darkModeMedia,
  hasStoredTheme,
  initialTheme,
  storeTheme,
  type Theme,
} from "@/lib/theme";
import {
  getCatalog,
  getConfig,
  type CatalogResponse,
  type Collector,
  type ConfigResponse,
  type Technique,
} from "@/lib/api";

// Lazy-loaded so xterm.js (the terminal's heavy dependency) is fetched only when
// the operator opens the Terminal tab, not on first paint of the Emitter view.
const TerminalView = lazy(() =>
  import("@/components/TerminalView").then((m) => ({ default: m.TerminalView })),
);

// Same treatment for the Docs tab: `marked` is only fetched if the operator opens
// it, so the Emitter view's first paint is unchanged.
const DocsView = lazy(() =>
  import("@/components/DocsView").then((m) => ({ default: m.DocsView })),
);

// The Logs tab polls only while it is mounted, so lazy-loading it also means an
// operator who never opens it never starts the poll.
const LogsView = lazy(() =>
  import("@/components/LogsView").then((m) => ({ default: m.LogsView })),
);

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

type Tab = "emitter" | "docs" | "logs" | "terminal";

export default function App() {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [collector, setCollector] = useState<Collector | null>(null);
  const [vendor, setVendor] = useState("fortigate");
  const [selected, setSelected] = useState<Technique | null>(null);
  const [tab, setTab] = useState<Tab>("emitter");
  // Seeded from the same rule the pre-paint script in index.html already applied,
  // so this agrees with what is on screen instead of overriding it.
  const [theme, setTheme] = useState<Theme>(initialTheme);
  // Below the lg breakpoint the left rail is a disclosure rather than a column.
  // Closed by default there: the run stage is what the operator came for, and a
  // 24-entry technique list above it would push it off the first screen.
  const [railOpen, setRailOpen] = useState(false);

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

  // Mount only. Every later change goes through changeTheme, which writes the
  // class before React re-renders; see the comment there for why that matters.
  useEffect(() => {
    applyTheme(theme);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Write the class synchronously, then update state.
  //
  // TerminalView resolves its xterm palette by reading the CSS variables off the
  // document, and React runs child effects BEFORE parent effects. Leaving the
  // class change to an effect in App therefore had the terminal read the
  // outgoing theme's colours: the whole app went light and the terminal pane
  // stayed dark. Applying it here means the class is already correct by the time
  // any child effect looks.
  const changeTheme = (next: Theme) => {
    applyTheme(next);
    setTheme(next);
  };

  // Keep following the operating system until the operator actually chooses.
  // Persisting the OS-derived default on load would look identical on the first
  // visit and then silently stop tracking the system setting forever after.
  useEffect(() => {
    const media = darkModeMedia();
    if (!media) return;
    const onChange = (event: MediaQueryListEvent) => {
      if (!hasStoredTheme()) changeTheme(event.matches ? "dark" : "light");
    };
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  const toggleTheme = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    storeTheme(next);
    changeTheme(next);
  };

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

  const navItem = (id: Tab, label: string) => (
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
    // Below lg this is an ordinary scrolling page. The fixed-viewport shell with
    // independently scrolling panes is a desktop affordance: on a short or narrow
    // screen it traps the run stage in a few hundred pixels with no way out.
    <div className="app-surface flex min-h-screen flex-col lg:h-screen lg:overflow-hidden">
      {/* top bar */}
      <header className="flex h-[54px] flex-none items-center justify-between gap-3 border-b px-3.5 sm:px-5">
        <div className="flex min-w-0 items-center gap-2.5">
          {MARK}
          <span className="text-sm font-semibold tracking-tight">Replicant</span>
          {/* The environment chip is orientation, not state. It is the first thing
              to go when the bar runs out of room. */}
          <span className="ml-1 hidden border-l pl-2.5 font-mono text-[11px] text-text-3 lg:inline">
            lab · 10.20.0.0/16
          </span>
        </div>
        <nav className="flex gap-4 sm:gap-6">
          {navItem("emitter", "Emitter")}
          {navItem("docs", "Docs")}
          {/* Always available. Unlike the terminal this needs no websocket and no
              loopback bind, and it is most wanted precisely when a remote bind
              means the operator cannot see the process's own output. */}
          {navItem("logs", "Logs")}
          {/* The server refuses the terminal websocket on a non-loopback bind, so
              showing the tab there would offer a control that can only fail. */}
          {config.terminal_enabled && navItem("terminal", "Terminal")}
        </nav>
        <div className="flex items-center gap-2.5 sm:gap-4">
          <span className="flex items-center gap-2 font-mono text-[11.5px] text-text-3">
            {collector ? (
              <>
                <span className="h-1.5 w-1.5 flex-none rounded-full bg-signal" />
                {/* The dot survives at every width; the address is what gets
                    dropped, since the Collector card below states it in full. */}
                <span className="hidden md:inline">
                  {collector.host}:{collector.port} · {collector.transport}
                </span>
              </>
            ) : (
              <>
                <span className="h-1.5 w-1.5 flex-none rounded-full bg-text-4" />
                <span className="hidden md:inline">no collector</span>
              </>
            )}
          </span>
          <button
            onClick={toggleTheme}
            className="flex h-[26px] w-[26px] flex-none items-center justify-center rounded-md border text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            {theme === "dark" ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
          </button>
        </div>
      </header>

      {tab === "emitter" ? (
        <div className="flex min-h-0 flex-1 flex-col lg:grid lg:grid-cols-[336px_minmax(0,1fr)]">
          {/* Below lg the rail is a disclosure instead of a column. One mechanism
              rather than the drawer-and-bottom-sheet pair the design spec sketched:
              two mechanisms is twice the surface to keep correct for a tool that is
              used at a desk, and the spec was written before the rail grew a filter
              box and 24 grouped entries. Recorded in the design doc. */}
          <button
            type="button"
            onClick={() => setRailOpen((open) => !open)}
            aria-expanded={railOpen}
            aria-controls="setup-rail"
            className="flex items-center justify-between gap-3 border-b px-4 py-3 text-left transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring lg:hidden"
          >
            <span className="u-label">Collector and techniques</span>
            <span className="flex items-center gap-2 font-mono text-[11px] text-text-3">
              {/* Naming the selection keeps the collapsed state informative: what
                  is armed is the one thing you lose by closing this. */}
              {selected?.id ?? "none selected"}
              <ChevronDown
                className={cn("h-3.5 w-3.5 transition-transform", railOpen && "rotate-180")}
              />
            </span>
          </button>
          <aside
            id="setup-rail"
            className={cn(
              "flex-col gap-6 border-b p-5 lg:flex lg:min-h-0 lg:animate-rise lg:overflow-y-auto lg:scroll-thin lg:border-b-0 lg:border-r",
              railOpen ? "flex" : "hidden",
            )}
          >
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
          <main className="animate-rise px-4 py-5 sm:px-7 sm:py-6 lg:min-h-0 lg:overflow-y-auto lg:scroll-thin [animation-delay:0.1s]">
            {selected && <TechniqueDetail technique={selected} vendor={vendor} />}
            <RunPanel
              technique={selected}
              defaultSeed={config.default_seed}
              collector={collector}
              vendor={vendor}
              epsCap={config.eps_cap}
              anchorEpoch={config.anchor_epoch}
            />
          </main>
        </div>
      ) : tab === "docs" ? (
        <div className="flex min-h-[420px] flex-1 lg:min-h-0">
          <Suspense
            fallback={
              <div className="grid h-full w-full place-items-center text-sm text-muted-foreground">
                Loading docs…
              </div>
            }
          >
            <DocsView />
          </Suspense>
        </div>
      ) : tab === "logs" ? (
        <div className="flex min-h-[420px] flex-1 p-3 sm:p-4 lg:min-h-0">
          <Suspense
            fallback={
              <div className="grid h-full w-full place-items-center text-sm text-muted-foreground">
                Loading logs…
              </div>
            }
          >
            <LogsView />
          </Suspense>
        </div>
      ) : (
        <div className="flex min-h-[420px] flex-1 p-3 sm:p-4 lg:min-h-0">
          <div className="h-full w-full overflow-hidden rounded-lg border bg-card p-2">
            <Suspense
              fallback={
                <div className="grid h-full place-items-center text-sm text-muted-foreground">
                  Loading terminal…
                </div>
              }
            >
              <TerminalView theme={theme} />
            </Suspense>
          </div>
        </div>
      )}
    </div>
  );
}
