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

import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { ChevronDown } from "lucide-react";
import { ConnectionCard } from "@/components/ConnectionCard";
import { CoverageBoard } from "@/components/CoverageBoard";
import { RunPanel, type RunAdmission } from "@/components/RunPanel";
import { VendorPicker } from "@/components/VendorPicker";
import { cn } from "@/lib/utils";
import {
  getActiveRun,
  getCatalog,
  getConfig,
  vendorShortLabel,
  type ActiveRun,
  type CatalogResponse,
  type Collector,
  type ConfigResponse,
  type Technique,
} from "@/lib/api";
import { isTerminalStatus } from "@/lib/runLifecycle";

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

type Tab = "emitter" | "techniques" | "collector" | "docs" | "logs" | "terminal";
const ACTIVE_DISCOVERY_RETRY_MS = 1000;

export default function App() {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [collector, setCollector] = useState<Collector | null>(null);
  const [vendor, setVendor] = useState("fortigate");
  const [activeRun, setActiveRun] = useState<ActiveRun | null>(null);
  const [activeRunDiscoveryPending, setActiveRunDiscoveryPending] = useState(true);
  const [runAdmission, setRunAdmission] = useState<RunAdmission | null>(null);
  const [selected, setSelected] = useState<Technique | null>(null);
  const [tab, setTab] = useState<Tab>("emitter");
  // Navigation becomes a disclosure on narrow screens.
  const [railOpen, setRailOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (!mainRef.current) return;
    mainRef.current.scrollTop = 0;
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
    mainRef.current.focus({ preventScroll: true });
  }, [tab]);

  useEffect(() => {
    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    const discoverActiveOwner = (cfg: ConfigResponse) => {
      getActiveRun()
        .then((restored) => {
          if (cancelled) return;
          const restoredRun = restored.run_id ? restored : null;
          setConfig(cfg);
          setActiveRun(restoredRun);
          // A known owner is already fail-closed. A successful null bootstrap
          // stays discovery-pending until RunPanel's fresh probe closes the gap
          // between bootstrap and its mounted controls.
          setActiveRunDiscoveryPending(restoredRun === null);
          // The run was rendered with this canonical profile. Load that catalog
          // first, so a restored PAN-OS run is never presented with FortiGate
          // metadata while RunPanel performs its own lifecycle probe.
          setVendor(restoredRun?.vendor ?? cfg.vendor);
        })
        .catch(() => {
          if (cancelled) return;
          // Unknown ownership is not an idle server. Keep the application on
          // its loading surface and retry without loading a possibly wrong
          // vendor catalog or exposing an enabled Run control.
          retryTimer = setTimeout(
            () => discoverActiveOwner(cfg),
            ACTIVE_DISCOVERY_RETRY_MS,
          );
        });
    };

    getConfig()
      .then((cfg) => {
        if (cancelled) return;
        discoverActiveOwner(cfg);
      })
      .catch((err) => {
        if (!cancelled) setLoadError((err as Error).message);
      });
    return () => {
      cancelled = true;
      if (retryTimer !== null) clearTimeout(retryTimer);
    };
  }, []);

  useEffect(() => {
    const ownerVendor = activeRun?.run_id ? (activeRun.vendor ?? null) : null;
    if (ownerVendor && ownerVendor !== vendor) setVendor(ownerVendor);
  }, [activeRun?.run_id, activeRun?.vendor, vendor]);

  useEffect(() => {
    if (!config) return;
    let cancelled = false;
    getCatalog(vendor)
      .then((cat) => {
        if (cancelled) return;
        setCatalog(cat);
        setSelected((previous) =>
          cat.techniques.find((t) => t.id === previous?.id)
          ?? cat.techniques.find((t) => t.implemented)
          ?? cat.techniques[0]
          ?? null,
        );
      })
      .catch((err) => {
        if (!cancelled) setLoadError((err as Error).message);
      });
    return () => {
      cancelled = true;
    };
  }, [config, vendor]);

  if (loadError) {
    return (
      <div className="flex h-screen items-center justify-center p-8 text-center">
        <div className="max-w-md space-y-2">
          <h1 className="text-lg text-destructive">Could not reach the API</h1>
          <p className="text-sm text-muted-foreground">{loadError}</p>
          <p className="text-sm text-muted-foreground">
            Open the URL printed by <code className="font-mono">replicant web</code>, which includes
            the persistent launch token.
          </p>
        </div>
      </div>
    );
  }

  const ownerVendor = activeRun?.run_id ? (activeRun.vendor ?? null) : null;
  if (
    !catalog
    || !config
  ) {
    return (
      <div className="flex h-screen items-center justify-center font-mono text-sm text-muted-foreground">
        Loading Replicant…
      </div>
    );
  }

  const activeRunIsTerminal = Boolean(
    activeRun?.status && isTerminalStatus(activeRun.status),
  );

  const catalogReady = catalog.vendor_profile === vendor
    && (ownerVendor === null || ownerVendor === vendor);
  const vendorLocked = Boolean(activeRun?.run_id || runAdmission || activeRunDiscoveryPending);
  const vendorLockReason = activeRun?.run_id
    ? activeRunIsTerminal
      ? `Vendor profile remains locked while Replicant confirms the active owner after ${activeRun.technique_id ?? "the run"} reached ${activeRun.status}.`
      : activeRun.status === "reserved" || activeRun.status === "admitting"
        ? `Vendor profile is locked while ${activeRun.technique_id ?? "a run"} holds run admission under ${vendorShortLabel(activeRun.vendor ?? vendor)}. Cancel that admission before switching profiles.`
        : `Vendor profile is locked while ${activeRun.technique_id ?? "a run"} is running under ${vendorShortLabel(activeRun.vendor ?? vendor)}. Stop the active run before switching profiles.`
    : runAdmission
      ? `Vendor profile is locked while Replicant requests admission for ${runAdmission.technique_id} under ${vendorShortLabel(runAdmission.vendor)}.`
      : activeRunDiscoveryPending
        ? "Vendor profile is locked while Replicant confirms active run ownership with the backend."
        : undefined;

  const navigate = (next: Tab) => {
    if (runAdmission && next !== "emitter") return;
    setTab(next);
    setRailOpen(false);
  };
  const navItem = (id: Tab, label: string) => {
    const disabledForAdmission = Boolean(runAdmission) && id !== "emitter";
    return <button onClick={() => navigate(id)} disabled={disabledForAdmission}
      aria-current={tab === id ? "page" : undefined}
      title={disabledForAdmission ? "Wait for the pending run admission before leaving the workspace." : undefined}
      className={cn("flex items-center whitespace-nowrap border-b px-4 py-3 text-left font-mono text-label uppercase tracking-[0.06em] transition-colors disabled:cursor-wait disabled:opacity-40 lg:border-b-0 lg:border-r",
        tab === id ? "bg-card text-foreground shadow-[inset_2px_0_0_hsl(var(--signal))] lg:shadow-[inset_0_-2px_0_hsl(var(--signal))]" : "text-muted-foreground enabled:hover:bg-card enabled:hover:text-foreground")}>
      {label}
    </button>;
  };
  const egress = collector ? `${collector.host}:${collector.port}/${collector.transport}` : "No collector";

  return (
    <div className="flex min-h-screen flex-col lg:h-screen lg:overflow-hidden">
      <a href="#workspace" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:rounded focus:bg-card focus:p-3">Skip to workspace</a>
      <div role="note" className="handling-banner flex-none">Synthetic telemetry // lab use only // detection unverified</div>
      <header className="flex flex-none flex-wrap items-stretch border-b bg-background">
        <div className="flex items-center gap-2.5 border-r px-4 py-2.5">
          <svg aria-hidden="true" width="18" height="18" viewBox="0 0 16 16" fill="none" stroke="hsl(var(--signal))" strokeWidth="1.4">
            <path d="M8 1.5 14 5v6l-6 3.5L2 11V5z" /><path d="M8 5v6M5 6.8l6 2.4" />
          </svg>
          <span className="font-mono text-[13px] font-medium tracking-[0.16em]">REPLICANT</span>
        </div>
        <button onClick={() => setRailOpen((open) => !open)} aria-expanded={railOpen} aria-controls="workspace-navigation"
          className="ml-auto flex items-center gap-1.5 px-4 font-mono text-label uppercase tracking-[0.06em] text-foreground lg:hidden">Menu <ChevronDown aria-hidden="true" className={cn("h-4 w-4", railOpen && "rotate-180")} /></button>
        <nav id="workspace-navigation" aria-label="Main navigation"
          className={cn("order-last w-full flex-col border-t lg:order-none lg:flex lg:w-auto lg:flex-row lg:border-t-0", railOpen ? "flex" : "hidden")}>
          {navItem("emitter", "Run workspace")}
          {navItem("techniques", "Coverage")}
          {navItem("collector", "Collector")}
          {navItem("logs", "Process logs")}
          {navItem("docs", "Documentation")}
          {config.terminal_enabled && navItem("terminal", "Terminal")}
        </nav>
        <dl className="ml-auto hidden items-stretch lg:flex">
          <div className="border-l px-4 py-1.5"><dt className="u-label">Profile</dt><dd className="font-mono text-label">{vendorShortLabel(vendor)}</dd></div>
          <div className="border-l px-4 py-1.5"><dt className="u-label">Egress</dt><dd className="max-w-[220px] truncate font-mono text-label">{egress}</dd></div>
          <div className="border-l px-4 py-1.5"><dt className="u-label">UTC</dt><dd className="font-mono text-label"><UtcClock /></dd></div>
        </dl>
      </header>
      <div className="flex min-h-0 flex-1 flex-col">
        <main ref={mainRef} id="workspace" tabIndex={-1} className="min-w-0 flex-1 p-4 outline-hidden sm:p-6 lg:overflow-y-auto lg:scroll-thin">
          {/* Keep drafts, evidence, and admission ownership mounted across navigation
              and profile loading. Lazy auxiliary views still poll only when open. */}
          <section hidden={tab !== "emitter"} aria-label="Run workspace" className="mx-auto max-w-[1600px]">
            {!catalogReady && <p role="status" className="mb-4 text-muted-foreground">Loading the {vendorShortLabel(vendor)} catalog…</p>}
            <RunPanel technique={catalogReady ? selected : null} defaultSeed={config.default_seed}
              collector={collector} vendor={vendor} epsCap={config.eps_cap} anchorEpoch={config.anchor_epoch}
              initialActiveRun={activeRun} onActiveRunChange={setActiveRun}
              onActiveRunDiscoveryChange={setActiveRunDiscoveryPending} onRunAdmissionChange={setRunAdmission}
              onChooseTechnique={() => navigate("techniques")} onConfigureCollector={() => navigate("collector")}
              vendorControls={<VendorPicker vendor={vendor} vendors={config.vendors} onVendorChange={setVendor}
                disabled={vendorLocked} reason={vendorLockReason} />} />
          </section>
          <section hidden={tab !== "techniques"} aria-label="Coverage" className="mx-auto max-w-[1600px]">
            <CoverageBoard techniques={catalogReady ? catalog.techniques : []} selectedId={selected?.id ?? null}
              onSelect={(technique) => { setSelected(technique); navigate("emitter"); }} />
          </section>
          <section hidden={tab !== "collector"} className="mx-auto max-w-[680px]">
            <div className="u-label">Egress</div>
            <h1 className="mt-1 text-stat font-normal">Collector connection</h1>
            <p className="mb-6 mt-1 text-body text-muted-foreground">Set your syslog destination and send a synthetic test log. Confirm receipt and parsing in your SIEM.</p>
            <ConnectionCard showVendorPicker={false} epsCap={config.eps_cap} collector={collector}
              onCollectorChange={setCollector} vendor={vendor} vendors={config.vendors} onVendorChange={setVendor} />
            <button className="quiet-button mt-4" onClick={() => navigate("emitter")}>Back to run workspace</button>
          </section>
          {tab === "docs" && <div className="flex min-h-[600px] lg:h-full lg:min-h-0">
            <Suspense fallback={<p className="text-muted-foreground">Loading docs…</p>}><DocsView /></Suspense>
          </div>}
          {tab === "logs" && <div className="flex min-h-[500px] lg:h-full lg:min-h-0">
            <Suspense fallback={<p className="text-muted-foreground">Loading logs…</p>}><LogsView /></Suspense>
          </div>}
          {tab === "terminal" && config.terminal_enabled && <div className="h-[70vh] min-w-0 overflow-hidden rounded-lg border bg-card p-2 lg:h-full">
            <Suspense fallback={<p className="text-muted-foreground">Loading terminal…</p>}><TerminalView /></Suspense>
          </div>}
        </main>
      </div>
      <footer className="flex flex-none flex-wrap gap-x-5 gap-y-1 border-t bg-frame px-4 py-1.5 font-mono text-micro uppercase tracking-[0.06em] text-muted-foreground">
        <span>Catalog {catalog.techniques.length} entries</span>
        <span>Profile {vendorShortLabel(vendor)}</span>
        <span>Cap {config.eps_cap} ev/s</span>
        <span className="lg:hidden">{egress}</span>
        <span>{collector ? "Receipt unconfirmed" : "Runs default to no send"}</span>
        <span className="sm:ml-auto">Emission is not evidence of SIEM receipt</span>
      </footer>
      <div role="note" className="handling-banner flex-none">Synthetic telemetry // lab use only // detection unverified</div>
    </div>
  );
}

/** Ticks once a second in its own component so the clock never re-renders the workspace. */
function UtcClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);
  return <time dateTime={now.toISOString()}>{now.toISOString().slice(11, 19)}</time>;
}
