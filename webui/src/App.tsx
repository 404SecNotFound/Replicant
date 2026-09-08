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
import { Activity, BookOpen, ChevronDown, Layers, List, Radio, Terminal, type LucideIcon } from "lucide-react";
import { ConnectionCard } from "@/components/ConnectionCard";
import { CatalogTable } from "@/components/CatalogTable";
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
  const navItem = (id: Tab, label: string, Icon: LucideIcon) => {
    const disabledForAdmission = Boolean(runAdmission) && id !== "emitter";
    return <button onClick={() => navigate(id)} disabled={disabledForAdmission}
      aria-current={tab === id ? "page" : undefined}
      title={disabledForAdmission ? "Wait for the pending run admission before leaving the workspace." : undefined}
      className={cn("relative flex w-full items-center gap-3 rounded-btn border border-transparent px-3 py-2.5 text-left text-[13px] transition-colors disabled:cursor-wait disabled:opacity-40",
        tab === id ? "border-selection/60 bg-selected text-foreground before:absolute before:inset-y-2 before:left-0 before:w-0.5 before:bg-signal" : "text-muted-foreground enabled:hover:bg-card enabled:hover:text-foreground")}>
      <Icon aria-hidden="true" className={cn("h-4 w-4 shrink-0", tab === id && "text-signal")} />{label}
    </button>;
  };

  return (
    <div className="flex min-h-screen flex-col lg:h-screen lg:overflow-hidden">
      <a href="#workspace" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:rounded focus:bg-card focus:p-3">Skip to workspace</a>
      <header className="flex h-16 flex-none items-center gap-3 border-b bg-background px-4 sm:px-6">
        <span aria-hidden="true" className="grid h-8 w-8 place-items-center rounded-lg border bg-card text-signal"><Activity className="h-5 w-5" /></span>
        <span className="text-lg font-medium tracking-tight">Replicant</span>
        <span className="ml-2 hidden border-l pl-4 text-label text-muted-foreground sm:block">Synthetic telemetry workspace</span>
        <span className="ml-auto hidden font-mono text-micro text-muted-foreground md:block">CEF · {vendorShortLabel(vendor)}</span>
        <button onClick={() => setRailOpen((open) => !open)} aria-expanded={railOpen} aria-controls="workspace-navigation"
          className="quiet-button ml-auto lg:hidden">Menu <ChevronDown aria-hidden="true" className={cn("h-4 w-4", railOpen && "rotate-180")} /></button>
      </header>
      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <aside id="workspace-navigation" className={cn("flex-none flex-col border-b bg-background p-3 lg:flex lg:w-[192px] lg:border-b-0 lg:border-r lg:py-6", railOpen ? "flex" : "hidden")}>
          <div className="mb-4 px-3 text-[10px] font-medium uppercase tracking-[0.16em] text-muted-foreground">Workspace</div>
          <nav aria-label="Main navigation" className="space-y-1">
            {navItem("emitter", "Run workspace", Activity)}
            {navItem("techniques", "Techniques", Layers)}
            {navItem("logs", "Process logs", List)}
            {navItem("docs", "Documentation", BookOpen)}
            {config.terminal_enabled && navItem("terminal", "Terminal", Terminal)}
          </nav>
          <div className="mt-6 border-t pt-4 lg:mt-auto">
            {navItem("collector", "Collector", Radio)}
            <p className="mt-2 break-all px-3 font-mono text-micro leading-relaxed text-muted-foreground">
              {collector ? `${collector.host}:${collector.port} · ${collector.transport.toUpperCase()}` : "Not configured"}
            </p>
            <p className="mt-2 px-3 text-label text-muted-foreground">{collector ? "Receipt remains unconfirmed." : "Runs default to no send."}</p>
          </div>
        </aside>
        <main ref={mainRef} id="workspace" tabIndex={-1} className="min-w-0 flex-1 p-4 outline-none sm:p-6 lg:overflow-y-auto lg:scroll-thin xl:p-8">
          {/* Keep drafts, evidence, and admission ownership mounted across navigation
              and profile loading. Lazy auxiliary views still poll only when open. */}
          <section hidden={tab !== "emitter"} aria-label="Run workspace">
            {!catalogReady && <p role="status" className="mb-4 text-muted-foreground">Loading the {vendorShortLabel(vendor)} catalog…</p>}
            <RunPanel technique={catalogReady ? selected : null} defaultSeed={config.default_seed}
              collector={collector} vendor={vendor} epsCap={config.eps_cap} anchorEpoch={config.anchor_epoch}
              initialActiveRun={activeRun} onActiveRunChange={setActiveRun}
              onActiveRunDiscoveryChange={setActiveRunDiscoveryPending} onRunAdmissionChange={setRunAdmission}
              onChooseTechnique={() => navigate("techniques")} onConfigureCollector={() => navigate("collector")}
              vendorControls={<VendorPicker vendor={vendor} vendors={config.vendors} onVendorChange={setVendor}
                disabled={vendorLocked} reason={vendorLockReason} />} />
          </section>
          <section hidden={tab !== "techniques"} className="mx-auto max-w-[1160px]">
            <div className="mb-6"><h1 className="text-3xl font-medium tracking-tight">Technique library</h1>
              <p className="mt-2 text-body text-muted-foreground">Choose the behavior you want to exercise. Each technique includes its signal, field coverage, and detection context.</p></div>
            <div className="panel">
              <CatalogTable techniques={catalogReady ? catalog.techniques : []} selectedId={selected?.id ?? null}
                onSelect={(technique) => { setSelected(technique); navigate("emitter"); }} />
            </div>
          </section>
          <section hidden={tab !== "collector"} className="mx-auto max-w-[680px]">
            <h1 className="text-3xl font-medium tracking-tight">Collector connection</h1>
            <p className="mb-6 mt-2 text-body text-muted-foreground">Set your syslog destination and send a synthetic test log. Confirm receipt and parsing in your SIEM.</p>
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
    </div>
  );
}
