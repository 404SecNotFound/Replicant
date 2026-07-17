import { useEffect, useState } from "react";
import { Activity, Moon, Sun, Terminal as TerminalIcon, LayoutDashboard } from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ConnectionCard } from "@/components/ConnectionCard";
import { CatalogTable } from "@/components/CatalogTable";
import { RunPanel } from "@/components/RunPanel";
import { TerminalView } from "@/components/TerminalView";
import {
  getCatalog,
  getConfig,
  type CatalogResponse,
  type Collector,
  type ConfigResponse,
  type Technique,
} from "@/lib/api";

export default function App() {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [collector, setCollector] = useState<Collector | null>(null);
  const [selected, setSelected] = useState<Technique | null>(null);
  const [tab, setTab] = useState("dashboard");
  const [dark, setDark] = useState(true);

  useEffect(() => {
    Promise.all([getCatalog(), getConfig()])
      .then(([cat, cfg]) => {
        setCatalog(cat);
        setConfig(cfg);
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
      <div className="flex h-screen items-center justify-center text-muted-foreground">
        Loading Replicant...
      </div>
    );
  }

  return (
    <Tabs value={tab} onValueChange={setTab} className="flex h-screen flex-col">
      <header className="flex items-center justify-between border-b px-4 py-3">
        <div className="flex items-center gap-3">
          <Activity className="h-5 w-5 text-primary" />
          <div>
            <div className="text-sm font-semibold leading-tight">Replicant</div>
            <div className="text-[11px] text-muted-foreground">
              synthetic FortiGate CEF · vendor {catalog.vendor_profile} · loopback
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <TabsList>
            <TabsTrigger value="dashboard">
              <LayoutDashboard className="h-4 w-4" /> Dashboard
            </TabsTrigger>
            <TabsTrigger value="terminal">
              <TerminalIcon className="h-4 w-4" /> Terminal
            </TabsTrigger>
          </TabsList>
          <Badge variant={collector ? "default" : "muted"}>
            {collector ? `connected ${collector.host}:${collector.port}` : "no collector"}
          </Badge>
          <Button variant="ghost" size="icon" onClick={() => setDark((d) => !d)}>
            {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </Button>
        </div>
      </header>

      <TabsContent value="dashboard" className="min-h-0 flex-1 p-4">
        <div className="grid h-full min-h-0 grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
          <div className="flex min-h-0 flex-col gap-4">
            <ConnectionCard
              epsCap={config.eps_cap}
              collector={collector}
              onCollectorChange={setCollector}
            />
            <CatalogTable
              techniques={catalog.techniques}
              selectedId={selected?.id ?? null}
              onSelect={setSelected}
            />
          </div>
          <RunPanel technique={selected} defaultSeed={config.default_seed} collector={collector} />
        </div>
      </TabsContent>

      <TabsContent value="terminal" className="min-h-0 flex-1 p-4">
        <Card className="h-full overflow-hidden p-2">
          <TerminalView />
        </Card>
      </TabsContent>
    </Tabs>
  );
}
