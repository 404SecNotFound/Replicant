import { useState } from "react";
import { Plug, CheckCircle2, XCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { testConnection, type Collector } from "@/lib/api";

interface Props {
  epsCap: number;
  collector: Collector | null;
  onCollectorChange: (c: Collector | null) => void;
}

export function ConnectionCard({ epsCap, collector, onCollectorChange }: Props) {
  const [host, setHost] = useState(collector?.host ?? "127.0.0.1");
  const [port, setPort] = useState(String(collector?.port ?? 514));
  const [transport, setTransport] = useState(collector?.transport ?? "udp");
  const [tlsVerify, setTlsVerify] = useState(collector?.tls_verify ?? true);
  const [tlsCafile, setTlsCafile] = useState(collector?.tls_cafile ?? "");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  async function handleTest() {
    setBusy(true);
    setResult(null);
    const target: Collector = { host, port: Number(port), transport };
    if (transport === "tls") {
      target.tls_verify = tlsVerify;
      target.tls_cafile = tlsCafile.trim() || null;
    }
    try {
      const resp = await testConnection(target);
      if (resp.ok) {
        onCollectorChange(target);
        setResult({ ok: true, message: `Test log sent to ${resp.endpoint}. Confirm on collector.` });
      } else {
        setResult({ ok: false, message: resp.error || "transport error" });
      }
    } catch (err) {
      setResult({ ok: false, message: (err as Error).message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle className="flex items-center gap-2 text-base">
          <Plug className="h-4 w-4 text-primary" /> Collector
        </CardTitle>
        <Badge variant="muted">eps cap {epsCap}</Badge>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-[1fr_90px_110px] gap-2">
          <div className="space-y-1">
            <Label htmlFor="host">Host</Label>
            <Input id="host" value={host} onChange={(e) => setHost(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="port">Port</Label>
            <Input id="port" value={port} onChange={(e) => setPort(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label>Transport</Label>
            <Select value={transport} onValueChange={setTransport}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="udp">udp</SelectItem>
                <SelectItem value="tcp">tcp</SelectItem>
                <SelectItem value="tls">tls</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        {transport === "tls" && (
          <div className="grid grid-cols-[auto_1fr] items-end gap-3">
            <div className="flex items-center gap-2 pb-2">
              <Switch id="tlsverify" checked={tlsVerify} onCheckedChange={setTlsVerify} />
              <Label htmlFor="tlsverify" className="whitespace-nowrap">
                Verify cert
              </Label>
            </div>
            <div className="space-y-1">
              <Label htmlFor="cafile">CA file (optional)</Label>
              <Input
                id="cafile"
                value={tlsCafile}
                onChange={(e) => setTlsCafile(e.target.value)}
                placeholder="/path/to/ca.pem"
              />
            </div>
          </div>
        )}
        <div className="flex items-center gap-3">
          <Button onClick={handleTest} disabled={busy || !host}>
            {busy ? "Sending..." : "Send test log"}
          </Button>
          {collector && (
            <span className="text-xs text-muted-foreground">
              active: {collector.host}:{collector.port}/{collector.transport}
            </span>
          )}
        </div>
        {result && (
          <div
            className={`flex items-start gap-2 rounded-md border p-2 text-xs ${
              result.ok ? "text-primary" : "text-destructive"
            }`}
          >
            {result.ok ? (
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
            ) : (
              <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
            )}
            <span>{result.message}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
