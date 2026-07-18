import { useState } from "react";
import { Check, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { testConnection, vendorLabel, type Collector } from "@/lib/api";

interface Props {
  epsCap: number;
  collector: Collector | null;
  onCollectorChange: (c: Collector | null) => void;
  vendor: string;
  vendors: string[];
  onVendorChange: (v: string) => void;
}

export function ConnectionCard({
  epsCap,
  collector,
  onCollectorChange,
  vendor,
  vendors,
  onVendorChange,
}: Props) {
  const [host, setHost] = useState(collector?.host ?? "10.20.0.50");
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
      const resp = await testConnection(target, vendor);
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
    <section className="rounded-lg border bg-card p-4">
      <div className="mb-3.5 flex items-baseline justify-between">
        <span className="text-[13px] font-semibold">Collector</span>
        <span className="font-mono text-[10.5px] text-text-3">
          {collector ? "verified" : "not connected"}
        </span>
      </div>

      <div className="u-label mb-1.5">Vendor profile</div>
      <div
        role="radiogroup"
        aria-label="Vendor profile"
        className="flex gap-0.5 rounded-md border bg-background p-0.5"
      >
        {vendors.map((v) => (
          <button
            key={v}
            role="radio"
            aria-checked={v === vendor}
            onClick={() => onVendorChange(v)}
            className={cn(
              "h-7 flex-1 rounded-[5px] text-[12px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              v === vendor
                ? "bg-elev text-foreground shadow-sm"
                : "text-text-3 hover:text-foreground",
            )}
          >
            {vendorLabel(v)}
          </button>
        ))}
      </div>

      <div className="mt-3.5 grid grid-cols-[1fr_66px_78px] gap-2">
        <div>
          <label className="u-label mb-1.5 block" htmlFor="host">
            Host
          </label>
          <Input
            id="host"
            className="h-9 font-mono text-[13px]"
            value={host}
            onChange={(e) => setHost(e.target.value)}
          />
        </div>
        <div>
          <label className="u-label mb-1.5 block" htmlFor="port">
            Port
          </label>
          <Input
            id="port"
            className="h-9 font-mono text-[13px]"
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
        <div>
          <label className="u-label mb-1.5 block">Trans</label>
          <Select value={transport} onValueChange={setTransport}>
            <SelectTrigger className="h-9 font-mono text-[13px]">
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
        <div className="mt-3 grid grid-cols-[auto_1fr] items-end gap-3">
          <div className="flex items-center gap-2 pb-2">
            <Switch id="tlsverify" checked={tlsVerify} onCheckedChange={setTlsVerify} />
            <label htmlFor="tlsverify" className="whitespace-nowrap text-[12.5px] text-muted-foreground">
              Verify cert
            </label>
          </div>
          <div>
            <label className="u-label mb-1.5 block" htmlFor="cafile">
              CA file (optional)
            </label>
            <Input
              id="cafile"
              className="h-9 font-mono text-[12px]"
              value={tlsCafile}
              onChange={(e) => setTlsCafile(e.target.value)}
              placeholder="/path/to/ca.pem"
            />
          </div>
        </div>
      )}

      <div className="mt-3.5 flex items-center justify-between">
        <button
          onClick={handleTest}
          disabled={busy || !host}
          className="h-8 rounded-md border px-3 text-[12.5px] font-medium text-muted-foreground transition-colors hover:text-foreground disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {busy ? "Sending…" : "Send test log"}
        </button>
        <span className="font-mono text-[11px] text-text-3">cap {epsCap} eps</span>
      </div>

      {result && (
        <div
          className={cn(
            "mt-3 flex items-start gap-2 rounded-md border p-2.5 text-[11.5px] leading-relaxed",
            result.ok
              ? "border-border text-foreground"
              : "border-destructive/40 bg-destructive/10 text-destructive",
          )}
        >
          {result.ok ? (
            <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-signal" />
          ) : (
            <X className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          )}
          <span>{result.message}</span>
        </div>
      )}
    </section>
  );
}
