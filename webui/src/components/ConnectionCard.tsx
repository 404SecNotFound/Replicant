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

import { useState } from "react";
import { X } from "lucide-react";
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
import { testConnection, vendorShortLabel, type Collector, type PathReport } from "@/lib/api";

/** Badge copy, keyed by verdict.
 *
 * The word "verified" appears nowhere, on any transport. It was set from a UDP
 * `sendto` succeeding, which only proves a route exists, and it read green
 * against a collector that could not receive anything across two live lab
 * sessions. A glanced-at green badge is indistinguishable from a correct one,
 * so no state the tool can observe by itself earns that word: the strongest
 * honest claim on UDP is that the datagram left this host.
 *
 * Exhaustive over BadgeState, so a new verdict without copy fails to compile.
 */
const BADGE: Record<BadgeState, { label: string; tone: string }> = {
  untested: { label: "not tested", tone: "text-text-3" },
  testing: { label: "testing…", tone: "text-text-3" },
  stale: { label: "not tested", tone: "text-text-3" },
  sent_unconfirmed: { label: "sent, unconfirmed", tone: "text-signal" },
  handshake_ok: { label: "handshake ok", tone: "text-signal" },
  refused: { label: "refused", tone: "text-destructive" },
  name_not_resolved: { label: "name not resolved", tone: "text-destructive" },
  failed: { label: "failed", tone: "text-destructive" },
};

type BadgeState =
  | "untested"
  | "testing"
  | "stale"
  | "sent_unconfirmed"
  | "handshake_ok"
  | "refused"
  | "name_not_resolved"
  | "failed";

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
  const [report, setReport] = useState<PathReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  // A test result belongs to the target it was obtained for. Editing the host
  // after a test used to leave the previous verdict on screen describing an
  // address that was no longer in the form, which is the same class of lie the
  // verdict exists to remove.
  const targetKey = `${host}|${port}|${transport}|${tlsVerify}|${tlsCafile}`;
  const [testedKey, setTestedKey] = useState<string | null>(null);
  const stale = testedKey !== null && testedKey !== targetKey;

  async function handleTest() {
    setBusy(true);
    setReport(null);
    setError(null);
    const target: Collector = { host, port: Number(port), transport };
    if (transport === "tls") {
      target.tls_verify = tlsVerify;
      target.tls_cafile = tlsCafile.trim() || null;
    }
    try {
      const resp = await testConnection(target, vendor);
      setReport(resp.report ?? null);
      setTestedKey(targetKey);
      // A collector is armed whenever the operator asked for it. A negative
      // verdict is reported, never enforced: a firewall that drops ICMP would
      // otherwise block a working lab, which is worse than the defect being
      // fixed here.
      onCollectorChange(target);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const badge: BadgeState = busy
    ? "testing"
    : error
      ? "failed"
      : stale || !report
        ? "untested"
        : report.verdict;

  return (
    <section className="rounded-lg border bg-card p-4">
      <div className="mb-3.5 flex items-baseline justify-between">
        <span className="text-[13px] font-semibold">Collector</span>
        <span className={cn("font-mono text-[10.5px]", BADGE[badge].tone)}>{BADGE[badge].label}</span>
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
            {vendorShortLabel(v)}
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

      {error && (
        <div className="mt-3 flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2.5 text-[11.5px] leading-relaxed text-destructive">
          <X className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {report && !stale && !error && (
        <div
          data-testid="connect-report"
          className={cn(
            "mt-3 space-y-2 rounded-md border p-2.5 text-[11.5px] leading-relaxed",
            report.verdict === "refused" ||
              report.verdict === "failed" ||
              report.verdict === "name_not_resolved"
              ? "border-destructive/40 bg-destructive/10 text-destructive"
              : "border-border text-foreground",
          )}
        >
          {/* The path, first and in monospace.
              This is the part that answers the defect, not the probe above it.
              A destination on its own never looks wrong: "10.20.0.125:514" reads
              as perfectly ordinary, and it survived two lab sessions and a dozen
              log lines. Beside its own source address it does not. */}
          {report.source && (
            <div className="font-mono text-[11px]">
              {report.source} <span className="text-text-3">-&gt;</span> {report.host}:
              {report.port}
              {report.interface ? (
                <span className="text-text-3">
                  {" "}
                  via {report.interface}
                  {report.gateway ? ` (gateway ${report.gateway})` : " (direct)"}
                </span>
              ) : (
                // Stated, not omitted. Silence would let the operator infer a
                // directness that was never established: route_for reads
                // /proc/net/route and answers for nothing on macOS.
                <span className="text-text-3"> (route not determined on this platform)</span>
              )}
            </div>
          )}

          {report.claim && <div className="text-signal">{report.claim}</div>}

          <div>{report.summary}</div>

          {/* Both required and both non-empty. A verdict without its limits is
              the same defect wearing better wording. */}
          <div className="text-text-3">
            Proves: {report.proves} Does not prove: {report.does_not_prove}
          </div>
        </div>
      )}

      {stale && (
        <div className="mt-3 rounded-md border p-2.5 text-[11.5px] leading-relaxed text-text-3">
          The target changed since the last test. Send a test log to describe this one.
        </div>
      )}
    </section>
  );
}
