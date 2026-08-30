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
  // Neutral, not orange and not green. "Sent, unconfirmed" colored like a live
  // signal is the verified-badge lie with a different word; the honest verdicts
  // read in the plain text color and only a failure gets the signal color.
  sent_unconfirmed: { label: "sent, unconfirmed", tone: "text-foreground" },
  handshake_ok: { label: "handshake ok", tone: "text-foreground" },
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
    <section className="rounded-lg bg-card px-4 py-5">
      <div className="u-label mb-2.5">Collector</div>
      <div className="mb-4 flex items-center gap-2">
        <span className="h-1.5 w-1.5 flex-none rounded-full bg-text-4" />
        <span className={cn("font-mono text-label uppercase tracking-[-0.24px]", BADGE[badge].tone)}>
          {BADGE[badge].label}
        </span>
      </div>

      {/* Content-sized segments with nowrap: "Check Point" has wrapped inside an
          equal-width segment twice now, so the segments take the width their
          label needs. The active segment recesses to the canvas color. */}
      <div
        role="radiogroup"
        aria-label="Vendor profile"
        className="flex w-max max-w-full overflow-hidden rounded-btn border"
      >
        {vendors.map((v) => (
          <button
            key={v}
            role="radio"
            aria-checked={v === vendor}
            onClick={() => onVendorChange(v)}
            className={cn(
              "whitespace-nowrap border-r px-2.5 py-2 font-mono text-label uppercase tracking-[-0.24px] transition-colors last:border-r-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring",
              v === vendor
                ? "bg-background text-foreground"
                : "text-text-4 hover:text-foreground",
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
            className="h-9 font-mono text-data"
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
            className="h-9 font-mono text-data"
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
        <div>
          <label className="u-label mb-1.5 block">Trans</label>
          <Select value={transport} onValueChange={setTransport}>
            <SelectTrigger className="h-9 font-mono text-data">
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
            <label htmlFor="tlsverify" className="whitespace-nowrap text-body text-muted-foreground">
              Verify cert
            </label>
          </div>
          <div>
            <label className="u-label mb-1.5 block" htmlFor="cafile">
              CA file (optional)
            </label>
            <Input
              id="cafile"
              className="h-9 font-mono text-data"
              value={tlsCafile}
              onChange={(e) => setTlsCafile(e.target.value)}
              placeholder="/path/to/ca.pem"
            />
          </div>
        </div>
      )}

      <button
        onClick={handleTest}
        disabled={busy || !host}
        className="mt-4 w-full rounded-btn bg-primary px-4 py-2.5 font-mono text-label uppercase tracking-[-0.24px] text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {busy ? "Sending…" : "Send test log"}
      </button>
      <div className="mt-3 text-center font-mono text-micro uppercase tracking-[-0.24px] text-text-4">
        cap {epsCap} eps
      </div>

      {error && (
        <div className="mt-3 flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2.5 text-label leading-relaxed text-destructive">
          <X className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {report && !stale && !error && (
        <div
          data-testid="connect-report"
          className={cn(
            "mt-3 space-y-2 rounded-md border p-2.5 text-label leading-relaxed",
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
            <div className="font-mono text-micro">
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
        <div className="mt-3 rounded-md border p-2.5 text-label leading-relaxed text-text-3">
          The target changed since the last test. Send a test log to describe this one.
        </div>
      )}
    </section>
  );
}
