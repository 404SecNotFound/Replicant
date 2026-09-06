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

// Browser API client. The launch URL's persistent token authenticates the HTML
// navigation, and the server exchanges it for an httpOnly session cookie before
// this bundle runs. Never copy that token into JavaScript state or an API header:
// doing so would let every request keep authenticating with the master credential
// after the browser session expired or was logged out.

import type { PaceChoice, PlanPreview } from "./pacing";

export interface NativeFieldCoverage {
  held: string[];
  varied: string[];
  unavailable: { held: string[]; varied: string[] };
}

/** Return `href` without its `token` parameter, or null if it had none. */
export function urlWithoutToken(href: string): string | null {
  const url = new URL(href);
  if (!url.searchParams.has("token")) return null;
  url.searchParams.delete("token");
  return url.toString();
}

export interface Technique {
  id: string;
  name: string;
  ndr_rule: string;
  ndr_uc: string;
  /** What running this technique is meant to establish. One sentence. */
  objective: string;
  /** Vendor-neutral builder dispatch family. */
  logical_log_type: string;
  logical_subtype: string;
  /** Every vendor-neutral family emitted by the plan; the pair above is primary. */
  logical_families: string[];
  /** Compatibility aliases for the catalog's primary logical/FortiGate binding. */
  log_type: string;
  subtype: string;
  signature_id: string;
  action: string | null;
  /** Selected-profile identifiers for the primary logical family only. */
  native_log_type: string;
  native_subtype: string;
  native_signature_id: string;
  native_action: string | null;
  native_metadata_scope: "primary";
  native_metadata_semantics: string;
  attack: string[];
  tactics: string[];
  intensities: string[];
  implemented: boolean;
  safety_notes: string | null;
  /** Compatibility signal vocabulary from the catalog. */
  cef_fields_held: string[];
  cef_fields_varied: string[];
  /** Selected-profile signal keys across the whole plan. */
  native_cef_fields_held: string[];
  native_cef_fields_varied: string[];
  native_cef_fields_unavailable: { held: string[]; varied: string[] };
  native_cef_fields_by_logical_family: Record<string, NativeFieldCoverage>;
  params: Record<string, Record<string, unknown>>;
  distributions: Record<string, unknown>;
  benign_baseline: string | null;
  /** Does a green result exercise the shipped rule, or only its parser? */
  transferability: "transfers" | "parser-only";
  /** Why it is parser-only, or a disclosed limit on one that otherwise transfers. */
  transferability_note: string | null;
  references: string[];
}

export interface CatalogResponse {
  vendor_profile: string;
  timezone: string;
  techniques: Technique[];
}

export interface ConfigResponse {
  default_seed: number;
  eps_cap: number;
  default_intensity: string;
  hostname: string;
  anchor_epoch: number;
  accepted_as: string;
  vendor: string;
  vendors: string[];
  terminal_enabled: boolean;
}

export const VENDOR_LABELS: Record<string, string> = {
  fortigate: "FortiGate",
  paloalto: "Palo Alto (PAN-OS)",
  checkpoint: "Check Point",
};

// Short forms for width-constrained controls. The vendor picker is three equal
// segments inside a 336px rail, which leaves about 92px each; "Palo Alto
// (PAN-OS)" wrapped to two lines and spilled out of its 28px-tall segment. The
// long forms stay in prose, where there is room and the full name is clearer.
export const VENDOR_SHORT_LABELS: Record<string, string> = {
  fortigate: "FortiGate",
  paloalto: "PAN-OS",
  checkpoint: "Check Point",
};

// An own-property check, not `VENDOR_LABELS[id] ?? id`: a plain object inherits
// from Object.prototype, so the bracket lookup resolves "constructor" and
// "toString" to functions. Those are not null or undefined, so ?? never fires
// and the caller gets a function where it expected a label.
//
// hasOwnProperty.call rather than Object.hasOwn because the project targets
// ES2020, and bumping the whole target for one lookup is not worth it.
export const vendorLabel = (id: string): string =>
  Object.prototype.hasOwnProperty.call(VENDOR_LABELS, id) ? VENDOR_LABELS[id] : id;

// Same own-property reasoning as above.
export const vendorShortLabel = (id: string): string =>
  Object.prototype.hasOwnProperty.call(VENDOR_SHORT_LABELS, id) ? VENDOR_SHORT_LABELS[id] : id;

export interface Manifest {
  technique_id: string;
  technique_name: string;
  ndr_uc: string;
  intensity: string;
  seed: number;
  target: string;
  transport: string;
  event_count: number;
  planned_event_count?: number | null;
  started_at: string;
  ended_at: string | null;
  updated_at?: string | null;
  anchor_epoch: number;
  warmup_note: string | null;
  status?: "running" | "done" | "stopped" | "error";
  partial?: boolean;
  error?: string | null;
  [key: string]: unknown;
}

/** An error that kept the response's status and structured detail.
 *
 * FastAPI's `detail` is a string for most failures but an object where the
 * client has to act on the parts rather than print the whole. Flattening it to
 * `new Error(detail)` rendered those as "[object Object]", so the information
 * that made the error actionable was destroyed at the one place that could have
 * used it.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(message: string, status: number, detail: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(path, {
    ...init,
    // This is the browser contract: same-origin, cookie-authenticated requests.
    // Scripts and CLI clients still use the server's Bearer/X-Replicant-Token
    // contract directly; the SPA must never possess or replay that credential.
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
  });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({ detail: resp.statusText }));
    const detail = body.detail;
    const message =
      typeof detail === "string"
        ? detail
        : (detail as { message?: string } | null)?.message || `request failed: ${resp.status}`;
    throw new ApiError(message, resp.status, detail);
  }
  return resp.json() as Promise<T>;
}

export interface ActiveRun {
  admission_id?: string | null;
  run_id: string | null;
  technique_id: string | null;
  vendor: string | null;
  status: string | null;
  event_count?: number;
  total?: number;
}

/** Which run holds the single-run lock. Server state, so only the server knows. */
export const getActiveRun = () => api<ActiveRun>("/api/runs/active");

export const getCatalog = (vendor?: string) =>
  api<CatalogResponse>(
    `/api/catalog${vendor ? `?vendor=${encodeURIComponent(vendor)}` : ""}`,
  );
export const getConfig = () => api<ConfigResponse>("/api/config");

export interface DocPage {
  id: string;
  title: string;
  available: boolean;
}

export interface DocsIndex {
  available: boolean;
  pages: DocPage[];
}

export interface DocContent {
  id: string;
  title: string;
  markdown: string;
}

export const getDocs = () => api<DocsIndex>("/api/docs");
export const getDoc = (id: string) => api<DocContent>(`/api/docs/${encodeURIComponent(id)}`);

/** The four operator-facing modes, least to most severe. */
export type LogLevel = "debug" | "verbose" | "info" | "warning";

export interface LogEntry {
  seq: number;
  ts: number;
  level: LogLevel;
  logger: string;
  message: string;
}

export interface LogsResponse {
  level: LogLevel;
  levels: LogLevel[];
  entries: LogEntry[];
  /** Pass back as `after` to fetch only what has arrived since. */
  cursor: number;
}

export const getLogs = (after = 0, limit = 500) =>
  api<LogsResponse>(`/api/logs?after=${after}&limit=${limit}`);

export const setLogLevel = (level: LogLevel) =>
  api<{ level: LogLevel }>("/api/logs/level", {
    method: "PUT",
    body: JSON.stringify({ level }),
  });

export interface TechniqueSample {
  technique_id: string;
  vendor: string;
  intensity: string;
  logical_log_type: string;
  logical_subtype: string;
  logical_families: string[];
  log_type: string;
  subtype: string;
  signature_id: string;
  native_log_type: string;
  native_subtype: string;
  native_signature_id: string;
  native_action: string | null;
  native_metadata_scope: "primary";
  native_metadata_semantics: string;
  cef_fields_held: string[];
  cef_fields_varied: string[];
  native_cef_fields_held: string[];
  native_cef_fields_varied: string[];
  native_cef_fields_unavailable: { held: string[]; varied: string[] };
  native_cef_fields_by_logical_family: Record<string, NativeFieldCoverage>;
  lines: string[];
}

export const getSample = (id: string, vendor?: string) =>
  api<TechniqueSample>(
    `/api/catalog/${encodeURIComponent(id)}/sample${
      vendor ? `?vendor=${encodeURIComponent(vendor)}` : ""
    }`,
  );

export interface Collector {
  host: string;
  port: number;
  transport: string;
  tls_verify?: boolean;
  tls_cafile?: string | null;
}

/** What a connect test established, and what it did not.
 *
 * Replaces the bool this endpoint used to be judged on. On UDP that bool only
 * meant the kernel accepted the datagram, which is true whenever a route
 * exists, and the UI rendered it as a green "verified".
 */
export interface PathReport {
  host: string;
  port: number;
  transport: string;
  verdict:
    | "sent_unconfirmed"
    | "refused"
    | "handshake_ok"
    | "name_not_resolved"
    | "failed";
  summary: string;
  proves: string;
  does_not_prove: string;
  source: string | null;
  interface: string | null;
  gateway: string | null;
  /** null means the platform could not answer, which is stated, not hidden. */
  direct: boolean | null;
  claim: string | null;
  path: string;
}

export const testConnection = (collector: Collector, vendor?: string) =>
  api<{ ok: boolean; endpoint: string; line?: string; error?: string; report?: PathReport }>(
    "/api/connect/test",
    {
      method: "POST",
      body: JSON.stringify({ ...collector, vendor }),
    },
  );

export interface RunBody {
  technique_id: string;
  intensity: string;
  duration?: string | null;
  seed?: number | null;
  to_file?: string | null;
  no_send: boolean;
  collector?: Collector | null;
  vendor?: string | null;
  /** Idempotent identity acknowledged by POST /api/run-admissions. */
  admission_id?: string | null;
  anchor?: string | null;
  /** Per-run slowdown. Null uses, and a value cannot exceed, the configured cap. */
  rate?: number | null;
  /** Delivery shape. Null lets the server pick from the destination. */
  pace?: PaceChoice | null;
  /** Compresses the plan timeline, event times included. Plan pacing only. */
  speed?: number;
}

export interface RunAdmissionState {
  admission_id: string;
  run_id: string;
  technique_id: string;
  vendor: string;
  status: string; // reserved | admitting | running | done | stopped | error
  event_count: number;
  total: number;
}

/**
 * Reserve the single-run owner before the potentially slow plan preparation.
 *
 * `admission_id` is generated by the browser and makes this call safe to retry
 * after a lost response. The returned run id stays stable through execution.
 */
export const reserveRun = (body: {
  admission_id: string;
  technique_id: string;
  vendor: string;
}) =>
  api<RunAdmissionState>("/api/run-admissions", {
    method: "POST",
    body: JSON.stringify(body),
  });

/** Resolve one known admission after the start response was unavailable. */
export const getRunAdmission = (admissionId: string) =>
  api<RunAdmissionState>(`/api/run-admissions/${encodeURIComponent(admissionId)}`);

export const startRun = (body: RunBody) =>
  api<{
    admission_id: string;
    run_id: string;
    vendor: string;
    total: number;
    pace: PaceChoice;
    speed: number;
    projected_s: number;
    plan_span_s: number;
  }>("/api/runs", {
    method: "POST",
    body: JSON.stringify(body),
  });

/**
 * How long this run would take, without starting it.
 *
 * Takes the same body as `startRun`, so the figures shown beside the pacing
 * options cannot describe a different run than the one that starts.
 */
export const getPlanPreview = (body: RunBody) =>
  api<PlanPreview>("/api/plan", { method: "POST", body: JSON.stringify(body) });

export const stopRun = (runId: string) =>
  api<{ ok: boolean }>(`/api/runs/${runId}/stop`, { method: "POST" });

export interface RunStatus {
  admission_id?: string | null;
  run_id: string;
  vendor: string;
  status: string; // reserved | admitting | running | done | stopped | error
  total: number;
  event_count: number;
  dropped: number;
  manifest: Manifest | null;
  manifest_path: string | null;
}

// Authoritative run state, polled when the SSE stream drops so a transient
// disconnect is not mistaken for the run finishing.
export const getRunStatus = (runId: string) =>
  api<RunStatus>(`/api/runs/${encodeURIComponent(runId)}`);

// Neither of these carries a credential in the query string any more.
//
// EventSource and WebSocket cannot set request headers, which is why the token
// used to be appended here. But a URL is the least private part of a request: it
// reaches server logs, browser history and the Referer header, and the value
// being appended was the *persistent* launch token from
// ~/.config/replicant/web-token. That was half of F-04.
//
// Both are same-origin, so the httpOnly session cookie authenticates them with
// no query parameter at all. The cookie is set on the first authenticated load,
// which is always the page load that precedes either of these.

export function runEventsUrl(runId: string): string {
  return `/api/runs/${encodeURIComponent(runId)}/events`;
}

export function terminalWsUrl(): string {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${window.location.host}/ws/terminal`;
}
