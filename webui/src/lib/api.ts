// API client. The per-session token arrives in the page URL (?token=...) from the
// `replicant web` launcher and is attached to every request.

export const TOKEN = new URLSearchParams(window.location.search).get("token") || "";

export interface Technique {
  id: string;
  name: string;
  ndr_rule: string;
  ndr_uc: string;
  log_type: string;
  subtype: string;
  attack: string[];
  tactics: string[];
  intensities: string[];
  implemented: boolean;
  safety_notes: string | null;
  signature_id: string;
  action: string | null;
  cef_fields_held: string[];
  cef_fields_varied: string[];
  params: Record<string, Record<string, unknown>>;
  distributions: Record<string, unknown>;
  benign_baseline: string | null;
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
}

export const VENDOR_LABELS: Record<string, string> = {
  fortigate: "FortiGate",
  paloalto: "Palo Alto (PAN-OS)",
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

export interface Manifest {
  technique_id: string;
  technique_name: string;
  ndr_uc: string;
  intensity: string;
  seed: number;
  target: string;
  transport: string;
  event_count: number;
  started_at: string;
  ended_at: string;
  anchor_epoch: number;
  warmup_note: string | null;
  [key: string]: unknown;
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-Replicant-Token": TOKEN,
      ...(init?.headers || {}),
    },
  });
  if (!resp.ok) {
    const detail = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new Error(detail.detail || `request failed: ${resp.status}`);
  }
  return resp.json() as Promise<T>;
}

export const getCatalog = () => api<CatalogResponse>("/api/catalog");
export const getConfig = () => api<ConfigResponse>("/api/config");

export interface TechniqueSample {
  technique_id: string;
  vendor: string;
  intensity: string;
  log_type: string;
  subtype: string;
  signature_id: string;
  cef_fields_held: string[];
  cef_fields_varied: string[];
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

export const testConnection = (collector: Collector, vendor?: string) =>
  api<{ ok: boolean; endpoint: string; line?: string; error?: string }>("/api/connect/test", {
    method: "POST",
    body: JSON.stringify({ ...collector, vendor }),
  });

export interface RunBody {
  technique_id: string;
  intensity: string;
  duration?: string | null;
  seed?: number | null;
  to_file?: string | null;
  no_send: boolean;
  collector?: Collector | null;
  vendor?: string | null;
}

export const startRun = (body: RunBody) =>
  api<{ run_id: string; total: number }>("/api/runs", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const stopRun = (runId: string) =>
  api<{ ok: boolean }>(`/api/runs/${runId}/stop`, { method: "POST" });

export function runEventsUrl(runId: string): string {
  return `/api/runs/${runId}/events?token=${encodeURIComponent(TOKEN)}`;
}

export function terminalWsUrl(): string {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${window.location.host}/ws/terminal?token=${encodeURIComponent(TOKEN)}`;
}
