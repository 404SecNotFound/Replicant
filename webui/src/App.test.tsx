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

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import * as api from "@/lib/api";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    getActiveRun: vi.fn(),
    getCatalog: vi.fn(),
    getConfig: vi.fn(),
    getPlanPreview: vi.fn(),
    getSample: vi.fn(),
    startRun: vi.fn(),
  };
});

const TECHNIQUE: api.Technique = {
  id: "REP-001",
  name: "Beaconing",
  ndr_rule: "rule",
  ndr_uc: "UC-001",
  objective: "Prove a detection can catch a beacon by its interval.",
  logical_log_type: "traffic",
  logical_subtype: "forward",
  logical_families: ["traffic:forward"],
  log_type: "traffic",
  subtype: "forward",
  native_log_type: "traffic",
  native_subtype: "forward",
  native_signature_id: "00013",
  native_action: "accept",
  native_metadata_scope: "primary",
  native_metadata_semantics: "Primary FortiGate category and subtype",
  attack: ["T1071"],
  tactics: ["Command and Control"],
  intensities: ["low", "medium", "high"],
  implemented: true,
  safety_notes: null,
  signature_id: "00013",
  action: "accept",
  cef_fields_held: ["dst"],
  cef_fields_varied: ["bytes"],
  native_cef_fields_held: ["dst"],
  native_cef_fields_varied: ["bytes"],
  native_cef_fields_unavailable: { held: [], varied: [] },
  native_cef_fields_by_logical_family: {
    "traffic:forward": {
      held: ["dst"],
      varied: ["bytes"],
      unavailable: { held: [], varied: [] },
    },
  },
  params: { medium: {} },
  distributions: {},
  benign_baseline: null,
  transferability: "transfers",
  transferability_note: null,
  references: [],
};

function config(overrides: Partial<api.ConfigResponse> = {}): api.ConfigResponse {
  return {
    default_seed: 1337,
    eps_cap: 2000,
    default_intensity: "medium",
    hostname: "FGT-LAB-01",
    anchor_epoch: 1752537600,
    accepted_as: "FGT-LAB-01",
    vendor: "fortigate",
    vendors: ["fortigate", "paloalto", "checkpoint"],
    terminal_enabled: true,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getActiveRun).mockResolvedValue({
    run_id: null,
    technique_id: null,
    status: null,
  });
  vi.mocked(api.getPlanPreview).mockResolvedValue({
    event_count: 49,
    plan_span_s: 14280,
    compressed_span_s: 14280,
    projected_s: 14280,
    projected_by_pace: { plan: 14280, burst: 0.24 },
    pace: "burst",
    speed: 1,
  });
  vi.mocked(api.getCatalog).mockResolvedValue({
    vendor_profile: "fortigate",
    timezone: "UTC+04:00",
    techniques: [TECHNIQUE],
  });
  vi.mocked(api.getSample).mockResolvedValue({
    technique_id: "REP-001",
    vendor: "fortigate",
    intensity: "low",
    logical_log_type: "traffic",
    logical_subtype: "forward",
    logical_families: ["traffic:forward"],
    log_type: "traffic",
    subtype: "forward",
    signature_id: "00013",
    native_log_type: "traffic",
    native_subtype: "forward",
    native_signature_id: "00013",
    native_action: "accept",
    native_metadata_scope: "primary",
    native_metadata_semantics: "Primary FortiGate category and subtype",
    cef_fields_held: ["dst"],
    cef_fields_varied: ["bytes"],
    native_cef_fields_held: ["dst"],
    native_cef_fields_varied: ["bytes"],
    native_cef_fields_unavailable: { held: [], varied: [] },
    native_cef_fields_by_logical_family: {
      "traffic:forward": {
        held: ["dst"],
        varied: ["bytes"],
        unavailable: { held: [], varied: [] },
      },
    },
    lines: ["CEF:0|Fortinet|Fortigate|..."],
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("navigation", () => {
  it("always offers the Docs tab", async () => {
    vi.mocked(api.getConfig).mockResolvedValue(config());

    render(<App />);

    expect(await screen.findByRole("button", { name: "Docs" })).toBeInTheDocument();
  });

  it("has no scenario surface (OBS-006 / CHAIN-16, deferred by design)", async () => {
    vi.mocked(api.getConfig).mockResolvedValue(config());

    render(<App />);
    await screen.findByRole("button", { name: "Emitter" });

    expect(screen.queryByText(/scenario/i)).not.toBeInTheDocument();
  });
});

describe("terminal tab visibility", () => {
  it("offers the Terminal tab when the server says it is available", async () => {
    vi.mocked(api.getConfig).mockResolvedValue(config({ terminal_enabled: true }));

    render(<App />);

    expect(await screen.findByRole("button", { name: "Terminal" })).toBeInTheDocument();
  });

  it("hides the Terminal tab when the server has disabled it", async () => {
    // The server refuses the websocket outright on a non-loopback bind. Leaving the
    // tab visible would offer the operator a control that can only ever fail.
    vi.mocked(api.getConfig).mockResolvedValue(config({ terminal_enabled: false }));

    render(<App />);

    expect(await screen.findByRole("button", { name: "Emitter" })).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Terminal" })).not.toBeInTheDocument(),
    );
  });
});

describe("vendor-specific detection metadata", () => {
  it("reloads catalog metadata when the selected profile changes", async () => {
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.getCatalog).mockImplementation(async (vendor?: string) => ({
      vendor_profile: vendor ?? "fortigate",
      timezone: "UTC+04:00",
      techniques: [
        vendor === "paloalto"
          ? {
              ...TECHNIQUE,
              native_log_type: "TRAFFIC",
              native_subtype: "end",
              native_signature_id: "end",
              native_action: "allow",
              native_metadata_semantics: "Primary PAN-OS CEF name and signature ID",
            }
          : TECHNIQUE,
      ],
    }));

    render(<App />);
    fireEvent.click(await screen.findByRole("radio", { name: "PAN-OS" }));

    await waitFor(() => expect(api.getCatalog).toHaveBeenCalledWith("paloalto"));
    expect((await screen.findAllByText("TRAFFIC:end")).length).toBeGreaterThan(0);
  });

  it("locks the vendor selector while any run is active", async () => {
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.getActiveRun).mockResolvedValue({
      run_id: "abc123",
      technique_id: "REP-004",
      status: "running",
    });

    render(<App />);

    const panOs = await screen.findByRole("radio", { name: "PAN-OS" });
    await waitFor(() => expect(panOs).toBeDisabled());
    expect(screen.getByText(/vendor profile is locked while REP-004 is running/i)).toBeVisible();

    fireEvent.click(panOs);
    expect(api.getCatalog).not.toHaveBeenCalledWith("paloalto");
  });

  it("keeps the local run panel mounted when a run starts", async () => {
    class FakeEventSource {
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      onerror: (() => void) | null = null;
      close = vi.fn();
    }

    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.startRun).mockResolvedValue({
      run_id: "run-1",
      total: 49,
      pace: "burst",
      speed: 1,
      projected_s: 0.024,
      plan_span_s: 14280,
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Run without sending" }));

    const panOs = await screen.findByRole("radio", { name: "PAN-OS" });
    await waitFor(() => expect(panOs).toBeDisabled());
    expect(screen.getByText(/vendor profile is locked while REP-001 is running/i)).toBeVisible();
    expect(screen.getByRole("button", { name: "Stop run" })).toBeEnabled();

    fireEvent.click(panOs);
    expect(api.getCatalog).not.toHaveBeenCalledWith("paloalto");
    expect(screen.getByRole("button", { name: "Stop run" })).toBeEnabled();
  });
});
