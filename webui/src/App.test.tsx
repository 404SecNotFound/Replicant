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

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
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
    getRunAdmission: vi.fn(),
    getRunStatus: vi.fn(),
    getSample: vi.fn(),
    reserveRun: vi.fn(),
    startRun: vi.fn(),
    stopRun: vi.fn(),
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

function sample(vendor = "fortigate"): api.TechniqueSample {
  const paloAlto = vendor === "paloalto";
  return {
    technique_id: "REP-001",
    vendor,
    intensity: "low",
    logical_log_type: "traffic",
    logical_subtype: "forward",
    logical_families: ["traffic:forward"],
    log_type: paloAlto ? "TRAFFIC" : "traffic",
    subtype: paloAlto ? "end" : "forward",
    signature_id: paloAlto ? "end" : "00013",
    native_log_type: paloAlto ? "TRAFFIC" : "traffic",
    native_subtype: paloAlto ? "end" : "forward",
    native_signature_id: paloAlto ? "end" : "00013",
    native_action: paloAlto ? "allow" : "accept",
    native_metadata_scope: "primary",
    native_metadata_semantics: paloAlto
      ? "Primary PAN-OS CEF name and signature ID"
      : "Primary FortiGate category and subtype",
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
    lines: [
      paloAlto
        ? "CEF:0|Palo Alto Networks|PAN-OS|..."
        : "CEF:0|Fortinet|Fortigate|...",
    ],
  };
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.getActiveRun).mockResolvedValue({
    run_id: null,
    technique_id: null,
    vendor: null,
    status: null,
  });
  vi.mocked(api.getRunStatus).mockImplementation(() => new Promise(() => undefined));
  vi.mocked(api.reserveRun).mockImplementation(async (request) => ({
    admission_id: request.admission_id,
    run_id: "reserved-run",
    technique_id: request.technique_id,
    vendor: request.vendor,
    status: "reserved",
    event_count: 0,
    total: 0,
  }));
  vi.mocked(api.getRunAdmission).mockResolvedValue({
    admission_id: "00000000-0000-4000-8000-000000000001",
    run_id: "reserved-run",
    technique_id: "REP-001",
    vendor: "fortigate",
    status: "running",
    event_count: 0,
    total: 49,
  });
  vi.mocked(api.stopRun).mockResolvedValue({ ok: true });
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
  vi.mocked(api.getSample).mockResolvedValue(sample());
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("navigation", () => {
  it("always offers the Docs tab", async () => {
    vi.mocked(api.getConfig).mockResolvedValue(config());

    render(<App />);

    expect(await screen.findByRole("button", { name: "Documentation" })).toBeInTheDocument();
  });

  it("has no scenario surface (OBS-006 / CHAIN-16, deferred by design)", async () => {
    vi.mocked(api.getConfig).mockResolvedValue(config());

    render(<App />);
    await screen.findByRole("button", { name: "Run workspace" });

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

    expect(await screen.findByRole("button", { name: "Run workspace" })).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Terminal" })).not.toBeInTheDocument(),
    );
  });
});

describe("vendor-specific detection metadata", () => {
  it("keeps unknown ownership fail-closed until bootstrap and child probes recover", async () => {
    const noActive: api.ActiveRun = {
      run_id: null,
      technique_id: null,
      vendor: null,
      status: null,
    };
    const recoveredOwner: api.ActiveRun = {
      run_id: "recovered-pan-run",
      technique_id: "REP-001",
      vendor: "paloalto",
      status: "running",
      event_count: 3,
      total: 49,
    };
    const panTechnique: api.Technique = {
      ...TECHNIQUE,
      native_log_type: "TRAFFIC",
      native_subtype: "end",
      native_signature_id: "end",
      native_action: "allow",
      native_metadata_semantics: "Primary PAN-OS CEF name and signature ID",
    };
    vi.useFakeTimers();
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.getActiveRun)
      .mockRejectedValueOnce(new Error("first bootstrap failure"))
      .mockRejectedValueOnce(new Error("second bootstrap failure"))
      .mockResolvedValueOnce(noActive)
      .mockRejectedValueOnce(new Error("first child discovery failure"))
      .mockRejectedValueOnce(new Error("second child discovery failure"))
      .mockResolvedValue(recoveredOwner);
    vi.mocked(api.getCatalog).mockImplementation(async (vendor?: string) => ({
      vendor_profile: vendor ?? "fortigate",
      timezone: "UTC+04:00",
      techniques: [vendor === "paloalto" ? panTechnique : TECHNIQUE],
    }));
    vi.mocked(api.getSample).mockImplementation(async (_id, vendor) => sample(vendor));

    render(<App />);
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(screen.getByText(/Loading Replicant/i)).toBeVisible();
    expect(api.getCatalog).not.toHaveBeenCalled();
    expect(screen.queryByRole("radio", { name: "PAN-OS" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Run without sending/i })).toBeNull();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(api.getActiveRun).toHaveBeenCalledTimes(2);
    expect(screen.getByText(/Loading Replicant/i)).toBeVisible();
    expect(api.getCatalog).not.toHaveBeenCalled();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
      await Promise.resolve();
      await Promise.resolve();
    });

    const fortiGate = screen.getByRole("radio", { name: "FortiGate" });
    const panOs = screen.getByRole("radio", { name: "PAN-OS" });
    const runButton = screen.getByRole("button", { name: "Run without sending" });
    expect(api.getActiveRun).toHaveBeenCalledTimes(4);
    expect(fortiGate).toBeChecked();
    expect(fortiGate).toBeDisabled();
    expect(panOs).toBeDisabled();
    expect(runButton).toBeDisabled();
    expect(screen.getByTestId("active-owner-discovery")).toBeVisible();
    expect(screen.getByText(/confirms active run ownership with the backend/i)).toBeVisible();
    expect(api.getCatalog).toHaveBeenCalledWith("fortigate");
    expect(api.getCatalog).not.toHaveBeenCalledWith("paloalto");
    fireEvent.click(panOs);
    fireEvent.click(runButton);
    expect(api.startRun).not.toHaveBeenCalled();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(api.getActiveRun).toHaveBeenCalledTimes(5);
    expect(fortiGate).toBeDisabled();
    expect(runButton).toBeDisabled();
    expect(api.getCatalog).not.toHaveBeenCalledWith("paloalto");

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(vi.mocked(api.getActiveRun).mock.calls.length).toBeGreaterThanOrEqual(6);
    expect(screen.getByRole("radio", { name: "PAN-OS" })).toBeChecked();
    expect(screen.getByRole("radio", { name: "PAN-OS" })).toBeDisabled();
    expect(api.getCatalog).toHaveBeenCalledWith("paloalto");
    expect(screen.getByText("Primary PAN-OS CEF name and signature ID")).toBeVisible();
    expect(screen.queryByText("Primary FortiGate category and subtype")).toBeNull();
    expect(screen.getByText(/REP-001 is running under PAN-OS/i)).toBeVisible();
    expect(api.startRun).not.toHaveBeenCalled();
  });

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
    const panOs = await screen.findByRole("radio", { name: "PAN-OS" });
    await waitFor(() => expect(panOs).toBeEnabled());
    fireEvent.click(panOs);

    await waitFor(() => expect(api.getCatalog).toHaveBeenCalledWith("paloalto"));
    expect((await screen.findAllByText("TRAFFIC:end")).length).toBeGreaterThan(0);
  });

  it("boots a restored PAN-OS run into its canonical locked catalog", async () => {
    const panTechnique: api.Technique = {
      ...TECHNIQUE,
      native_log_type: "TRAFFIC",
      native_subtype: "end",
      native_signature_id: "end",
      native_action: "allow",
      native_metadata_semantics: "Primary PAN-OS CEF name and signature ID",
    };
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.getActiveRun).mockResolvedValue({
      run_id: "pan-run",
      technique_id: "REP-001",
      vendor: "paloalto",
      status: "running",
      event_count: 12,
      total: 49,
    });
    vi.mocked(api.getCatalog).mockImplementation(async (vendor?: string) => ({
      vendor_profile: vendor ?? "fortigate",
      timezone: "UTC+04:00",
      techniques: [vendor === "paloalto" ? panTechnique : TECHNIQUE],
    }));
    vi.mocked(api.getSample).mockImplementation(async (_id, vendor) => sample(vendor));

    render(<App />);

    const panOs = await screen.findByRole("radio", { name: "PAN-OS" });
    expect(panOs).toBeChecked();
    expect(panOs).toBeDisabled();
    expect(api.getCatalog).toHaveBeenCalledWith("paloalto");
    expect(api.getCatalog).not.toHaveBeenCalledWith("fortigate");
    expect(await screen.findByText("Primary PAN-OS CEF name and signature ID")).toBeVisible();
    expect((await screen.findAllByText("TRAFFIC:end")).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Sample CEF" }));
    await waitFor(() => expect(api.getSample).toHaveBeenCalledWith("REP-001", "paloalto"));
    expect(screen.queryByText("Primary FortiGate category and subtype")).toBeNull();
    expect(screen.getByText(/running under PAN-OS/i)).toBeVisible();
  });

  it("retains a bootstrapped owner through failed child discovery, then releases it", async () => {
    const terminalA = deferred<api.RunStatus>();
    const clearedOwner = deferred<api.ActiveRun>();
    const runA: api.ActiveRun = {
      run_id: "pan-run",
      technique_id: "REP-001",
      vendor: "paloalto",
      status: "running",
      event_count: 12,
      total: 49,
    };
    const panTechnique: api.Technique = {
      ...TECHNIQUE,
      native_log_type: "TRAFFIC",
      native_subtype: "end",
      native_signature_id: "end",
      native_action: "allow",
      native_metadata_semantics: "Primary PAN-OS CEF name and signature ID",
    };
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.getActiveRun)
      // App's bootstrap is authoritative. RunPanel's duplicate probe then
      // fails once before the terminal ownership confirmation succeeds.
      .mockResolvedValueOnce(runA)
      .mockRejectedValueOnce(new Error("temporary active-owner failure"))
      .mockReturnValue(clearedOwner.promise);
    vi.mocked(api.getRunStatus).mockReturnValue(terminalA.promise);
    vi.mocked(api.getCatalog).mockImplementation(async (vendor?: string) => ({
      vendor_profile: vendor ?? "fortigate",
      timezone: "UTC+04:00",
      techniques: [vendor === "paloalto" ? panTechnique : TECHNIQUE],
    }));
    vi.mocked(api.getSample).mockImplementation(async (_id, vendor) => sample(vendor));

    render(<App />);

    const panOs = await screen.findByRole("radio", { name: "PAN-OS" });
    expect(panOs).toBeChecked();
    expect(panOs).toBeDisabled();
    await waitFor(() => expect(api.getRunStatus).toHaveBeenCalledWith("pan-run"));
    expect(api.getCatalog).not.toHaveBeenCalledWith("fortigate");
    expect(await screen.findByText("Primary PAN-OS CEF name and signature ID")).toBeVisible();

    await act(async () => {
      terminalA.resolve({
        run_id: "pan-run",
        vendor: "paloalto",
        status: "done",
        total: 49,
        event_count: 49,
        dropped: 0,
        manifest: null,
        manifest_path: null,
      });
      await Promise.resolve();
    });

    expect(
      await screen.findByText(/remains locked while Replicant confirms.*REP-001 reached done/i),
    ).toBeVisible();
    expect(panOs).toBeDisabled();

    await act(async () => {
      clearedOwner.resolve({
        run_id: null,
        technique_id: null,
        vendor: null,
        status: null,
      });
      await Promise.resolve();
    });

    await waitFor(() => expect(panOs).toBeEnabled());
    expect(panOs).toBeChecked();
    expect(api.getCatalog).not.toHaveBeenCalledWith("fortigate");
    expect(screen.queryByText("Primary FortiGate category and subtype")).toBeNull();
    expect(screen.getByText("Primary PAN-OS CEF name and signature ID")).toBeVisible();
  });

  it("realigns the locked catalog when active ownership transfers across vendors", async () => {
    let terminalAResolve: ((status: api.RunStatus) => void) | undefined;
    let ownerBResolve: ((active: api.ActiveRun) => void) | undefined;
    const terminalA = new Promise<api.RunStatus>((resolve) => {
      terminalAResolve = resolve;
    });
    const ownerB = new Promise<api.ActiveRun>((resolve) => {
      ownerBResolve = resolve;
    });
    const pendingB = new Promise<api.RunStatus>(() => undefined);
    const runA: api.ActiveRun = {
      run_id: "run-a",
      technique_id: "REP-001",
      vendor: "fortigate",
      status: "running",
      event_count: 12,
      total: 49,
    };
    const runB: api.ActiveRun = {
      run_id: "run-b",
      technique_id: "REP-001",
      vendor: "paloalto",
      status: "running",
      event_count: 3,
      total: 49,
    };
    const panTechnique: api.Technique = {
      ...TECHNIQUE,
      native_log_type: "TRAFFIC",
      native_subtype: "end",
      native_signature_id: "end",
      native_action: "allow",
      native_metadata_semantics: "Primary PAN-OS CEF name and signature ID",
    };
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.getActiveRun)
      .mockResolvedValueOnce(runA)
      .mockResolvedValueOnce(runA)
      .mockReturnValue(ownerB);
    vi.mocked(api.getRunStatus).mockImplementation((runId) =>
      runId === "run-a" ? terminalA : pendingB,
    );
    vi.mocked(api.getCatalog).mockImplementation(async (vendor?: string) => ({
      vendor_profile: vendor ?? "fortigate",
      timezone: "UTC+04:00",
      techniques: [vendor === "paloalto" ? panTechnique : TECHNIQUE],
    }));
    vi.mocked(api.getSample).mockImplementation(async (_id, vendor) => sample(vendor));

    render(<App />);
    expect(await screen.findByRole("radio", { name: "FortiGate" })).toBeChecked();

    await act(async () => {
      terminalAResolve!({
        run_id: "run-a",
        vendor: "fortigate",
        status: "done",
        total: 49,
        event_count: 49,
        dropped: 0,
        manifest: null,
        manifest_path: null,
      });
      await Promise.resolve();
    });
    expect(
      await screen.findByText(/remains locked while Replicant confirms.*REP-001 reached done/i),
    ).toBeVisible();

    await act(async () => {
      ownerBResolve!(runB);
      await Promise.resolve();
    });

    await waitFor(() => expect(screen.getByRole("radio", { name: "PAN-OS" })).toBeChecked());
    expect(screen.getByRole("radio", { name: "PAN-OS" })).toBeDisabled();
    expect(api.getCatalog).toHaveBeenCalledWith("paloalto");
    expect(await screen.findByText("Primary PAN-OS CEF name and signature ID")).toBeVisible();
    expect(screen.queryByText("Primary FortiGate category and subtype")).toBeNull();
  });

  it("locks the vendor selector while any run is active", async () => {
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.getActiveRun).mockResolvedValue({
      run_id: "abc123",
      technique_id: "REP-004",
      vendor: "fortigate",
      status: "running",
    });

    render(<App />);

    const panOs = await screen.findByRole("radio", { name: "PAN-OS" });
    await waitFor(() => expect(panOs).toBeDisabled());
    expect(screen.getByText(/vendor profile is locked while REP-004 is running/i)).toBeVisible();

    fireEvent.click(panOs);
    expect(api.getCatalog).not.toHaveBeenCalledWith("paloalto");
  });

  it("locks the selected vendor throughout admission and publishes the accepted owner", async () => {
    const startResponse = deferred<Awaited<ReturnType<typeof api.startRun>>>();
    const streamUrls: string[] = [];
    const panTechnique: api.Technique = {
      ...TECHNIQUE,
      native_log_type: "TRAFFIC",
      native_subtype: "end",
      native_signature_id: "end",
      native_action: "allow",
      native_metadata_semantics: "Primary PAN-OS CEF name and signature ID",
    };

    class FakeEventSource {
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      onerror: (() => void) | null = null;
      close = vi.fn();

      constructor(url: string) {
        streamUrls.push(url);
      }
    }

    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(api.getConfig).mockResolvedValue(config({ vendor: "paloalto" }));
    vi.mocked(api.getActiveRun)
      .mockResolvedValueOnce({
        run_id: null,
        technique_id: null,
        vendor: null,
        status: null,
      })
      .mockResolvedValue({
        run_id: null,
        technique_id: null,
        vendor: null,
        status: null,
      });
    vi.mocked(api.getCatalog).mockImplementation(async (vendor?: string) => ({
      vendor_profile: vendor ?? "fortigate",
      timezone: "UTC+04:00",
      techniques: [vendor === "paloalto" ? panTechnique : TECHNIQUE],
    }));
    vi.mocked(api.getSample).mockImplementation(async (_id, vendor) => sample(vendor));
    vi.mocked(api.startRun).mockReturnValue(startResponse.promise);

    render(<App />);

    const panOs = await screen.findByRole("radio", { name: "PAN-OS" });
    const fortiGate = screen.getByRole("radio", { name: "FortiGate" });
    await waitFor(() => expect(api.getActiveRun).toHaveBeenCalledTimes(2));
    expect(panOs).toBeChecked();
    expect(panOs).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: "Run without sending" }));
    await waitFor(() => expect(api.startRun).toHaveBeenCalledTimes(1));

    expect(panOs).toBeDisabled();
    expect(fortiGate).toBeDisabled();
    expect(screen.getByText(/requests admission for REP-001 under PAN-OS/i)).toBeVisible();
    expect(screen.queryByText(/already running/i)).toBeNull();
    expect(screen.queryByRole("button", { name: /stop the running/i })).toBeNull();
    expect(screen.getByRole("button", { name: "Stop run" })).toBeDisabled();
    for (const tabName of ["Documentation", "Process logs", "Terminal"]) {
      expect(screen.getByRole("button", { name: tabName })).toBeDisabled();
      expect(screen.getByRole("button", { name: tabName })).toHaveAttribute(
        "title",
        expect.stringMatching(/pending run admission/i),
      );
    }

    // A pending POST stays owned by this mounted panel. Navigation cannot
    // detach it and leave App with an admission that no response can settle.
    fireEvent.click(screen.getByRole("button", { name: "Documentation" }));
    expect(screen.getByRole("button", { name: "Run without sending" })).toBeDisabled();

    fireEvent.click(fortiGate);
    expect(api.getCatalog).not.toHaveBeenCalledWith("fortigate");

    await act(async () => {
      startResponse.resolve({
        admission_id: "00000000-0000-4000-8000-000000000001",
        run_id: "run-b",
        vendor: "paloalto",
        total: 49,
        pace: "burst",
        speed: 1,
        projected_s: 0.024,
        plan_span_s: 14280,
      });
      await Promise.resolve();
    });

    await waitFor(() => expect(streamUrls).toEqual(["/api/runs/run-b/events"]));
    expect(panOs).toBeChecked();
    expect(panOs).toBeDisabled();
    expect(screen.getByText(/REP-001 is running under PAN-OS/i)).toBeVisible();
    expect(screen.getByRole("button", { name: "Stop run" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Documentation" })).toBeEnabled();
    expect(api.getCatalog).not.toHaveBeenCalledWith("fortigate");
    expect(screen.queryByText("Primary FortiGate category and subtype")).toBeNull();
  });

  it("keeps admission fail-closed when the start response is lost and recovers the owner", async () => {
    const startResponse = deferred<Awaited<ReturnType<typeof api.startRun>>>();
    const recoveredOwner = deferred<api.RunAdmissionState>();
    const noActive: api.ActiveRun = {
      run_id: null,
      technique_id: null,
      vendor: null,
      status: null,
    };
    const panTechnique: api.Technique = {
      ...TECHNIQUE,
      native_log_type: "TRAFFIC",
      native_subtype: "end",
      native_signature_id: "end",
      native_action: "allow",
      native_metadata_semantics: "Primary PAN-OS CEF name and signature ID",
    };
    vi.mocked(api.getConfig).mockResolvedValue(config({ vendor: "paloalto" }));
    vi.mocked(api.getActiveRun)
      .mockResolvedValueOnce(noActive)
      .mockResolvedValueOnce(noActive);
    vi.mocked(api.getCatalog).mockResolvedValue({
      vendor_profile: "paloalto",
      timezone: "UTC+04:00",
      techniques: [panTechnique],
    });
    vi.mocked(api.getSample).mockResolvedValue(sample("paloalto"));
    vi.mocked(api.getRunAdmission).mockReturnValue(recoveredOwner.promise);
    vi.mocked(api.startRun).mockReturnValue(startResponse.promise);

    render(<App />);

    const panOs = await screen.findByRole("radio", { name: "PAN-OS" });
    await waitFor(() => expect(api.getActiveRun).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByRole("button", { name: "Run without sending" }));
    await waitFor(() => expect(api.startRun).toHaveBeenCalledTimes(1));
    expect(panOs).toBeDisabled();
    expect(screen.getByText(/requests admission for REP-001 under PAN-OS/i)).toBeVisible();

    await act(async () => {
      startResponse.reject(new Error("response connection reset"));
      await Promise.resolve();
    });

    await waitFor(() => expect(api.getRunAdmission).toHaveBeenCalledTimes(1));
    expect(screen.getByText(/start response unavailable.*checking its admission record/i)).toBeVisible();
    expect(screen.getByText(/requests admission for REP-001 under PAN-OS/i)).toBeVisible();
    expect(panOs).toBeChecked();
    expect(panOs).toBeDisabled();
    expect(screen.getByRole("button", { name: "Documentation" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: /stop the running/i })).toBeNull();

    await act(async () => {
      recoveredOwner.resolve({
        admission_id: "00000000-0000-4000-8000-000000000001",
        run_id: "accepted-despite-lost-response",
        technique_id: "REP-001",
        vendor: "paloalto",
        status: "running",
        event_count: 1,
        total: 49,
      });
      await Promise.resolve();
    });

    expect(screen.getByText(/REP-001 is already running/i)).toBeVisible();
    expect(screen.getByRole("button", { name: /stop the running REP-001/i })).toBeEnabled();
    expect(screen.getByText(/REP-001 is running under PAN-OS/i)).toBeVisible();
    expect(panOs).toBeChecked();
    expect(panOs).toBeDisabled();
    expect(screen.getByRole("button", { name: "Documentation" })).toBeEnabled();
    expect(api.getCatalog).not.toHaveBeenCalledWith("fortigate");
  });

  it("keeps admission locked while the exact record is admitting, then adopts it", async () => {
    const startResponse = deferred<Awaited<ReturnType<typeof api.startRun>>>();
    const noActive: api.ActiveRun = {
      run_id: null,
      technique_id: null,
      vendor: null,
      status: null,
    };
    const admitting: api.RunAdmissionState = {
      admission_id: "00000000-0000-4000-8000-000000000001",
      run_id: "registered-before-preview",
      technique_id: "REP-001",
      vendor: "fortigate",
      status: "admitting",
      event_count: 0,
      total: 0,
    };
    const recovered = { ...admitting, status: "running", total: 49 };
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.getActiveRun)
      .mockResolvedValueOnce(noActive)
      .mockResolvedValueOnce(noActive);
    vi.mocked(api.getRunAdmission)
      .mockResolvedValueOnce(admitting)
      .mockResolvedValueOnce(recovered);
    vi.mocked(api.startRun).mockReturnValue(startResponse.promise);

    render(<App />);

    const fortiGate = await screen.findByRole("radio", { name: "FortiGate" });
    await waitFor(() => expect(api.getActiveRun).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByRole("button", { name: "Run without sending" }));
    await waitFor(() => expect(api.startRun).toHaveBeenCalledTimes(1));
    vi.useFakeTimers();

    await act(async () => {
      startResponse.reject(new Error("response lost after submit"));
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(api.getRunAdmission).toHaveBeenCalledTimes(1);
    expect(fortiGate).toBeChecked();
    expect(fortiGate).toBeDisabled();
    expect(screen.getByText(/requests admission for REP-001 under FortiGate/i)).toBeVisible();
    expect(screen.queryByRole("button", { name: /stop the running/i })).toBeNull();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });

    expect(api.getRunAdmission).toHaveBeenCalledTimes(2);
    expect(screen.getByText(/REP-001 is already running/i)).toBeVisible();
    expect(screen.getByRole("button", { name: /stop the running REP-001/i })).toBeEnabled();
    expect(screen.getByText(/recovered from its admission record/i)).toBeVisible();
    expect(fortiGate).toBeChecked();
    expect(fortiGate).toBeDisabled();
  });

  it("cancels an unclaimed reservation before releasing uncertain admission", async () => {
    const startResponse = deferred<Awaited<ReturnType<typeof api.startRun>>>();
    const noActive: api.ActiveRun = {
      run_id: null,
      technique_id: null,
      vendor: null,
      status: null,
    };
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.getActiveRun).mockResolvedValue(noActive);
    vi.mocked(api.getRunAdmission)
      .mockResolvedValueOnce({
        admission_id: "00000000-0000-4000-8000-000000000001",
        run_id: "reserved-run",
        technique_id: "REP-001",
        vendor: "fortigate",
        status: "reserved",
        event_count: 0,
        total: 0,
      })
      .mockResolvedValueOnce({
        admission_id: "00000000-0000-4000-8000-000000000001",
        run_id: "reserved-run",
        technique_id: "REP-001",
        vendor: "fortigate",
        status: "stopped",
        event_count: 0,
        total: 0,
      });
    vi.mocked(api.getRunStatus).mockResolvedValue({
      run_id: "reserved-run",
      vendor: "fortigate",
      status: "stopped",
      total: 0,
      event_count: 0,
      dropped: 0,
      manifest: null,
      manifest_path: null,
    });
    vi.mocked(api.startRun).mockReturnValue(startResponse.promise);

    render(<App />);

    const fortiGate = await screen.findByRole("radio", { name: "FortiGate" });
    await waitFor(() => expect(api.getActiveRun).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByRole("button", { name: "Run without sending" }));
    await waitFor(() => expect(api.startRun).toHaveBeenCalledTimes(1));
    vi.useFakeTimers();

    await act(async () => {
      startResponse.reject(new Error("connection reset"));
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(api.stopRun).toHaveBeenCalledWith("reserved-run");
    expect(fortiGate).toBeDisabled();
    expect(screen.getByText(/requests admission for REP-001 under FortiGate/i)).toBeVisible();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });

    expect(api.getRunAdmission).toHaveBeenCalledTimes(2);
    expect(api.getActiveRun).toHaveBeenCalledTimes(3);
    expect(fortiGate).toBeChecked();
    expect(fortiGate).toBeEnabled();
    expect(screen.queryByText(/requests admission/i)).toBeNull();
    expect(screen.getByText("start failed: connection reset")).toBeVisible();
    expect(screen.queryByText(/checking its admission record/i)).toBeNull();
    expect(screen.getByRole("button", { name: "Run without sending" })).toBeEnabled();
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
      admission_id: "00000000-0000-4000-8000-000000000001",
      run_id: "run-1",
      vendor: "fortigate",
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
    expect(
      screen.getByText(/vendor profile is locked while REP-001 is running under FortiGate/i),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Stop run" })).toBeEnabled();

    fireEvent.click(panOs);
    expect(api.getCatalog).not.toHaveBeenCalledWith("paloalto");
    expect(screen.getByRole("button", { name: "Stop run" })).toBeEnabled();
  });
});

describe("workspace drafts and run evidence", () => {
  it("retains draft settings across library, collector, and profile navigation", async () => {
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.getCatalog).mockImplementation(async (vendor = "fortigate") => ({
      vendor_profile: vendor, timezone: "UTC+04:00", techniques: [TECHNIQUE],
    }));
    render(<App />);
    const duration = await screen.findByLabelText("Duration");
    fireEvent.change(duration, { target: { value: "30m" } });
    fireEvent.change(screen.getByLabelText("Seed"), { target: { value: "42" } });
    fireEvent.click(screen.getByRole("radio", { name: "high" }));
    fireEvent.click(screen.getByRole("button", { name: "Techniques" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Filter techniques" }), { target: { value: "T1071" } });
    expect(screen.getByRole("button", { name: /Beaconing T1071/ })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Collector" }));
    expect(screen.getByRole("heading", { name: "Collector connection" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Back to run workspace" }));
    await waitFor(() => expect(screen.getByRole("radio", { name: "PAN-OS" })).toBeEnabled());
    fireEvent.click(screen.getByRole("radio", { name: "PAN-OS" }));
    await waitFor(() => expect(screen.getByRole("radio", { name: "PAN-OS" })).toBeChecked());
    expect(await screen.findByLabelText("Duration")).toHaveValue("30m");
    expect(screen.getByLabelText("Seed")).toHaveValue("42");
    expect(screen.getByRole("radio", { name: "high" })).toBeChecked();
    fireEvent.click(screen.getByRole("button", { name: "Techniques" }));
    expect(screen.getByRole("textbox", { name: "Filter techniques" })).toHaveValue("T1071");
  });

  it("keeps a live stream attached during navigation and preserves its identity after draft changes", async () => {
    let stream!: FakeEventSource;
    class FakeEventSource {
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      onerror: (() => void) | null = null;
      close = vi.fn();
      constructor() { stream = this; }
    }
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(api.getConfig).mockResolvedValue(config());
    vi.mocked(api.getCatalog).mockImplementation(async (vendor = "fortigate") => ({
      vendor_profile: vendor, timezone: "UTC+04:00", techniques: [TECHNIQUE],
    }));
    vi.mocked(api.startRun).mockResolvedValue({
      admission_id: "00000000-0000-4000-8000-000000000001", run_id: "retained-run",
      vendor: "fortigate", output_path: "/server/out/test.log", total: 2, pace: "burst", speed: 1, projected_s: 0.01, plan_span_s: 5,
    });
    render(<App />);
    await screen.findByRole("button", { name: "Run without sending" });
    fireEvent.click(screen.getByRole("switch", { name: "File" }));
    fireEvent.change(screen.getByLabelText("Output file name"), { target: { value: "/requested/test.log" } });
    const start = screen.getByRole("button", { name: "Run and write to file" });
    await waitFor(() => expect(start).toBeEnabled());
    fireEvent.click(start);
    await waitFor(() => expect(screen.getByRole("button", { name: "Stop run" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Techniques" }));
    expect(stream.close).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Run workspace" }));
    expect(screen.getByRole("button", { name: "Stop run" })).toBeEnabled();
    const manifest = {
      technique_id: "REP-001", technique_name: "Beaconing", vendor: "fortigate", ndr_uc: "UC-001",
      intensity: "medium", seed: 1337, target: "/server/out/test.log", transport: "file", event_count: 2,
      planned_event_count: 2, started_at: "2026-09-08T00:00:00Z", ended_at: "2026-09-08T00:00:01Z",
      anchor_epoch: 1752537600, warmup_note: null, status: "done" as const,
    };
    await act(async () => {
      stream.onmessage?.({ data: JSON.stringify({ type: "line", data: "CEF:0|Fortinet|Fortigate|test" }) } as MessageEvent<string>);
      stream.onmessage?.({ data: JSON.stringify({ type: "done", status: "done", count: 2, manifest }) } as MessageEvent<string>);
    });
    await waitFor(() => expect(screen.getByRole("radio", { name: "PAN-OS" })).toBeEnabled());
    fireEvent.click(screen.getByRole("radio", { name: "PAN-OS" }));
    await screen.findByRole("radio", { name: "PAN-OS", checked: true });
    expect(screen.getByRole("region", { name: "Run result" })).toHaveTextContent("REP-001 · FortiGate");
    expect(screen.getByRole("region", { name: "Run result" })).toHaveTextContent("Event stream · fortigate");
    expect(screen.getByTestId("run-destination")).toHaveTextContent("No send");
    expect(screen.getByTestId("run-destination")).toHaveTextContent("/server/out/test.log");
    expect(screen.getByTestId("run-destination")).not.toHaveTextContent("/requested/test.log");
    expect(screen.getByRole("region", { name: "Run result" })).toHaveTextContent("uncapped");
    expect(screen.getByTestId("manifest-events")).toHaveTextContent("2 / 2");
    expect(screen.getByText(/The draft has changed/)).toBeVisible();
    expect(api.startRun).toHaveBeenCalledTimes(1);
  });

  it("removes stale plan numbers while a changed preset is being calculated", async () => {
    vi.mocked(api.getConfig).mockResolvedValue(config());
    const pending = deferred<Awaited<ReturnType<typeof api.getPlanPreview>>>();
    const initial = {
      event_count: 49, plan_span_s: 14280, compressed_span_s: 14280, projected_s: 0.24,
      projected_by_pace: { plan: 14280, burst: 0.24 }, pace: "burst" as const, speed: 1,
    };
    vi.mocked(api.getPlanPreview).mockResolvedValueOnce(initial).mockReturnValue(pending.promise);
    render(<App />);
    expect(await screen.findByText("49")).toBeVisible();
    fireEvent.click(screen.getByRole("radio", { name: "high" }));
    expect(screen.queryByText("49")).not.toBeInTheDocument();
    expect(screen.getAllByText("Calculating…")).toHaveLength(3);
    await waitFor(() => expect(api.getPlanPreview).toHaveBeenLastCalledWith(expect.objectContaining({ intensity: "high" })));
    await act(async () => { pending.resolve({ ...initial, event_count: 91 }); });
    expect(screen.getByText("91")).toBeVisible();
  });
});
