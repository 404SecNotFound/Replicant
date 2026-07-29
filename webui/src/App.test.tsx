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

import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import * as api from "@/lib/api";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, getCatalog: vi.fn(), getConfig: vi.fn(), getSample: vi.fn() };
});

const TECHNIQUE: api.Technique = {
  id: "REP-001",
  name: "Beaconing",
  ndr_rule: "rule",
  ndr_uc: "UC-001",
  log_type: "traffic",
  subtype: "forward",
  attack: ["T1071"],
  tactics: ["Command and Control"],
  intensities: ["low", "medium", "high"],
  implemented: true,
  safety_notes: null,
  signature_id: "00013",
  action: "accept",
  cef_fields_held: ["dst"],
  cef_fields_varied: ["bytes"],
  params: { medium: {} },
  distributions: {},
  benign_baseline: null,
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
  vi.mocked(api.getCatalog).mockResolvedValue({
    vendor_profile: "fortigate",
    timezone: "UTC+04:00",
    techniques: [TECHNIQUE],
  });
  vi.mocked(api.getSample).mockResolvedValue({
    technique_id: "REP-001",
    vendor: "fortigate",
    intensity: "low",
    log_type: "traffic",
    subtype: "forward",
    signature_id: "00013",
    cef_fields_held: ["dst"],
    cef_fields_varied: ["bytes"],
    lines: ["CEF:0|Fortinet|Fortigate|..."],
  });
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
