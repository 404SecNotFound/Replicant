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

import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TechniqueDetail } from "./TechniqueDetail";
import { makeTechnique } from "@/test/factories";
import {
  getSample,
  getValidationContract,
  validateTechnique,
  type ValidationContract,
} from "@/lib/api";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    getSample: vi.fn(),
    getValidationContract: vi.fn(),
    validateTechnique: vi.fn(),
  };
});

const contract: ValidationContract = {
  schema_version: "1.0",
  technique_id: "REP-001",
  technique_name: "Beaconing",
  detection_rule: "NDR-C2-001",
  expected_event_families: ["traffic:forward"],
  signal_fields: { held: ["src", "dst"], varied: ["rt"] },
  observation_window: {
    parameters: ["duration_min"],
    fixed_seconds: null,
    description: "Measure the full callback window.",
  },
  positive_control: { required: true, expectation: "Measure callback regularity." },
  negative_control: {
    mode: "standalone",
    present: true,
    reason: "Matched irregular callbacks.",
    separable_by: ["cadence"],
  },
  measurable_axes: [
    {
      id: "cadence",
      description: "Low inter-arrival variation.",
      metric: "cadence_cv",
      field: "rt",
      group_by: ["src", "dst"],
      parameter: "jitter_pct",
    },
  ],
  transferability: "transfers",
  limitations: ["Tier 0 does not prove collector receipt or a detection alert."],
};

beforeEach(() => {
  vi.mocked(getSample).mockResolvedValue({
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
    native_metadata_semantics: "primary",
    cef_fields_held: [],
    cef_fields_varied: [],
    native_cef_fields_held: [],
    native_cef_fields_varied: [],
    native_cef_fields_unavailable: { held: [], varied: [] },
    native_cef_fields_by_logical_family: {},
    lines: [],
  });
  vi.mocked(getValidationContract).mockResolvedValue(contract);
  vi.mocked(validateTechnique).mockResolvedValue({
    technique_id: "REP-001",
    tier: "plan",
    verdict: "pass",
    intensity: "medium",
    seed: 1337,
    run_id: "RUN-1",
    expected_events: 10,
    observed_events: 10,
    dimensions: {
      plan: "pass",
      delivery: "not_run",
      detection: "not_run",
      negative_control: "pass",
    },
    proves: "Tier 0 proves plan structure.",
    does_not_prove: "Tier 0 does not prove collector receipt or an alert.",
    limitations: [],
    evidence_url: "/api/evidence/RUN-1",
  });
});

describe("Technique validation", () => {
  it("shows the contract and renders NOT RUN differently from PASS", async () => {
    render(<TechniqueDetail technique={makeTechnique()} vendor="fortigate" />);
    expect(await screen.findByText("Measure callback regularity.")).toBeVisible();
    const notRun = screen.getByTestId("validation-dimension-delivery");
    expect(notRun).toHaveTextContent("NOT RUN");
    expect(notRun.className).toContain("border-dashed");

    fireEvent.click(screen.getByRole("button", { name: "Run Tier 0 · plan" }));
    expect(await screen.findByText("Download evidence pack")).toHaveAttribute(
      "href",
      "/api/evidence/RUN-1",
    );
    expect(screen.getByTestId("validation-dimension-plan").className).toContain("text-metric");
    expect(screen.getByTestId("validation-dimension-delivery").className).toContain(
      "border-dashed",
    );
  });
});
