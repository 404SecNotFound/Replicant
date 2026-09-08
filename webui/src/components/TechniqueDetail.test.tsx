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

// The detail panel has to say what a technique is FOR.
//
// It opened with "Emits synthetic <log type> telemetry that exercises <rule>",
// a sentence that is true of every catalog entry. It reads as specific and
// carries no information that distinguishes one entry from another, which is
// the only question this screen exists to answer.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { TechniqueDetail } from "./TechniqueDetail";
import { makeTechnique } from "@/test/factories";

describe("TechniqueDetail objective", () => {
  it("states the objective", () => {
    render(
      <TechniqueDetail
        technique={makeTechnique({
          objective: "Prove a sweep rule fires on one port probed across many hosts.",
        })}
        vendor="fortigate"
      />,
    );

    expect(screen.getByTestId("technique-objective")).toHaveTextContent(
      /Prove a sweep rule fires on one port probed across many hosts\./,
    );
  });

  it("puts the objective before the mechanical description", () => {
    // Ordering is the point: the operator should read what it is for before
    // what it emits, not have to scan past a template to reach the meaning.
    const { container } = render(
      <TechniqueDetail technique={makeTechnique()} vendor="fortigate" />,
    );
    const text = container.textContent ?? "";

    expect(text.indexOf("Prove")).toBeGreaterThan(-1);
    expect(text.indexOf("Prove")).toBeLessThan(text.indexOf("Emits synthetic"));
  });

  it("renders nothing rather than an empty slot when there is no objective", () => {
    render(
      <TechniqueDetail technique={makeTechnique({ objective: "" })} vendor="fortigate" />,
    );

    expect(screen.queryByTestId("technique-objective")).toBeNull();
  });
});

describe("TechniqueDetail transferability (roadmap item 5)", () => {
  it("warns when a technique is parser-only, with its reason", () => {
    render(
      <TechniqueDetail
        technique={makeTechnique({
          transferability: "parser-only",
          transferability_note: "the production rule keys on real GeoIP enrichment",
        })}
        vendor="fortigate"
      />,
    );
    expect(screen.getByTestId("technique-transferability")).toHaveTextContent(/Parser-only/);
    expect(screen.getByTestId("technique-transferability")).toHaveTextContent(
      /real GeoIP enrichment/,
    );
  });

  it("shows a disclosed limit on a technique that otherwise transfers", () => {
    render(
      <TechniqueDetail
        technique={makeTechnique({
          transferability: "transfers",
          transferability_note: "the integer-second eventtime ceiling hides sub-second lag",
        })}
        vendor="fortigate"
      />,
    );
    expect(screen.getByTestId("technique-transferability")).toHaveTextContent(
      /Transfers, with a limit/,
    );
  });

  it("renders nothing when a technique transfers cleanly", () => {
    render(
      <TechniqueDetail
        technique={makeTechnique({ transferability: "transfers", transferability_note: null })}
        vendor="fortigate"
      />,
    );
    expect(screen.queryByTestId("technique-transferability")).toBeNull();
  });
});

describe("TechniqueDetail vendor metadata", () => {
  it("labels the vendor-native identifier as the primary match", () => {
    render(<TechniqueDetail technique={makeTechnique()} vendor="fortigate" />);

    expect(screen.getByText("Primary native match")).toBeVisible();
  });

  it("distinguishes the logical event family from the vendor-native match", () => {
    render(
      <TechniqueDetail
        technique={makeTechnique({
          logical_log_type: "dns",
          logical_subtype: "dns-query",
          logical_families: ["dns:dns-query"],
          native_log_type: "TRAFFIC",
          native_subtype: "end",
          native_signature_id: "end",
          native_metadata_semantics: "Primary PAN-OS CEF name and signature ID",
        })}
        vendor="paloalto"
      />,
    );

    expect(screen.getAllByText("dns:dns-query").length).toBeGreaterThan(0);
    expect(screen.getAllByText("TRAFFIC:end").length).toBeGreaterThan(0);
    expect(screen.getByText("Primary PAN-OS CEF name and signature ID")).toBeVisible();
  });

  it("discloses every logical family in a mixed plan", () => {
    render(
      <TechniqueDetail
        technique={makeTechnique({
          id: "REP-018",
          logical_log_type: "event",
          logical_subtype: "vpn",
          logical_families: ["event:vpn", "event:system", "traffic:forward"],
          native_cef_fields_by_logical_family: {
            "event:vpn": {
              held: [],
              varied: ["duser", "src", "rt"],
              unavailable: { held: [], varied: ["dst"] },
            },
            "event:system": {
              held: [],
              varied: ["duser", "src", "rt"],
              unavailable: { held: [], varied: ["dst"] },
            },
            "traffic:forward": {
              held: [],
              varied: ["src", "dst", "rt"],
              unavailable: { held: [], varied: ["duser"] },
            },
          },
        })}
        vendor="fortigate"
      />,
    );

    expect(screen.getAllByText("event:vpn + event:system + traffic:forward").length).toBe(2);
    expect(screen.getByTestId("technique-family-field-coverage")).toHaveTextContent(
      /event:vpn.*unavailable dst.*traffic:forward.*unavailable duser/i,
    );
  });

  it("names catalog signals that the selected profile cannot emit", () => {
    render(
      <TechniqueDetail
        technique={makeTechnique({
          native_cef_fields_varied: ["PanOSDNSQuery"],
          native_cef_fields_unavailable: { held: [], varied: ["FTNTFGTxid"] },
        })}
        vendor="paloalto"
      />,
    );

    expect(screen.getByTestId("technique-unavailable-fields")).toHaveTextContent(
      /Not emitted by Palo Alto.*signal FTNTFGTxid/i,
    );
  });
});
