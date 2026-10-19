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

import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Technique } from "@/lib/api";
import { CoverageBoard } from "./CoverageBoard";

function technique(id: string, name: string, tactics: string[], extra: Partial<Technique> = {}): Technique {
  return {
    id, name, tactics, ndr_rule: `NDR-${id}`, ndr_uc: `UC-${id}`, objective: `Objective of ${id}.`,
    search_aliases: [], logical_log_type: "traffic", logical_subtype: "forward", logical_families: ["traffic:forward"],
    log_type: "traffic", subtype: "forward", signature_id: "00013", action: "accept",
    native_log_type: "traffic", native_subtype: "forward", native_signature_id: "00013", native_action: "accept",
    native_metadata_scope: "primary", native_metadata_semantics: "", attack: ["T1071"], intensities: ["low", "medium", "high"],
    implemented: true, safety_notes: null, cef_fields_held: ["src"], cef_fields_varied: ["rt"],
    native_cef_fields_held: ["src", "dst"], native_cef_fields_varied: ["rt"],
    native_cef_fields_unavailable: { held: [], varied: [] }, native_cef_fields_by_logical_family: {},
    params: {}, distributions: {}, benign_baseline: `Baseline of ${id}.`, transferability: "transfers",
    transferability_note: null, references: [], ...extra,
  };
}

const CATALOG = [
  technique("REP-001", "Periodic C2 callback", ["TA0011 Command and Control"]),
  technique("REP-002", "Vertical port scan", ["TA0007 Discovery"]),
  technique("REP-005", "Outbound exfil volume", ["TA0010 Exfiltration", "TA0011 Command and Control"]),
  technique("REP-004", "DNS tunneling", ["TA0011 Command and Control"], {
    native_log_type: "dns", native_subtype: "dns-query", transferability: "parser-only", transferability_note: "Needs a DNS parser.",
  }),
];

describe("CoverageBoard", () => {
  it("draws one lane per tactic in kill-chain order, with multi-tactic entries in each", () => {
    render(<CoverageBoard techniques={CATALOG} selectedId="REP-001" onSelect={vi.fn()} />);
    const lanes = screen.getAllByRole("region").map((r) => r.getAttribute("aria-label"));
    expect(lanes).toEqual(["Discovery", "Command and Control", "Exfiltration"]);
    expect(within(screen.getByRole("region", { name: "Exfiltration" })).getByText("Outbound exfil volume")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Command and Control" })).getByText("Outbound exfil volume")).toBeInTheDocument();
    expect(screen.getByText("4 techniques across 3 tactics")).toBeInTheDocument();
  });

  it("names the tactics no entry reaches instead of drawing them empty", () => {
    render(<CoverageBoard techniques={CATALOG} selectedId={null} onSelect={vi.fn()} />);
    expect(screen.getByText(/No firewall signal: Reconnaissance, Resource Development, Initial Access/)).toBeInTheDocument();
  });

  it("focuses a cell without leaving the board, and loads it only from the dossier", () => {
    const onSelect = vi.fn();
    render(<CoverageBoard techniques={CATALOG} selectedId="REP-001" onSelect={onSelect} />);
    const dossier = screen.getByRole("complementary", { name: "Technique dossier" });
    expect(within(dossier).getByText("Objective of REP-001.")).toBeInTheDocument();

    fireEvent.click(within(screen.getByRole("region", { name: "Discovery" })).getByRole("button", { name: /REP-002/ }));
    expect(onSelect).not.toHaveBeenCalled();
    expect(within(dossier).getByText("Objective of REP-002.")).toBeInTheDocument();
    expect(within(dossier).getByText("Baseline of REP-002.")).toBeInTheDocument();

    fireEvent.click(within(dossier).getByRole("button", { name: "Load into run workspace" }));
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ id: "REP-002" }));
  });

  it("discloses a parser-only entry in the dossier", () => {
    render(<CoverageBoard techniques={CATALOG} selectedId="REP-004" onSelect={vi.fn()} />);
    expect(screen.getByText(/Parser-only: a pass exercises field mapping, not the shipped rule. Needs a DNS parser./)).toBeInTheDocument();
  });

  it("filters by text and by log type, and says when nothing matches", () => {
    render(<CoverageBoard techniques={CATALOG} selectedId={null} onSelect={vi.fn()} />);
    fireEvent.change(screen.getByRole("textbox", { name: "Filter techniques" }), { target: { value: "port scan" } });
    expect(screen.getByRole("region", { name: "Discovery" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Command and Control" })).toBeNull();

    fireEvent.change(screen.getByRole("textbox", { name: "Filter techniques" }), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "dns:dns-query" }));
    expect(within(screen.getByRole("region", { name: "Command and Control" })).getAllByRole("button")).toHaveLength(1);

    fireEvent.change(screen.getByRole("textbox", { name: "Filter techniques" }), { target: { value: "nothing like this" } });
    expect(screen.getByText("No techniques match that filter.")).toBeInTheDocument();
  });
});
