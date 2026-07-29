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
import { describe, expect, it, vi } from "vitest";
import { CatalogTable } from "./CatalogTable";
import { makeTechnique } from "@/test/factories";

const CATALOG = [
  makeTechnique({ id: "REP-001", name: "Beaconing", ndr_uc: "UC-001" }),
  makeTechnique({
    id: "REP-004",
    name: "DNS tunneling",
    ndr_uc: "UC-003",
    attack: ["T1048.003"],
    log_type: "dns",
    subtype: "dns-query",
    tactics: ["TA0011 Command and Control", "TA0010 Exfiltration"],
  }),
  makeTechnique({
    id: "REP-009",
    name: "VPN brute force",
    ndr_uc: "UC-007",
    attack: ["T1110"],
    log_type: "event",
    subtype: "vpn",
    tactics: ["TA0006 Credential Access"],
  }),
];

function renderRail(selectedId: string | null = "REP-001") {
  const onSelect = vi.fn();
  render(<CatalogTable techniques={CATALOG} selectedId={selectedId} onSelect={onSelect} />);
  return { onSelect };
}

const filterBox = () => screen.getByRole("textbox", { name: /filter/i });
const group = (name: RegExp) => screen.getByRole("button", { name });

describe("CatalogTable grouping", () => {
  it("shows one group per tactic, each with its count", () => {
    renderRail();

    expect(group(/Credential Access/)).toHaveTextContent("1");
    expect(group(/Command and Control/)).toHaveTextContent("2");
  });

  it("lists a two-tactic technique under both of them", () => {
    renderRail();

    expect(screen.getAllByRole("button", { name: /DNS tunneling/ })).toHaveLength(2);
  });

  it("orders the groups by the ATT&CK kill chain", () => {
    renderRail();
    const headings = screen
      .getAllByRole("button")
      .map((b) => b.textContent ?? "")
      .filter((text) => /Credential Access|Command and Control|Exfiltration/.test(text));

    // Credential Access (TA0006) precedes C2 (TA0011), which precedes Exfiltration
    // (TA0010). Numeric order would put Exfiltration before C2.
    expect(headings[0]).toMatch(/Credential Access/);
    expect(headings[1]).toMatch(/Command and Control/);
    expect(headings[2]).toMatch(/Exfiltration/);
  });

  it("collapses a group without losing the others", () => {
    renderRail();
    expect(screen.getByRole("button", { name: /VPN brute force/ })).toBeInTheDocument();

    fireEvent.click(group(/Credential Access/));

    expect(screen.queryByRole("button", { name: /VPN brute force/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Beaconing/ })).toBeInTheDocument();
  });
});

describe("CatalogTable filtering", () => {
  it("narrows on a use case id and drops the groups that empty out", () => {
    renderRail();

    fireEvent.change(filterBox(), { target: { value: "UC-007" } });

    expect(screen.getByRole("button", { name: /VPN brute force/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Beaconing/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Command and Control/ })).not.toBeInTheDocument();
  });

  it("narrows on an ATT&CK technique id", () => {
    renderRail();

    fireEvent.change(filterBox(), { target: { value: "T1048" } });

    expect(screen.getAllByRole("button", { name: /DNS tunneling/ }).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /VPN brute force/ })).not.toBeInTheDocument();
  });

  it("filters by log type", () => {
    renderRail();

    fireEvent.click(screen.getByRole("button", { name: "event:vpn" }));

    expect(screen.getByRole("button", { name: /VPN brute force/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Beaconing/ })).not.toBeInTheDocument();
  });

  it("says so when nothing matches, rather than showing an empty rail", () => {
    renderRail();

    fireEvent.change(filterBox(), { target: { value: "REP-999" } });

    expect(screen.getByText(/no techniques match/i)).toBeInTheDocument();
  });

  it("reports how many of the catalog are showing once a filter is on", () => {
    renderRail();

    fireEvent.change(filterBox(), { target: { value: "UC-007" } });

    expect(screen.getByText(/1 of 3/)).toBeInTheDocument();
  });
});

describe("CatalogTable selection", () => {
  it("reports the technique that was clicked", () => {
    const { onSelect } = renderRail();

    fireEvent.click(screen.getByRole("button", { name: /VPN brute force/ }));

    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ id: "REP-009" }));
  });

  it("marks the selected technique for assistive tech", () => {
    renderRail("REP-009");

    expect(screen.getByRole("button", { name: /VPN brute force/ })).toHaveAttribute(
      "aria-current",
      "true",
    );
  });
});
