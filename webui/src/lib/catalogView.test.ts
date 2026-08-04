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

import { describe, expect, it } from "vitest";
import { filterTechniques, groupByTactic, logTypeOf, LOG_TYPES } from "./catalogView";
import type { Technique } from "./api";

function technique(overrides: Partial<Technique> = {}): Technique {
  return {
    id: "REP-001",
    name: "Beaconing",
    ndr_rule: "rule",
    ndr_uc: "UC-001",
    objective: "Prove a detection can catch a beacon by its interval.",
    log_type: "traffic",
    subtype: "forward",
    attack: ["T1071.001"],
    tactics: ["TA0011 Command and Control"],
    intensities: ["low", "medium", "high"],
    implemented: true,
    safety_notes: null,
    signature_id: "00013",
    action: "accept",
    cef_fields_held: [],
    cef_fields_varied: [],
    params: {},
    distributions: {},
    benign_baseline: null,
    references: [],
    ...overrides,
  };
}

describe("logTypeOf", () => {
  it("joins the pair the way the catalog and the vendor profiles key on it", () => {
    expect(logTypeOf(technique({ log_type: "dns", subtype: "dns-response" }))).toBe(
      "dns:dns-response",
    );
  });

  it("lists exactly the render paths the catalog uses", () => {
    expect(LOG_TYPES).toEqual([
      "traffic:forward",
      "dns:dns-query",
      "dns:dns-response",
      "event:vpn",
      "utm:ips",
    ]);
  });
});

describe("groupByTactic", () => {
  it("lists a multi-tactic technique under each of its tactics", () => {
    const exfil = technique({
      id: "REP-004",
      tactics: ["TA0011 Command and Control", "TA0010 Exfiltration"],
    });

    const groups = groupByTactic([exfil]);

    expect(groups.map((g) => g.tactic)).toEqual([
      "TA0011 Command and Control",
      "TA0010 Exfiltration",
    ]);
    expect(groups.every((g) => g.techniques.length === 1)).toBe(true);
  });

  it("orders groups by the ATT&CK kill chain, not by number or name", () => {
    // TA0043 Reconnaissance is the FIRST tactic and has the HIGHEST number, so
    // sorting numerically or alphabetically both put it in the wrong place.
    const groups = groupByTactic([
      technique({ id: "a", tactics: ["TA0010 Exfiltration"] }),
      technique({ id: "b", tactics: ["TA0043 Reconnaissance"] }),
      technique({ id: "c", tactics: ["TA0001 Initial Access"] }),
    ]);

    expect(groups.map((g) => g.tactic)).toEqual([
      "TA0043 Reconnaissance",
      "TA0001 Initial Access",
      "TA0010 Exfiltration",
    ]);
  });

  it("keeps catalog order inside a group", () => {
    const groups = groupByTactic([
      technique({ id: "REP-002" }),
      technique({ id: "REP-001" }),
    ]);

    expect(groups[0].techniques.map((t) => t.id)).toEqual(["REP-002", "REP-001"]);
  });

  it("puts an unmapped technique in its own trailing group rather than dropping it", () => {
    const groups = groupByTactic([
      technique({ id: "REP-001" }),
      technique({ id: "REP-099", tactics: [] }),
    ]);

    expect(groups[groups.length - 1].tactic).toBe("Unmapped");
    expect(groups[groups.length - 1].techniques.map((t) => t.id)).toEqual(["REP-099"]);
  });

  it("emits no empty groups", () => {
    expect(groupByTactic([]).length).toBe(0);
  });
});

describe("filterTechniques", () => {
  const catalog = [
    technique({ id: "REP-001", name: "Beaconing", ndr_uc: "UC-001", attack: ["T1071.001"] }),
    technique({
      id: "REP-004",
      name: "DNS tunneling",
      ndr_uc: "UC-003",
      attack: ["T1048.003"],
      log_type: "dns",
      subtype: "dns-query",
    }),
    technique({
      id: "REP-009",
      name: "VPN brute force",
      ndr_uc: "UC-007",
      attack: ["T1110"],
      log_type: "event",
      subtype: "vpn",
    }),
  ];

  it("returns everything when nothing is set", () => {
    expect(filterTechniques(catalog, {}).length).toBe(3);
  });

  it("matches on the technique id", () => {
    expect(filterTechniques(catalog, { query: "REP-004" }).map((t) => t.id)).toEqual(["REP-004"]);
  });

  it("matches on the name, case-insensitively", () => {
    expect(filterTechniques(catalog, { query: "dns tunn" }).map((t) => t.id)).toEqual(["REP-004"]);
  });

  it("matches on the use case id", () => {
    expect(filterTechniques(catalog, { query: "uc-007" }).map((t) => t.id)).toEqual(["REP-009"]);
  });

  it("matches on the ATT&CK technique id", () => {
    // One box for all four, because an engineer arriving from a detection backlog
    // has whichever identifier their ticket happened to use.
    expect(filterTechniques(catalog, { query: "T1048" }).map((t) => t.id)).toEqual(["REP-004"]);
  });

  it("filters by log type", () => {
    expect(filterTechniques(catalog, { logTypes: ["event:vpn"] }).map((t) => t.id)).toEqual([
      "REP-009",
    ]);
  });

  it("treats several log types as a union", () => {
    expect(
      filterTechniques(catalog, { logTypes: ["event:vpn", "dns:dns-query"] }).map((t) => t.id),
    ).toEqual(["REP-004", "REP-009"]);
  });

  it("applies query and log type together", () => {
    expect(filterTechniques(catalog, { query: "REP", logTypes: ["dns:dns-query"] }).length).toBe(1);
  });

  it("collapses to no groups when the query matches nothing", () => {
    expect(groupByTactic(filterTechniques(catalog, { query: "nothing here" })).length).toBe(0);
  });

  it("ignores surrounding whitespace in the query", () => {
    expect(filterTechniques(catalog, { query: "  REP-001  " }).map((t) => t.id)).toEqual([
      "REP-001",
    ]);
  });
});

// The type scale.
//
// Before it there were eleven hardcoded sizes across 84 call sites and no scale
// in the design doc at all. Measured on the rendered page, 58 of 104 text
// elements sat below 12px and only 3 reached the 16px browser default. The
// smallest thing on screen was an 8.5px rule id inside the signal-path diagram.
//
// This asserts the scale exists and stays ordered. It cannot catch a component
// picking the wrong rung, which is a judgement call, but it does catch the scale
// being quietly widened back out into eleven ad hoc values.
describe("type scale", () => {
  it("is ordered, and nothing reads below 11px", async () => {
    // Imported as raw text, not as a module. The config is plain JS with no
    // type declaration, so a normal import fails `tsc` under noImplicitAny, and
    // the frontend build, the installer job and the wheel job all run that
    // build. `?raw` is typed as string by vite/client, so this stays type-clean.
    const source = (await import("../../tailwind.config.js?raw")).default;
    const px: Record<string, number> = {};
    for (const [, name, value] of source.matchAll(
      /(\w+):\s*\["([0-9.]+)px"/g,
    )) {
      px[name] = parseFloat(value);
    }

    expect(px.micro).toBeGreaterThanOrEqual(11);
    expect(px.label).toBeGreaterThan(px.micro);
    expect(px.body).toBeGreaterThan(px.label);
    expect(px.lede).toBeGreaterThan(px.body);
    expect(px.title).toBeGreaterThan(px.lede);
    // Prose has to clear the size the old UI used for everything.
    expect(px.body).toBeGreaterThanOrEqual(14);
  });
});
