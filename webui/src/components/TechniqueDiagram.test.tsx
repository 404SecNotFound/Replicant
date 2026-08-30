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

// The catalog itself, as raw text, so the coverage assertion cannot go stale:
// a REP-025 added to the catalog fails here until someone decides its diagram.
import catalogYaml from "../../../replicant/data/technique-catalog.yaml?raw";
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DIAGRAM_SPECS, TechniqueDiagram } from "./TechniqueDiagram";
import type { Technique } from "@/lib/api";

const catalogIds = [...catalogYaml.matchAll(/^\s*-?\s*id:\s*"?(REP-\d{3})"?\s*$/gm)].map(
  (m) => m[1],
);

function fakeTechnique(id: string): Technique {
  return {
    id,
    name: "Test technique",
    ndr_uc: "UC-000",
    ndr_rule: "NDR-TEST-000",
    log_type: "traffic",
    subtype: "forward",
    signature_id: "00000",
    action: "accept",
    objective: "",
    tactics: [],
    attack: [],
    intensities: [],
    params: {},
    distributions: {},
    cef_fields_varied: [],
    cef_fields_held: [],
    references: [],
    safety_notes: "",
    implemented: true,
    benign_baseline: "",
  } as unknown as Technique;
}

describe("diagram coverage", () => {
  it("reads the real catalog, not a stand-in", () => {
    // If the id regex or the import path breaks, the per-id loop below would
    // quietly assert over an empty list and prove nothing.
    expect(catalogIds.length).toBeGreaterThanOrEqual(24);
  });

  it.each(catalogIds)("%s has an explicit diagram spec", (id) => {
    // No fallback exists any more: REP-012..024 spent months rendering the
    // periodic-beacon glyph because of a `?? "periodic"`. Every catalog entry
    // decides its own diagram, in DIAGRAM_SPECS, on purpose.
    expect(DIAGRAM_SPECS[id]).toBeDefined();
  });

  it("every spec renders a drawing with its caption", () => {
    for (const id of Object.keys(DIAGRAM_SPECS)) {
      const { container, unmount } = render(<TechniqueDiagram technique={fakeTechnique(id)} />);
      const svg = container.querySelector("svg");
      expect(svg, id).not.toBeNull();
      // A mapped technique must never show the unmapped placeholder.
      expect(svg!.textContent, id).not.toContain("NO DIAGRAM DRAWN");
      // The glyph actually drew something beyond the frame chrome: the frame
      // alone has 2 rects (source and detection chips) and 1 guide line.
      const shapes = svg!.querySelectorAll("line, circle, path, rect").length;
      expect(shapes, id).toBeGreaterThan(3);
      unmount();
    }
  });

  it("an unmapped id says so instead of drawing someone else's diagram", () => {
    const { container } = render(<TechniqueDiagram technique={fakeTechnique("REP-999")} />);
    expect(container.textContent).toContain("NO DIAGRAM DRAWN");
  });

  it("reused glyphs carry their own caption where the story differs", () => {
    // REP-019 shares the scan fan but its signal is being slow; rendering it
    // under "one dst · many ports" alone would imply the burst it is not.
    const { container } = render(<TechniqueDiagram technique={fakeTechnique("REP-019")} />);
    expect(container.textContent).toContain("SLOW PROBES, LONG WINDOW");
  });
});
