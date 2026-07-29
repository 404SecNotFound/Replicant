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
import { TechniqueDetail } from "./TechniqueDetail";
import { makeTechnique } from "@/test/factories";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    getSample: vi.fn(async () => ({
      lines: ["CEF:0|Fortinet|Fortigate|v7.4.3|00013|traffic:forward accept|3|" + "x".repeat(400)],
    })),
  };
});

beforeEach(() => {
  vi.clearAllMocks();
});

// The sample line arrives from an async fetch. Settling it before asserting keeps
// the state update inside act() rather than after the test has returned.
async function renderSettled() {
  const utils = render(<TechniqueDetail technique={makeTechnique()} vendor="fortigate" />);
  await waitFor(() => expect(utils.container.querySelector(".whitespace-pre")).not.toBeNull());
  return utils;
}

describe("TechniqueDetail", () => {
  it("renders the technique identity and its ATT&CK tags", async () => {
    await renderSettled();

    expect(screen.getByText("Beaconing")).toBeInTheDocument();
    expect(screen.getByText(/REP-001/)).toBeInTheDocument();
    expect(screen.getByText("T1071.001")).toBeInTheDocument();
  });

  // Regression guard for a horizontal-overflow bug found by measuring the real
  // page, not by any test: at 375px the document scrolled sideways to 3452px.
  //
  // Cause: a CSS grid item defaults to `min-width: auto`, so it will not shrink
  // below its content's intrinsic width. One 3376px CEF sample line inside an
  // `overflow-x-auto` box therefore stretched the whole column track and took
  // the page with it, instead of scrolling inside its own box.
  //
  // jsdom has no layout engine, so this cannot assert the width; it asserts the
  // one class that prevents it. The behavioural check is a browser width
  // measurement, recorded in tasks/todo.md.
  it("keeps min-w-0 on the cards, or a wide CEF line drags the page sideways", async () => {
    const { container } = await renderSettled();

    const grid = container.querySelector(".grid.gap-4");
    expect(grid, "the detail card grid moved; re-point this guard").not.toBeNull();

    const items = [...(grid?.children ?? [])];
    expect(items.length).toBeGreaterThan(0);

    for (const item of items) {
      expect(
        item.className,
        `grid item "${item.textContent?.slice(0, 40)}" lost min-w-0, so it can no longer ` +
          "shrink below its widest child and the page will scroll horizontally",
      ).toContain("min-w-0");
    }
  });

  it("puts the CEF sample in its own horizontal scroller", async () => {
    // The other half of the same bug: min-w-0 lets the box shrink, and this is
    // what makes the overflowing content scroll rather than clip.
    const { container } = await renderSettled();

    expect(container.querySelector(".overflow-x-auto")).not.toBeNull();
  });
});
