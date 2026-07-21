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

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SignalReadout } from "./SignalReadout";

const base = {
  eps: 120,
  cap: 2000,
  samples: [] as number[],
  pct: 0,
  running: false,
  count: 0,
  total: 1000,
  elapsedLabel: "0s",
};

describe("SignalReadout", () => {
  // Regression guard for DEF-002. This component once hardcoded 2000 as the cap
  // while ConnectionCard read the real value from /api/config, so an operator
  // running with a non-default eps_cap saw a waveform scaled against a number
  // that had nothing to do with their run. A literal here would pass a test that
  // only ever renders the default, which is why this asserts a NON-default cap.
  it("renders the cap it is given, not a hardcoded default", () => {
    render(<SignalReadout {...base} cap={50} />);
    expect(screen.getByText(/cap 50/)).toBeInTheDocument();
    expect(screen.queryByText(/cap 2000/)).not.toBeInTheDocument();
  });

  it("scales the waveform against the cap when samples are small", () => {
    // scale = max(cap * 0.25, ...samples, 1). With cap 2000 and a lone sample of
    // 10, the floor of 500 dominates, so the point sits near the baseline rather
    // than filling the height. Asserting the geometry catches a scale inversion,
    // which is invisible to a smoke test that only checks the SVG rendered.
    const { container } = render(<SignalReadout {...base} cap={2000} samples={[10]} />);
    const path = container.querySelector("path");
    expect(path).not.toBeNull();
    const d = path!.getAttribute("d") ?? "";
    // BOTTOM is 66 and the plot height is 52, so 10/500 of the way up from 66
    // is ~64.96. Well below the midpoint of the 14..66 band.
    const firstY = Number(d.replace(/^M[\d.]+ /, "").split(" ")[0]);
    expect(firstY).toBeGreaterThan(60);
    expect(firstY).toBeLessThanOrEqual(66);
  });

  it("lifts the waveform toward the top when a sample reaches the cap", () => {
    const { container } = render(<SignalReadout {...base} cap={100} samples={[100]} />);
    const d = container.querySelector("path")!.getAttribute("d") ?? "";
    const firstY = Number(d.replace(/^M[\d.]+ /, "").split(" ")[0]);
    // At the scale ceiling the point should sit at TOP (14), not the baseline.
    expect(firstY).toBeCloseTo(14, 1);
  });

  it("shows the emitting indicator only while running", () => {
    const { rerender } = render(<SignalReadout {...base} running={false} />);
    expect(screen.queryByText(/emitting/i)).not.toBeInTheDocument();
    rerender(<SignalReadout {...base} running={true} />);
    expect(screen.getByText(/emitting/i)).toBeInTheDocument();
  });
});
