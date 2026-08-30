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
  capApplies: true,
  samples: [] as number[],
  pct: 0,
  running: false,
  count: 0,
  total: 1000,
  elapsedLabel: "0s",
  windowSeconds: 11,
};

describe("SignalReadout cap label", () => {
  // The eps cap is only enforced when there is an emitter to throttle
  // (orchestrator.py, the send loop). A dry run or a file-only run is not
  // throttled at all, so the readout was printing "cap 2000" beside a measured
  // rate an order of magnitude above it. The number was right and the label was
  // a lie, which is worse than showing nothing: it invites the reader to
  // conclude the cap is broken.
  it("shows the cap when the run is sending to a collector", () => {
    render(<SignalReadout {...base} cap={50} capApplies />);

    expect(screen.getByText(/cap 50/)).toBeInTheDocument();
    expect(screen.queryByText(/uncapped/i)).not.toBeInTheDocument();
  });

  it("says uncapped, not 'cap N', when nothing is being sent", () => {
    render(<SignalReadout {...base} cap={2000} capApplies={false} />);

    expect(screen.getByText(/uncapped/i)).toBeInTheDocument();
    expect(screen.queryByText(/cap 2000/)).not.toBeInTheDocument();
  });

  it("still reports the sample window when uncapped", () => {
    render(<SignalReadout {...base} capApplies={false} windowSeconds={11} />);

    expect(screen.getByText(/window 11s/)).toBeInTheDocument();
  });

  it("explains why it is uncapped rather than leaving the reader guessing", () => {
    const { container } = render(<SignalReadout {...base} capApplies={false} />);
    const label = container.querySelector("[title]");

    expect(label?.getAttribute("title") ?? "").toMatch(/collector|sending/i);
  });
});

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
    // scale = max(...samples, cap * 0.25, 1) while the cap applies. With cap
    // 2000 and a lone sample of 10, the floor of 500 dominates, so the point
    // sits near the baseline rather than filling the height. Asserting the
    // geometry catches a scale inversion, which is invisible to a smoke test
    // that only checks the SVG rendered.
    const { container } = render(<SignalReadout {...base} cap={2000} samples={[10]} />);
    const path = container.querySelector("path");
    expect(path).not.toBeNull();
    const d = path!.getAttribute("d") ?? "";
    // BOTTOM is 32 and the plot band is 28, so 10/500 of the way up from 32 is
    // ~31.4. Well below the midpoint of the 4..32 band.
    const firstY = Number(d.replace(/^M[\d.]+ /, "").split(" ")[0]);
    expect(firstY).toBeGreaterThan(29);
    expect(firstY).toBeLessThanOrEqual(32);
  });

  it("lifts the waveform toward the top when a sample reaches the cap", () => {
    const { container } = render(<SignalReadout {...base} cap={100} samples={[100]} />);
    const d = container.querySelector("path")!.getAttribute("d") ?? "";
    const firstY = Number(d.replace(/^M[\d.]+ /, "").split(" ")[0]);
    // At the scale ceiling the point should sit at TOP (4), not the baseline.
    expect(firstY).toBeCloseTo(4, 1);
  });

  it("labels the plot's own scale so autoscaled readings stay self-describing", () => {
    const { container } = render(
      <SignalReadout {...base} capApplies={false} samples={[40, 80]} />,
    );
    // Uncapped, the scale follows the largest sample; the top hairline label
    // must state that value or the filled band misreads as a large rate.
    const texts = [...container.querySelectorAll("text")].map((t) => t.textContent);
    expect(texts).toContain("80");
  });

  it("labels the window it was given, not a hardcoded one", () => {
    // The label read "window 30s" while the plot held 48 samples at 220ms, which
    // is 10.6s. It is now derived from the real sampling parameters.
    render(<SignalReadout {...base} windowSeconds={11} />);
    expect(screen.getByText(/window 11s/)).toBeInTheDocument();
    expect(screen.queryByText(/window 30s/)).not.toBeInTheDocument();
  });

  it("shows the emitting indicator only while running", () => {
    const { rerender } = render(<SignalReadout {...base} running={false} />);
    expect(screen.queryByText(/emitting/i)).not.toBeInTheDocument();
    rerender(<SignalReadout {...base} running={true} />);
    expect(screen.getByText(/emitting/i)).toBeInTheDocument();
  });
});
