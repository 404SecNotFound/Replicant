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

// What the form promises for each pacing option.
//
// The option names alone decide nothing for an operator: "burst" and "plan" are
// implementation words. What has to be on screen is the consequence, with the
// real numbers in it, which is why these assert on the sentence rather than on
// the label.

import { describe, expect, it } from "vitest";
import { defaultPace, fmtSpan, paceConsequence, type PlanPreview } from "./pacing";

// REP-001 low, the technique from the lab: 49 events across 238 minutes.
const BEACON: PlanPreview = {
  event_count: 49,
  plan_span_s: 14280,
  compressed_span_s: 14280,
  projected_s: 14280,
  // Both modes priced from one plan: 238 minutes of beacon, or a quarter second
  // of burst carrying the same 238 minutes of timestamps.
  projected_by_pace: { plan: 14280, burst: 0.24 },
  pace: "plan",
  speed: 1,
};

describe("fmtSpan", () => {
  it("reads as a duration rather than a number of seconds", () => {
    expect(fmtSpan(14280)).toBe("3h 58m");
    expect(fmtSpan(238)).toBe("3m 58s");
    expect(fmtSpan(12)).toBe("12s");
  });

  it("keeps sub-second runs legible instead of rounding them to zero", () => {
    // A burst of 49 events is a fraction of a second. "0s" would read as a bug.
    expect(fmtSpan(0.24)).toBe("0.2s");
  });
});

describe("defaultPace", () => {
  it("paces by the plan when events go to a collector", () => {
    expect(defaultPace(true)).toBe("plan");
  });

  it("bursts to a file, which has no wall clock to reproduce", () => {
    expect(defaultPace(false)).toBe("burst");
  });
});

describe("paceConsequence", () => {
  it("says how long a plan-paced run will actually take", () => {
    const text = paceConsequence("plan", 1, BEACON);

    expect(text).toContain("3h 58m");
    expect(text).toMatch(/when the plan says/i);
  });

  it("warns that burst leaves the timestamps spread but delivers them at once", () => {
    const burst: PlanPreview = { ...BEACON, pace: "burst", projected_s: 0.24 };

    const text = paceConsequence("burst", 1, burst);

    // Both halves of the trap: it is over in a moment, and the timestamps still
    // claim four hours, which is what an interval-keyed rule reads.
    expect(text).toContain("0.2s");
    expect(text).toContain("3h 58m");
    expect(text).toMatch(/will not match|nothing to match/i);
  });

  it("states the cost of compression next to the time it saves", () => {
    const fast: PlanPreview = {
      ...BEACON,
      speed: 60,
      compressed_span_s: 238,
      projected_s: 238,
      projected_by_pace: { plan: 238, burst: 0.24 },
    };

    const text = paceConsequence("plan", 60, fast);

    expect(text).toContain("3m 58s");
    // The tradeoff is the point. Compression preserves relative timing and
    // changes absolute intervals, so a rule keyed on real gaps stops matching.
    expect(text).toMatch(/60/);
    expect(text).toMatch(/will not match/i);
  });

  it("says something useful before the preview has arrived", () => {
    const text = paceConsequence("plan", 1, null);

    expect(text.length).toBeGreaterThan(0);
    expect(text).not.toContain("NaN");
    expect(text).not.toContain("undefined");
  });
});
