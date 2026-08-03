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
// a sentence that is true of all 24 catalog entries. It reads as specific and
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
