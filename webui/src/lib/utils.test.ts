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
import { cn } from "./utils";

describe("cn keeps the type scale", () => {
  // Stock tailwind-merge classifies the custom rungs as text-color classes and
  // deletes them when a real color follows in the same call, so an element
  // silently inherits its parent's size while its source says otherwise.
  // Found live: the vendor segmented control rendered 16px against a class
  // list that said text-label. cn() is configured to know the rungs; this
  // pins that configuration, for every rung the config declares.
  it("every fontSize rung in tailwind.config.js survives a color in the same call", async () => {
    const source = (await import("../../tailwind.config.js?raw")).default;
    const rungs = [...source.matchAll(/(\w+):\s*\["[0-9.]+px"/g)].map((m) => m[1]);
    expect(rungs.length).toBeGreaterThanOrEqual(6);

    for (const rung of rungs) {
      expect(cn(`text-${rung}`, "text-signal")).toBe(`text-${rung} text-signal`);
    }
  });

  it("still merges real conflicts", () => {
    expect(cn("text-body", "text-label")).toBe("text-label");
    expect(cn("text-signal", "text-foreground")).toBe("text-foreground");
    expect(cn("p-2", "p-4")).toBe("p-4");
  });
});
