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

// `?raw` gives the literal bytes of the shipped files, transformed by nothing.
import indexCss from "../index.css?raw";
import indexHtml from "../../index.html?raw";
import { describe, expect, it } from "vitest";
import { hslTripletToHex } from "./theme";

describe("hslTripletToHex", () => {
  // The palette is written as HSL triplets so Tailwind can compose them with an
  // alpha, but the design contract is stated in hex (#101010, #ee6018, ...).
  // Each token in index.css names its intended hex in a trailing comment; this
  // extracts every such pair and asserts the triplet really is that color, so a
  // token cannot silently drift from the Factory palette it claims to encode.
  const pairs = [...indexCss.matchAll(/(--[\w-]+):\s*([\d.]+ [\d.]+% [\d.]+%);\s*\/\*\s*(#[0-9a-f]{6})/g)].map(
    (m) => [m[1], m[2], m[3]] as const,
  );

  it("finds the documented palette tokens in index.css", () => {
    // If the comment convention changes, this fails loudly instead of the
    // per-token assertions below quietly testing nothing.
    expect(pairs.length).toBeGreaterThanOrEqual(10);
  });

  it.each(pairs)("%s (%s) encodes exactly %s", (_name, triplet, hex) => {
    expect(hslTripletToHex(triplet)).toBe(hex);
  });

  it("handles the achromatic and boundary cases", () => {
    expect(hslTripletToHex("0 0% 0%")).toBe("#000000");
    expect(hslTripletToHex("0 0% 100%")).toBe("#ffffff");
    expect(hslTripletToHex("360 100% 50%")).toBe("#ff0000");
    expect(hslTripletToHex("40 33% 98.5%")).toBe("#fcfcfa");
  });

  it("returns null rather than a wrong colour when the value is not a triplet", () => {
    // A caller that gets null can fall back; one that gets "#000000" cannot tell
    // the difference between black and a missing variable.
    expect(hslTripletToHex("")).toBeNull();
    expect(hslTripletToHex("rebeccapurple")).toBeNull();
    expect(hslTripletToHex("#ee6018")).toBeNull();
  });
});

describe("dark-only", () => {
  it("index.html carries no pre-paint theme script any more", () => {
    // The Factory system is dark-only. The old light theme lived partly in an
    // inline script that ran before first paint; if one reappears, either the
    // light theme is coming back (bring back the parity guard with it) or
    // something else has claimed the pre-bundle slot and deserves a look.
    expect(indexHtml).not.toContain("prefers-color-scheme");
    expect(indexHtml).not.toContain("replicant.theme");
  });

  it("the stylesheet defines exactly one theme", () => {
    expect(indexCss).not.toContain(".dark {");
    expect(indexCss).toContain("color-scheme: dark");
  });
});
