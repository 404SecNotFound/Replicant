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

import { VENDOR_LABELS, vendorLabel } from "./api";

describe("vendorLabel", () => {
  it("maps every vendor id the backend can send", () => {
    // These three ids are canonical in settings.VENDORS on the Python side and
    // arrive over /api/config. If a fourth vendor profile ships without a label
    // here, the selector silently renders the raw id.
    expect(vendorLabel("fortigate")).toBe("FortiGate");
    expect(vendorLabel("paloalto")).toBe("Palo Alto (PAN-OS)");
    expect(vendorLabel("checkpoint")).toBe("Check Point");
  });

  it("falls back to the raw id rather than rendering blank", () => {
    // The failure this prevents is a silently empty dropdown entry: an unknown
    // id must still be selectable and identifiable, not render as "".
    expect(vendorLabel("newvendor")).toBe("newvendor");
    expect(vendorLabel("")).toBe("");
  });

  it("does not inherit labels from Object.prototype", () => {
    // VENDOR_LABELS is a plain object, so a lookup of "constructor" or
    // "toString" would return a function through the prototype chain and the
    // ?? fallback would never fire. Real input comes from an API response, so
    // this is worth pinning rather than assuming.
    expect(vendorLabel("constructor")).toBe("constructor");
    expect(vendorLabel("toString")).toBe("toString");
  });

  it("keeps VENDOR_LABELS and vendorLabel in agreement", () => {
    for (const [id, label] of Object.entries(VENDOR_LABELS)) {
      expect(vendorLabel(id)).toBe(label);
    }
  });
});
