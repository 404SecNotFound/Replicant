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
import { anchorNotice, defaultAnchor } from "./anchor";

// 1752537600 == 2025-07-15T00:00:00Z, the deterministic default anchor.
const FIXED = 1752537600;

describe("defaultAnchor", () => {
  it("uses now for a live send", () => {
    // A live send with the fixed anchor is the trap this control exists to close.
    expect(defaultAnchor(true)).toBe("now");
  });

  it("uses the fixed anchor for file output", () => {
    // Byte-identical artifacts from the same seed are the point of --to-file, and
    // that only holds with a fixed anchor.
    expect(defaultAnchor(false)).toBe("fixed");
  });
});

describe("anchorNotice", () => {
  it("warns when a live send is about to go out with a fixed anchor", () => {
    const notice = anchorNotice("fixed", true, FIXED);

    expect(notice).toMatch(/2025-07-15/);
    expect(notice).toMatch(/event time/i);
  });

  it("says nothing when the anchor is now", () => {
    expect(anchorNotice("now", true, FIXED)).toBeNull();
  });

  it("says nothing when the run is not sending", () => {
    // Writing a fixed-anchor file is the correct use of the default. Warning here
    // would teach the operator to dismiss the warning that matters.
    expect(anchorNotice("fixed", false, FIXED)).toBeNull();
  });

  it("names the actual configured anchor rather than a hardcoded date", () => {
    expect(anchorNotice("fixed", true, 1784073600)).toMatch(/2026-07-15/);
  });
});
