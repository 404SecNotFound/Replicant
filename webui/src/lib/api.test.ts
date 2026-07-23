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

import { afterEach, describe, expect, it, vi } from "vitest";

import { VENDOR_LABELS, getRunStatus, startRun, stopRun, vendorLabel } from "./api";

function mockFetch(status: number, body: unknown) {
  return vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    statusText: `status ${status}`,
    json: async () => body,
  })) as unknown as typeof fetch;
}

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

describe("api client", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("returns parsed JSON and attaches the session token header", async () => {
    const f = mockFetch(200, {
      run_id: "r1",
      status: "running",
      total: 5,
      event_count: 2,
      dropped: 0,
      manifest: null,
      manifest_path: null,
    });
    vi.stubGlobal("fetch", f);
    const status = await getRunStatus("r1");
    expect(status.status).toBe("running");
    const [url, init] = (f as unknown as { mock: { calls: [string, RequestInit][] } }).mock
      .calls[0];
    expect(url).toBe("/api/runs/r1");
    expect((init.headers as Record<string, string>)["X-Replicant-Token"]).toBeDefined();
  });

  it("throws with the server's detail on an error response", async () => {
    // The 409 the backend returns when a run is already active must reach the user
    // as its message, not a generic failure.
    vi.stubGlobal("fetch", mockFetch(409, { detail: "a run is already in progress: r9" }));
    await expect(
      startRun({ technique_id: "REP-001", intensity: "low", no_send: true }),
    ).rejects.toThrow(/in progress/);
  });

  it("falls back to a status-coded message when the error body has no detail", async () => {
    vi.stubGlobal("fetch", mockFetch(500, {}));
    await expect(stopRun("r1")).rejects.toThrow(/request failed: 500/);
  });
});
