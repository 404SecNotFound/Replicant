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

// The collector badge said "verified" whenever a collector object existed.
//
// It was set from a UDP sendto() succeeding, which only proves a route exists,
// and it showed green against a collector that could not receive anything across
// two live lab sessions. Both were the same transposed address: 10.20.0.125
// typed for a collector at 10.0.20.125.
//
// What these guard is stated honestly: no test catches an operator typo. They
// catch the regression where the disclosure that makes a typo visible stops
// being rendered. The probe is not that disclosure. Printing the source address
// beside the destination is.

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ConnectionCard } from "./ConnectionCard";
import { testConnection, type PathReport } from "@/lib/api";

vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual<typeof import("@/lib/api")>("@/lib/api")),
  testConnection: vi.fn(),
}));

const REPORT: PathReport = {
  host: "10.20.0.125",
  port: 514,
  transport: "udp",
  verdict: "sent_unconfirmed",
  summary: "312 bytes left 10.0.20.127 for 10.20.0.125:514.",
  proves: "The datagram was accepted by this host's network stack.",
  does_not_prove: "That anything received it.",
  source: "10.0.20.127",
  interface: "ens33",
  gateway: "10.0.20.254",
  direct: false,
  claim: null,
  path: "10.0.20.127 -> 10.20.0.125:514",
};

function renderCard() {
  return render(
    <ConnectionCard
      epsCap={2000}
      collector={null}
      onCollectorChange={() => {}}
      vendor="fortigate"
      vendors={["fortigate", "paloalto", "checkpoint"]}
      onVendorChange={() => {}}
    />,
  );
}

async function test_() {
  fireEvent.click(screen.getByRole("button", { name: /send test log/i }));
  return screen.findByTestId("connect-report");
}

describe("ConnectionCard verdict", () => {
  it("never says verified for a UDP send", async () => {
    vi.mocked(testConnection).mockResolvedValue({ ok: true, endpoint: "x", report: REPORT });

    renderCard();
    await test_();

    expect(screen.queryByText(/verified/i)).toBeNull();
    expect(screen.getByText(/sent, unconfirmed/)).toBeVisible();
  });

  it("shows the source beside the destination, which is what makes a typo visible", async () => {
    vi.mocked(testConnection).mockResolvedValue({ ok: true, endpoint: "x", report: REPORT });

    renderCard();
    const panel = await test_();

    // "10.20.0.125:514" alone reads as perfectly ordinary and survived two lab
    // sessions. Beside 10.0.20.127 it does not.
    expect(panel).toHaveTextContent(/10\.0\.20\.127/);
    expect(panel).toHaveTextContent(/10\.20\.0\.125:514/);
  });

  it("names the gateway, because a routed destination is what a typo looks like", async () => {
    vi.mocked(testConnection).mockResolvedValue({ ok: true, endpoint: "x", report: REPORT });

    renderCard();
    const panel = await test_();

    expect(panel).toHaveTextContent(/via ens33/);
    expect(panel).toHaveTextContent(/gateway 10\.0\.20\.254/);
  });

  it("says the route could not be determined rather than staying silent", async () => {
    // route_for parses /proc/net/route and answers for nothing on macOS, so this
    // is the developer's own machine. Silence would let the operator infer a
    // directness that was never established.
    vi.mocked(testConnection).mockResolvedValue({
      ok: true,
      endpoint: "x",
      report: { ...REPORT, interface: null, gateway: null, direct: null },
    });

    renderCard();
    const panel = await test_();

    expect(panel).toHaveTextContent(/route not determined on this platform/);
  });

  it("always states what the test did not prove", async () => {
    vi.mocked(testConnection).mockResolvedValue({ ok: true, endpoint: "x", report: REPORT });

    renderCard();
    const panel = await test_();

    expect(panel).toHaveTextContent(/Does not prove: That anything received it\./);
  });

  it("reports a refusal without preventing the run", async () => {
    // Report, never block. A firewall dropping ICMP on a working collector must
    // not be able to stop a legitimate lab, which would be worse than the defect.
    const onChange = vi.fn();
    vi.mocked(testConnection).mockResolvedValue({
      ok: false,
      endpoint: "x",
      report: { ...REPORT, verdict: "refused", summary: "Nothing is listening on udp/514." },
    });

    render(
      <ConnectionCard
        epsCap={2000}
        collector={null}
        onCollectorChange={onChange}
        vendor="fortigate"
        vendors={["fortigate"]}
        onVendorChange={() => {}}
      />,
    );
    await test_();

    expect(screen.getByText(/refused/)).toBeVisible();
    // Still armed: the operator asked for this collector and gets to use it.
    expect(onChange).toHaveBeenCalled();
  });

  it("stops describing a target the operator has since edited", async () => {
    vi.mocked(testConnection).mockResolvedValue({ ok: true, endpoint: "x", report: REPORT });

    renderCard();
    await test_();

    fireEvent.change(screen.getByLabelText(/host/i), { target: { value: "10.0.20.125" } });

    // The old verdict described an address no longer in the form, which is the
    // same class of lie the verdict exists to remove.
    await waitFor(() => expect(screen.queryByTestId("connect-report")).toBeNull());
    expect(screen.getByText(/not tested/)).toBeVisible();
  });
});
