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

// The destination has to be legible before the run starts.
//
// The defect these guard: both destination switches default to off, so a run
// rendered every event and delivered none while the event stream, the progress
// and the eps readout stayed identical to a working run. It cost a live
// LogRhythm session, with tcpdump showing no packets and nothing saying why.

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RunPanel } from "./RunPanel";
import { makeTechnique } from "@/test/factories";

const COLLECTOR = { host: "10.20.0.50", port: 514, transport: "udp" as const };

function renderPanel(collector: typeof COLLECTOR | null = COLLECTOR) {
  return render(
    <RunPanel
      technique={makeTechnique()}
      defaultSeed={1337}
      collector={collector}
      vendor="fortigate"
      epsCap={2000}
      anchorEpoch={1752537600}
    />,
  );
}

describe("RunPanel destination", () => {
  it("says it will not send when no destination is selected", () => {
    renderPanel();

    expect(screen.getByRole("button", { name: /Run without sending/ })).toBeVisible();
  });

  it("warns before the run that nothing will be delivered", () => {
    renderPanel();

    const notice = screen.getByRole("status");
    expect(notice).toHaveTextContent(/No destination selected/);
    // The eps readout is what made the silent run look like a working one.
    expect(notice).toHaveTextContent(/measures rendering/);
    expect(notice).toHaveTextContent(/10\.20\.0\.50:514/);
  });

  it("names the collector in the button once sending is on", () => {
    renderPanel();

    fireEvent.click(screen.getByRole("switch", { name: /Collector/ }));

    expect(screen.getByRole("button", { name: /Run and send to 10\.20\.0\.50:514/ })).toBeVisible();
    expect(screen.queryByText(/No destination selected/)).toBeNull();
  });

  it("names the file destination when only the file switch is on", () => {
    renderPanel();

    fireEvent.click(screen.getByRole("switch", { name: /File/ }));

    expect(screen.getByRole("button", { name: /Run and write to file/ })).toBeVisible();
    expect(screen.queryByText(/No destination selected/)).toBeNull();
  });

  it("does not show the destination warning when there is no collector to enable", () => {
    // With no collector the existing "sends fail closed" note already covers it,
    // and a second warning telling the operator to turn on a switch that is
    // disabled would be advice they cannot act on.
    renderPanel(null);

    expect(screen.queryByText(/No destination selected/)).toBeNull();
    expect(screen.getByText(/No collector configured/)).toBeVisible();
  });
});
