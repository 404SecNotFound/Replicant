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

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RunPanel } from "./RunPanel";
import { getPlanPreview } from "@/lib/api";
import { makeTechnique } from "@/test/factories";

// Only the preview is stubbed. It is the one call the form makes before a run,
// and letting it reach a real fetch would make every test in this file depend on
// a server that is not running.
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual<typeof import("@/lib/api")>("@/lib/api")),
  getPlanPreview: vi.fn(),
}));

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

// A configured collector is a statement of intent. The CLI has always read it
// that way: `replicant run REP-001 --host ...` sends, and `--no-send` is the
// opt-out. The form read it the other way, so an operator who connected a
// collector, saw it verify, picked a technique and pressed the button got a run
// that rendered every event and delivered none. PR #31 made that visible with a
// labelled button and a warning; it left the default that causes it, so the
// visible answer was still the wrong one. These pin the two surfaces together.
describe("RunPanel destination", () => {
  it("sends to a connected collector by default, as the CLI does", () => {
    renderPanel();

    expect(screen.getByRole("button", { name: /Run and send to 10\.20\.0\.50:514/ })).toBeVisible();
    expect(screen.queryByText(/No destination selected/)).toBeNull();
  });

  it("keeps the collector switch on when one is connected", () => {
    renderPanel();

    expect(screen.getByRole("switch", { name: /Collector/ })).toBeChecked();
  });

  it("says it will not send once the operator turns the collector off", () => {
    renderPanel();

    fireEvent.click(screen.getByRole("switch", { name: /Collector/ }));

    expect(screen.getByRole("button", { name: /Run without sending/ })).toBeVisible();
  });

  it("warns before the run that nothing will be delivered", () => {
    renderPanel();

    fireEvent.click(screen.getByRole("switch", { name: /Collector/ }));

    const notice = screen.getByRole("status");
    expect(notice).toHaveTextContent(/No destination selected/);
    // The eps readout is what made the silent run look like a working one.
    expect(notice).toHaveTextContent(/measures rendering/);
    expect(notice).toHaveTextContent(/10\.20\.0\.50:514/);
  });

  it("names the file destination when only the file switch is on", () => {
    renderPanel();

    fireEvent.click(screen.getByRole("switch", { name: /Collector/ }));
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

// The pacing control.
//
// The defect these guard: a plan carries a per-event time and the emit loop
// ignored it, so REP-001 reached a live collector as 49 events in 3 seconds
// carrying 238 minutes of timestamps. Nothing keyed on the interval between
// events could fire on that. The mode is now a choice, and a choice an operator
// cannot price is not one, so each option states its own consequence with this
// run's real numbers rather than leaving "burst" and "plan" to speak for
// themselves.

describe("RunPanel pacing", () => {
  beforeEach(() => {
    vi.mocked(getPlanPreview).mockResolvedValue({
      event_count: 49,
      plan_span_s: 14280,
      compressed_span_s: 14280,
      projected_s: 14280,
      projected_by_pace: { plan: 14280, burst: 0.24 },
      pace: "plan",
      speed: 1,
    });
  });

  it("defaults a live send to the plan's own timeline", async () => {
    // A connected collector already sends, so this is the default state of the
    // form rather than something the test has to switch on.
    renderPanel();

    expect(await screen.findByRole("radio", { name: /plan time/i })).toBeChecked();
  });

  it("says how long the run will take before it starts", async () => {
    renderPanel();

    // 14280 seconds is 3h 58m. A count of events does not tell an operator that.
    // It appears twice by design, on the option and in the sentence under it, so
    // this names the one it is asserting rather than matching both.
    await waitFor(() =>
      expect(screen.getByTestId("pace-consequence")).toHaveTextContent(/3h 58m/),
    );
  });

  it("prices both options at once so they can be compared", async () => {
    renderPanel();

    // The same plan is four hours one way and a fifth of a second the other.
    // Showing only the selected one would hide the choice being made.
    await waitFor(() => {
      expect(screen.getByRole("radio", { name: /plan time/i })).toHaveAccessibleName(/3h 58m/);
      expect(screen.getByRole("radio", { name: /burst/i })).toHaveAccessibleName(/0\.2s/);
    });
  });

  it("defaults a file run to burst, which has no wall clock to reproduce", async () => {
    renderPanel();
    // File-only: the collector has to come off first, now that it starts on.
    fireEvent.click(screen.getByRole("switch", { name: /Collector/ }));
    fireEvent.click(screen.getByRole("switch", { name: /File/ }));

    expect(await screen.findByRole("radio", { name: /burst/i })).toBeChecked();
  });

  it("warns that a burst leaves the timestamps spread out", async () => {
    vi.mocked(getPlanPreview).mockResolvedValue({
      event_count: 49,
      plan_span_s: 14280,
      compressed_span_s: 14280,
      projected_s: 0.24,
      projected_by_pace: { plan: 14280, burst: 0.24 },
      pace: "burst",
      speed: 1,
    });
    renderPanel();

    fireEvent.click(screen.getByRole("radio", { name: /burst/i }));

    await waitFor(() =>
      expect(screen.getByTestId("pace-consequence")).toHaveTextContent(/3h 58m/),
    );
    expect(screen.getByTestId("pace-consequence")).toHaveTextContent(/nothing to match/i);
  });

  it("hides the speed control when it could not do anything", () => {
    // Burst ignores the plan's timeline, so there is nothing to compress. A
    // control whose output cannot change is decoration.
    renderPanel();
    // File-only: the collector has to come off first, now that it starts on.
    fireEvent.click(screen.getByRole("switch", { name: /Collector/ }));
    fireEvent.click(screen.getByRole("switch", { name: /File/ }));

    expect(screen.queryByLabelText(/speed/i)).toBeNull();
  });

  it("states what compression costs beside the time it saves", async () => {
    vi.mocked(getPlanPreview).mockResolvedValue({
      event_count: 49,
      plan_span_s: 14280,
      compressed_span_s: 238,
      projected_s: 238,
      projected_by_pace: { plan: 238, burst: 0.24 },
      pace: "plan",
      speed: 60,
    });
    renderPanel();

    fireEvent.change(await screen.findByLabelText(/speed/i), { target: { value: "60" } });

    await waitFor(() =>
      expect(screen.getByTestId("pace-consequence")).toHaveTextContent(/will not match/i),
    );
  });
});
