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

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RunPanel } from "./RunPanel";
import {
  ApiError,
  getActiveRun,
  getPlanPreview,
  getRunAdmission,
  getRunStatus,
  reserveRun,
  startRun,
  stopRun,
  type ActiveRun,
  type Manifest,
  type RunAdmissionState,
  type RunStatus,
} from "@/lib/api";
import type { RunAdmission } from "./RunPanel";
import { makeTechnique } from "@/test/factories";

// Only the preview is stubbed. It is the one call the form makes before a run,
// and letting it reach a real fetch would make every test in this file depend on
// a server that is not running.
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual<typeof import("@/lib/api")>("@/lib/api")),
  getPlanPreview: vi.fn(),
  getActiveRun: vi.fn(),
  getRunAdmission: vi.fn(),
  getRunStatus: vi.fn(),
  reserveRun: vi.fn(),
  startRun: vi.fn(),
  stopRun: vi.fn(),
}));

const COLLECTOR = { host: "10.20.0.50", port: 514, transport: "udp" as const };
const NO_ACTIVE_RUN: ActiveRun = {
  run_id: null,
  technique_id: null,
  vendor: null,
  status: null,
};

function reservation(
  admissionId = "00000000-0000-4000-8000-000000000001",
  status = "reserved",
): RunAdmissionState {
  return {
    admission_id: admissionId,
    run_id: "reserved-run",
    technique_id: "REP-001",
    vendor: "fortigate",
    status,
    event_count: 0,
    total: status === "running" ? 49 : 0,
  };
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

function runStatus(
  runId: string,
  status: string,
  eventCount: number,
  total = 900,
  vendor = "fortigate",
): RunStatus {
  return {
    run_id: runId,
    vendor,
    status,
    total,
    event_count: eventCount,
    dropped: 0,
    manifest: null,
    manifest_path: null,
  };
}

function renderPanel(
  collector: typeof COLLECTOR | null = COLLECTOR,
  epsCap = 2000,
  onActiveRunChange?: (activeRun: ActiveRun | null) => void,
  onRunAdmissionChange?: (admission: RunAdmission | null) => void,
  onActiveRunDiscoveryChange?: (pending: boolean) => void,
) {
  return render(
    <RunPanel
      technique={makeTechnique()}
      defaultSeed={1337}
      collector={collector}
      vendor="fortigate"
      epsCap={epsCap}
      anchorEpoch={1752537600}
      onActiveRunChange={onActiveRunChange}
      onRunAdmissionChange={onRunAdmissionChange}
      onActiveRunDiscoveryChange={onActiveRunDiscoveryChange}
    />,
  );
}

describe("REP-009 signature shape", () => {
  it("shows the selector only for the IPS spike technique", async () => {
    vi.mocked(getActiveRun).mockResolvedValue(NO_ACTIVE_RUN);
    vi.mocked(getPlanPreview).mockResolvedValue({
      event_count: 40,
      plan_span_s: 3600,
      compressed_span_s: 3600,
      projected_s: 3600,
      projected_by_pace: { plan: 3600, burst: 0.02 },
      pace: "plan",
      speed: 1,
    });
    const props = {
      defaultSeed: 1337,
      collector: COLLECTOR,
      vendor: "fortigate",
      epsCap: 2000,
      anchorEpoch: 1752537600,
    };
    const view = render(
      <RunPanel technique={makeTechnique({ id: "REP-009" })} {...props} />,
    );

    expect(await screen.findByRole("combobox", { name: "IPS signature mode" })).toBeVisible();

    view.rerender(<RunPanel technique={makeTechnique({ id: "REP-001" })} {...props} />);
    expect(screen.queryByRole("combobox", { name: "IPS signature mode" })).toBeNull();
  });
});

beforeEach(() => {
  vi.mocked(reserveRun).mockImplementation(async (request) =>
    reservation(request.admission_id),
  );
  vi.mocked(getRunAdmission).mockResolvedValue(reservation(undefined, "running"));
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe("RunPanel partial manifest", () => {
  it("shows the last durable audit record when an emitted run fails", async () => {
    let stream: {
      onmessage: ((event: MessageEvent<string>) => void) | null;
      onerror: (() => void) | null;
      close: ReturnType<typeof vi.fn>;
    } | null = null;

    class FakeEventSource {
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      onerror: (() => void) | null = null;
      close = vi.fn();

      constructor(_url: string) {
        stream = this;
      }
    }

    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(getActiveRun).mockResolvedValue({
      run_id: null,
      technique_id: null,
      vendor: null,
      status: null,
    });
    vi.mocked(getPlanPreview).mockResolvedValue({
      event_count: 49,
      plan_span_s: 14280,
      compressed_span_s: 14280,
      projected_s: 14280,
      projected_by_pace: { plan: 14280, burst: 0.24 },
      pace: "plan",
      speed: 1,
    });
    vi.mocked(startRun).mockResolvedValue({
      admission_id: "00000000-0000-4000-8000-000000000001",
      run_id: "run-1",
      vendor: "fortigate",
      total: 49,
      pace: "plan",
      speed: 1,
      projected_s: 14280,
      plan_span_s: 14280,
    });

    renderPanel();
    const runButton = screen.getByRole("button", { name: /^Run and send/ });
    await waitFor(() => expect(runButton).toBeEnabled());
    fireEvent.click(runButton);
    await waitFor(() => expect(stream).not.toBeNull());

    const partial = {
      technique_id: "REP-001",
      technique_name: "Beaconing",
      ndr_uc: "NDR-001",
      intensity: "low",
      seed: 1337,
      target: "10.20.0.50:514",
      transport: "udp",
      event_count: 2,
      planned_event_count: 49,
      started_at: "2026-09-06T10:00:00+04:00",
      ended_at: "2026-09-06T10:00:01+04:00",
      updated_at: "2026-09-06T10:00:01+04:00",
      anchor_epoch: 1752537600,
      warmup_note: null,
      status: "error",
      partial: true,
      error: "ConnectionError: collector failed",
    };
    act(() => {
      stream!.onmessage?.({
        data: JSON.stringify({
          type: "error",
          message: "collector failed",
          count: 2,
          manifest: partial,
        }),
      } as MessageEvent<string>);
    });

    expect(screen.getByText(/Run failed.*partial manifest written/i)).toBeVisible();
    expect(screen.getByTestId("manifest-events")).toHaveTextContent("2 / 49");
    expect(screen.getByText("collector failed")).toBeVisible();
  });
});

describe("RunPanel rate ceiling", () => {
  it("refuses a per-run rate above the configured collector ceiling", async () => {
    renderPanel(COLLECTOR, 10);

    const input = screen.getByLabelText("Rate");
    expect(input).toHaveAttribute("max", "10");
    fireEvent.change(input, { target: { value: "11" } });

    expect(screen.getByRole("alert")).toHaveTextContent(
      /11 events\/s exceeds the configured cap of 10 events\/s/i,
    );
    expect(screen.getByRole("button", { name: /^Run and send/ })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: /^Run and send/ }));
    expect(startRun).not.toHaveBeenCalled();
  });
});

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

// The single-run lock, and why the form could not see it.
//
// Only one run may be active, because each carries its own rate limiter and two
// against one collector would multiply the eps cap (safety rule 4). That is
// correct. What was wrong is that `running` is per-panel state: selecting a
// different technique remounted the panel, the flag reset, the button
// re-enabled, and pressing it produced a 409 naming a hex run id the operator
// could not resolve, see, or stop.
//
// It became acute when a configured collector started defaulting to plan pace,
// because a REP-001 run is then just under four hours rather than seconds. The
// reported symptom was "I set up the collector, press start, and nothing
// happens", across several techniques.
describe("RunPanel single-run lock", () => {
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
    vi.mocked(getActiveRun).mockReset().mockResolvedValue(NO_ACTIVE_RUN);
    vi.mocked(stopRun).mockReset().mockResolvedValue({ ok: true });
    vi.mocked(getRunStatus).mockReset().mockResolvedValue(runStatus("abc123", "running", 12));
  });

  it("names the technique holding the lock instead of showing an idle form", async () => {
    vi.mocked(getActiveRun).mockResolvedValue({
      run_id: "abc123",
      technique_id: "REP-004",
      vendor: "fortigate",
      status: "running",
      event_count: 12,
      total: 900,
    });

    renderPanel();

    // The operator is looking at REP-001 while REP-004 holds the lock. Naming it
    // is the whole point: "a run is already in progress: 9f3c..." was not
    // something anyone could act on.
    const notice = await screen.findByRole("status");
    expect(notice).toHaveTextContent(/REP-004 is already running/);
    expect(notice).toHaveTextContent(/12 of 900 events/);
  });

  it("offers to stop the run that is holding the lock", async () => {
    vi.mocked(getActiveRun).mockResolvedValue({
      run_id: "abc123",
      technique_id: "REP-004",
      vendor: "fortigate",
      status: "running",
    });

    renderPanel();

    fireEvent.click(await screen.findByRole("button", { name: /stop the running/i }));

    expect(stopRun).toHaveBeenCalledWith("abc123");
  });

  it.each([
    ["reserved", /holds an unclaimed run admission awaiting start/i],
    ["admitting", /holds run admission while the server prepares it/i],
  ])("describes the %s admission state without calling it running", async (status, message) => {
    vi.mocked(getActiveRun).mockResolvedValue({
      admission_id: "00000000-0000-4000-8000-000000000001",
      run_id: "reserved-run",
      technique_id: "REP-004",
      vendor: "fortigate",
      status,
      event_count: 0,
      total: 0,
    });
    vi.mocked(getRunStatus).mockImplementation(() => new Promise(() => undefined));

    renderPanel();

    expect(await screen.findByRole("status")).toHaveTextContent(message);
    expect(screen.getByRole("button", { name: /cancel admission for REP-004/i })).toBeEnabled();
    expect(screen.queryByText(/REP-004 is already running/i)).toBeNull();
  });

  it("watches a restored run through natural completion before releasing the vendor", async () => {
    const onActiveRunChange = vi.fn();
    const terminal = deferred<RunStatus>();
    const activeProbe = deferred<ActiveRun>();
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce({
        run_id: "abc123",
        technique_id: "REP-004",
        vendor: "fortigate",
        status: "running",
        event_count: 12,
        total: 900,
      })
      .mockReturnValue(activeProbe.promise);
    vi.mocked(getRunStatus).mockReturnValue(terminal.promise);

    renderPanel(COLLECTOR, 2000, onActiveRunChange);

    await waitFor(() => expect(getRunStatus).toHaveBeenCalledWith("abc123"));
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "abc123", vendor: "fortigate", status: "running" }),
    );

    const completedManifest: Manifest = {
      technique_id: "REP-004",
      technique_name: "Exfiltration",
      ndr_uc: "NDR-004",
      intensity: "medium",
      seed: 1337,
      target: "10.20.0.50:514",
      transport: "udp",
      event_count: 900,
      planned_event_count: 900,
      started_at: "2026-09-06T10:00:00+04:00",
      ended_at: "2026-09-06T10:15:00+04:00",
      updated_at: "2026-09-06T10:15:00+04:00",
      anchor_epoch: 1752537600,
      warmup_note: null,
      status: "done",
      partial: false,
      error: null,
    };
    await act(async () => {
      terminal.resolve({ ...runStatus("abc123", "done", 900), manifest: completedManifest });
      await Promise.resolve();
    });

    const checking = await screen.findByRole("button", { name: /checking REP-004/i });
    expect(checking).toBeDisabled();
    expect(screen.getByText(/reached done.*confirming active run ownership/i)).toBeVisible();
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "abc123", status: "done", event_count: 900 }),
    );

    await act(async () => {
      activeProbe.resolve(NO_ACTIVE_RUN);
      await Promise.resolve();
    });

    await waitFor(() => expect(onActiveRunChange).toHaveBeenLastCalledWith(null));
    expect(screen.queryByRole("button", { name: /checking REP-004/i })).toBeNull();
    expect(screen.getByText(/Run complete.*manifest written/i)).toBeVisible();
    expect(screen.getByTestId("manifest-events")).toHaveTextContent("900 / 900");
    expect(screen.getByText("Events emitted").parentElement).toHaveTextContent("900");
  });

  it("retains a restored lock through transient status and active-probe failures", async () => {
    const onActiveRunChange = vi.fn();
    const firstStatus = deferred<RunStatus>();
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce({
        run_id: "abc123",
        technique_id: "REP-004",
        vendor: "fortigate",
        status: "running",
        event_count: 12,
        total: 900,
      })
      .mockRejectedValueOnce(new Error("temporary active-run failure"))
      .mockResolvedValue(NO_ACTIVE_RUN);
    vi.mocked(getRunStatus)
      .mockReturnValueOnce(firstStatus.promise)
      .mockResolvedValueOnce(runStatus("abc123", "running", 24))
      .mockResolvedValueOnce(runStatus("abc123", "done", 900));

    renderPanel(COLLECTOR, 2000, onActiveRunChange);

    await waitFor(() => expect(getRunStatus).toHaveBeenCalledTimes(1));
    vi.useFakeTimers();
    await act(async () => {
      firstStatus.reject(new Error("temporary status failure"));
      await Promise.resolve();
    });

    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "abc123", status: "running" }),
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(getRunStatus).toHaveBeenCalledTimes(2);
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "abc123", status: "running", event_count: 24 }),
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(getRunStatus).toHaveBeenCalledTimes(3);
    expect(getActiveRun).toHaveBeenCalledTimes(2);
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "abc123", status: "done", event_count: 900 }),
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(getActiveRun).toHaveBeenCalledTimes(3);
    expect(onActiveRunChange).toHaveBeenLastCalledWith(null);
  });

  it("reconciles an evicted restored handle without releasing its lock", async () => {
    const onActiveRunChange = vi.fn();
    const transientOwnerProbe = deferred<ActiveRun>();
    const successorStatus = deferred<RunStatus>();
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce({
        run_id: "run-a",
        technique_id: "REP-004",
        vendor: "fortigate",
        status: "running",
        event_count: 12,
        total: 900,
      })
      .mockReturnValueOnce(transientOwnerProbe.promise)
      .mockResolvedValue({
        run_id: "run-b",
        technique_id: "REP-007",
        vendor: "paloalto",
        status: "running",
        event_count: 3,
        total: 50,
      });
    vi.mocked(getRunStatus).mockImplementation((runId) =>
      runId === "run-a"
        ? Promise.reject(new ApiError("run not found", 404, "run not found"))
        : successorStatus.promise,
    );

    renderPanel(COLLECTOR, 2000, onActiveRunChange);

    await waitFor(() => expect(getRunStatus).toHaveBeenCalledWith("run-a"));
    await waitFor(() => expect(getActiveRun).toHaveBeenCalledTimes(2));
    vi.useFakeTimers();
    await act(async () => {
      transientOwnerProbe.reject(new Error("temporary active-owner failure"));
      await Promise.resolve();
    });

    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "run-a", status: "running" }),
    );
    expect(onActiveRunChange.mock.calls.map(([active]) => active?.run_id ?? null)).not.toContain(
      null,
    );
    expect(screen.getByRole("button", { name: /stop the running REP-004/i })).toBeEnabled();
    expect(vi.mocked(getRunStatus).mock.calls.filter(([runId]) => runId === "run-a")).toHaveLength(
      1,
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });

    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "run-b", technique_id: "REP-007" }),
    );
    expect(onActiveRunChange.mock.calls.map(([active]) => active?.run_id ?? null)).not.toContain(
      null,
    );
    expect(screen.getByRole("button", { name: /stop the running REP-007/i })).toBeEnabled();
    expect(vi.mocked(getRunStatus).mock.calls.filter(([runId]) => runId === "run-a")).toHaveLength(
      1,
    );
    expect(getRunStatus).toHaveBeenCalledWith("run-b");
  });

  it("keeps discovery fail-closed through probe errors and adopts the recovered owner", async () => {
    const onActiveRunChange = vi.fn();
    const onActiveRunDiscoveryChange = vi.fn();
    vi.useFakeTimers();
    vi.mocked(getActiveRun)
      .mockRejectedValueOnce(new Error("first discovery failure"))
      .mockRejectedValueOnce(new Error("second discovery failure"))
      .mockResolvedValue({
        run_id: "recovered-run",
        technique_id: "REP-007",
        vendor: "paloalto",
        status: "running",
      });
    vi.mocked(getRunStatus).mockResolvedValue(
      runStatus("recovered-run", "running", 12, 900, "paloalto"),
    );

    renderPanel(
      COLLECTOR,
      2000,
      onActiveRunChange,
      undefined,
      onActiveRunDiscoveryChange,
    );
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    const runButton = screen.getByRole("button", { name: /^Run and send/ });
    expect(runButton).toBeDisabled();
    expect(screen.getByTestId("active-owner-discovery")).toBeVisible();
    expect(onActiveRunDiscoveryChange).toHaveBeenLastCalledWith(true);
    expect(startRun).not.toHaveBeenCalled();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(getActiveRun).toHaveBeenCalledTimes(2);
    expect(runButton).toBeDisabled();
    expect(onActiveRunChange).not.toHaveBeenCalled();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });

    expect(getActiveRun).toHaveBeenCalledTimes(3);
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "recovered-run", vendor: "paloalto" }),
    );
    expect(onActiveRunDiscoveryChange).toHaveBeenLastCalledWith(false);
    expect(screen.queryByTestId("active-owner-discovery")).toBeNull();
    expect(screen.getByRole("button", { name: /stop the running REP-007/i })).toBeEnabled();
    expect(runButton).toBeDisabled();
  });

  it("preserves a bootstrapped owner across StrictMode cleanup and releases it", async () => {
    const onActiveRunChange = vi.fn();
    const terminal = deferred<RunStatus>();
    const clearedOwner = deferred<ActiveRun>();
    const runA: ActiveRun = {
      run_id: "strict-run",
      technique_id: "REP-004",
      vendor: "paloalto",
      status: "running",
      event_count: 12,
      total: 900,
    };
    vi.mocked(getActiveRun)
      // StrictMode invokes the mount probe once per effect setup. Both are
      // transient failures; the terminal confirmation is the next probe.
      .mockRejectedValueOnce(new Error("first StrictMode discovery failed"))
      .mockRejectedValueOnce(new Error("second StrictMode discovery failed"))
      .mockReturnValue(clearedOwner.promise);
    vi.mocked(getRunStatus).mockReturnValue(terminal.promise);

    render(
      <StrictMode>
        <RunPanel
          technique={makeTechnique()}
          defaultSeed={1337}
          collector={COLLECTOR}
          vendor="paloalto"
          epsCap={2000}
          anchorEpoch={1752537600}
          initialActiveRun={runA}
          onActiveRunChange={onActiveRunChange}
        />
      </StrictMode>,
    );

    await waitFor(() => expect(getActiveRun).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(getRunStatus).toHaveBeenCalledTimes(2));
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "strict-run", vendor: "paloalto", status: "running" }),
    );

    await act(async () => {
      terminal.resolve(runStatus("strict-run", "done", 900, 900, "paloalto"));
      await Promise.resolve();
    });

    expect(await screen.findByRole("button", { name: /checking REP-004/i })).toBeDisabled();
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "strict-run", status: "done", event_count: 900 }),
    );

    await act(async () => {
      clearedOwner.resolve(NO_ACTIVE_RUN);
      await Promise.resolve();
    });

    await waitFor(() => expect(onActiveRunChange).toHaveBeenLastCalledWith(null));
    expect(screen.getByRole("button", { name: /^Run and send/ })).toBeEnabled();
  });

  it("transfers the lock directly from terminal run A to concurrent run B", async () => {
    const onActiveRunChange = vi.fn();
    const terminalA = deferred<RunStatus>();
    const statusB = deferred<RunStatus>();
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce({
        run_id: "run-a",
        technique_id: "REP-004",
        vendor: "fortigate",
        status: "running",
      })
      .mockResolvedValueOnce({
        run_id: "run-b",
        technique_id: "REP-007",
        vendor: "paloalto",
        status: "running",
        event_count: 3,
        total: 50,
      });
    vi.mocked(getRunStatus).mockImplementation((runId) =>
      runId === "run-a" ? terminalA.promise : statusB.promise,
    );

    renderPanel(COLLECTOR, 2000, onActiveRunChange);

    await waitFor(() => expect(getRunStatus).toHaveBeenCalledWith("run-a"));
    await waitFor(() =>
      expect(onActiveRunChange).toHaveBeenLastCalledWith(
        expect.objectContaining({ run_id: "run-a" }),
      ),
    );
    onActiveRunChange.mockClear();

    await act(async () => {
      terminalA.resolve(runStatus("run-a", "done", 900));
      await Promise.resolve();
    });

    await waitFor(() =>
      expect(onActiveRunChange).toHaveBeenLastCalledWith(
        expect.objectContaining({
          run_id: "run-b",
          technique_id: "REP-007",
          vendor: "paloalto",
        }),
      ),
    );
    expect(onActiveRunChange.mock.calls.map(([active]) => active?.run_id ?? null)).not.toContain(
      null,
    );
    await waitFor(() => expect(getRunStatus).toHaveBeenCalledWith("run-b"));
    expect(screen.getByRole("button", { name: /stop the running REP-007/i })).toBeEnabled();
  });

  it("ignores an older refresh response after terminal A transfers to B", async () => {
    const onActiveRunChange = vi.fn();
    const terminalA = deferred<RunStatus>();
    const staleRefresh = deferred<ActiveRun>();
    const statusB = deferred<RunStatus>();
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce({
        run_id: "run-a",
        technique_id: "REP-004",
        vendor: "fortigate",
        status: "running",
      })
      .mockReturnValueOnce(staleRefresh.promise)
      .mockResolvedValueOnce({
        run_id: "run-b",
        technique_id: "REP-007",
        vendor: "paloalto",
        status: "running",
      });
    vi.mocked(getRunStatus).mockImplementation((runId) =>
      runId === "run-a" ? terminalA.promise : statusB.promise,
    );

    const view = renderPanel(COLLECTOR, 2000, onActiveRunChange);
    await waitFor(() => expect(getRunStatus).toHaveBeenCalledWith("run-a"));

    view.rerender(
      <RunPanel
        technique={makeTechnique({ id: "REP-002", name: "Changed selection" })}
        defaultSeed={1337}
        collector={COLLECTOR}
        vendor="fortigate"
        epsCap={2000}
        anchorEpoch={1752537600}
        onActiveRunChange={onActiveRunChange}
      />,
    );
    await waitFor(() => expect(getActiveRun).toHaveBeenCalledTimes(2));

    await act(async () => {
      terminalA.resolve(runStatus("run-a", "done", 900));
      await Promise.resolve();
    });
    await waitFor(() =>
      expect(onActiveRunChange).toHaveBeenLastCalledWith(
        expect.objectContaining({ run_id: "run-b", technique_id: "REP-007" }),
      ),
    );
    onActiveRunChange.mockClear();

    await act(async () => {
      staleRefresh.resolve({
        run_id: "run-a",
        technique_id: "REP-004",
        vendor: "fortigate",
        status: "running",
      });
      await Promise.resolve();
    });

    expect(onActiveRunChange).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: /stop the running REP-007/i })).toBeEnabled();
    expect(vi.mocked(getRunStatus).mock.calls.filter(([runId]) => runId === "run-a")).toHaveLength(
      1,
    );
  });

  it("does not let a delayed same-A refresh regress terminal status or progress", async () => {
    const onActiveRunChange = vi.fn();
    const terminalA = deferred<RunStatus>();
    const staleSameOwner = deferred<ActiveRun>();
    const terminalOwnerProbe = deferred<ActiveRun>();
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce({
        run_id: "run-a",
        technique_id: "REP-004",
        vendor: "fortigate",
        status: "running",
        event_count: 12,
        total: 900,
      })
      .mockReturnValueOnce(staleSameOwner.promise)
      .mockReturnValueOnce(terminalOwnerProbe.promise);
    vi.mocked(getRunStatus).mockReturnValue(terminalA.promise);

    const view = renderPanel(COLLECTOR, 2000, onActiveRunChange);
    await waitFor(() => expect(getRunStatus).toHaveBeenCalledWith("run-a"));

    view.rerender(
      <RunPanel
        technique={makeTechnique({ id: "REP-002", name: "Changed selection" })}
        defaultSeed={1337}
        collector={COLLECTOR}
        vendor="fortigate"
        epsCap={2000}
        anchorEpoch={1752537600}
        onActiveRunChange={onActiveRunChange}
      />,
    );
    await waitFor(() => expect(getActiveRun).toHaveBeenCalledTimes(2));

    await act(async () => {
      terminalA.resolve(runStatus("run-a", "done", 900));
      await Promise.resolve();
    });
    await waitFor(() => expect(getActiveRun).toHaveBeenCalledTimes(3));
    const checking = screen.getByRole("button", { name: /checking REP-004/i });
    expect(checking).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent(/900 of 900 events/i);
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "run-a", status: "done", event_count: 900 }),
    );

    await act(async () => {
      staleSameOwner.resolve({
        run_id: "run-a",
        technique_id: "REP-004",
        vendor: "fortigate",
        status: "running",
        event_count: 12,
        total: 900,
      });
      await Promise.resolve();
    });

    expect(screen.getByRole("button", { name: /checking REP-004/i })).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent(/reached done/i);
    expect(screen.getByRole("status")).toHaveTextContent(/900 of 900 events/i);
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "run-a", status: "done", event_count: 900 }),
    );
  });

  it("keeps the vendor callback locked until a requested stop is authoritatively released", async () => {
    const onActiveRunChange = vi.fn();
    const runningStatus = deferred<RunStatus>();
    const activeProbe = deferred<ActiveRun>();
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce({
        run_id: "abc123",
        technique_id: "REP-004",
        vendor: "fortigate",
        status: "running",
        event_count: 12,
        total: 900,
      })
      .mockReturnValue(activeProbe.promise);
    vi.mocked(getRunStatus)
      .mockReturnValueOnce(runningStatus.promise)
      .mockResolvedValueOnce(runStatus("abc123", "stopped", 25));

    renderPanel(COLLECTOR, 2000, onActiveRunChange);

    const stop = await screen.findByRole("button", { name: /stop the running REP-004/i });
    await waitFor(() => expect(getRunStatus).toHaveBeenCalledTimes(1));
    vi.useFakeTimers();
    fireEvent.click(stop);
    await act(async () => {
      await Promise.resolve();
    });

    const stopping = screen.getByRole("button", { name: /stopping REP-004/i });
    expect(stopping).toBeDisabled();
    expect(screen.getByText(/waiting for the backend to report a terminal state/i)).toBeVisible();
    fireEvent.click(stopping);
    expect(stopRun).toHaveBeenCalledTimes(1);

    await act(async () => {
      runningStatus.resolve(runStatus("abc123", "running", 24));
      await Promise.resolve();
    });
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "abc123", status: "running", event_count: 24 }),
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });

    expect(getRunStatus).toHaveBeenCalledTimes(2);
    const checking = screen.getByRole("button", { name: /checking REP-004/i });
    expect(checking).toBeDisabled();
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "abc123", status: "stopped", event_count: 25 }),
    );

    await act(async () => {
      activeProbe.resolve(NO_ACTIVE_RUN);
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(onActiveRunChange).toHaveBeenLastCalledWith(null);
    expect(screen.queryByRole("button", { name: /checking REP-004/i })).toBeNull();
  });

  it("does not start a second watcher when the selected technique refreshes", async () => {
    const pendingStatus = deferred<RunStatus>();
    vi.mocked(getActiveRun).mockResolvedValue({
      run_id: "abc123",
      technique_id: "REP-004",
      vendor: "fortigate",
      status: "running",
      event_count: 12,
      total: 900,
    });
    vi.mocked(getRunStatus).mockReturnValue(pendingStatus.promise);

    const view = renderPanel();
    await waitFor(() => expect(getRunStatus).toHaveBeenCalledTimes(1));

    view.rerender(
      <RunPanel
        technique={makeTechnique({ id: "REP-002", name: "Changed selection" })}
        defaultSeed={1337}
        collector={COLLECTOR}
        vendor="fortigate"
        epsCap={2000}
        anchorEpoch={1752537600}
      />,
    );

    await waitFor(() => expect(getActiveRun).toHaveBeenCalledTimes(2));
    expect(getRunStatus).toHaveBeenCalledTimes(1);
  });

  it("lets the latest overlapping empty-state refresh own active-run discovery", async () => {
    const onActiveRunChange = vi.fn();
    const olderRefresh = deferred<ActiveRun>();
    const newerRefresh = deferred<ActiveRun>();
    const statusB = deferred<RunStatus>();
    vi.mocked(getActiveRun)
      .mockReturnValueOnce(olderRefresh.promise)
      .mockReturnValueOnce(newerRefresh.promise);
    vi.mocked(getRunStatus).mockReturnValue(statusB.promise);

    const view = renderPanel(COLLECTOR, 2000, onActiveRunChange);
    await waitFor(() => expect(getActiveRun).toHaveBeenCalledTimes(1));
    view.rerender(
      <RunPanel
        technique={makeTechnique({ id: "REP-002", name: "Changed selection" })}
        defaultSeed={1337}
        collector={COLLECTOR}
        vendor="fortigate"
        epsCap={2000}
        anchorEpoch={1752537600}
        onActiveRunChange={onActiveRunChange}
      />,
    );
    await waitFor(() => expect(getActiveRun).toHaveBeenCalledTimes(2));
    onActiveRunChange.mockClear();

    // The older request returns a stale owner while the newer request is still
    // pending. It must not claim the lock and then cause the newer B result to
    // fail its expected-null compare-and-swap.
    await act(async () => {
      olderRefresh.resolve({
        run_id: "run-a",
        technique_id: "REP-004",
        vendor: "fortigate",
        status: "running",
      });
      await Promise.resolve();
    });
    expect(onActiveRunChange).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: /stop the running REP-004/i })).toBeNull();

    await act(async () => {
      newerRefresh.resolve({
        run_id: "run-b",
        technique_id: "REP-007",
        vendor: "paloalto",
        status: "running",
      });
      await Promise.resolve();
    });

    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "run-b", technique_id: "REP-007" }),
    );
    expect(screen.getByRole("button", { name: /stop the running REP-007/i })).toBeEnabled();
    expect(vi.mocked(getRunStatus).mock.calls.map(([runId]) => runId)).toEqual(["run-b"]);
  });

  it("cancels a pending restored-run watcher on unmount", async () => {
    const onActiveRunChange = vi.fn();
    const pendingStatus = deferred<RunStatus>();
    vi.mocked(getActiveRun).mockResolvedValueOnce({
      run_id: "abc123",
      technique_id: "REP-004",
      vendor: "fortigate",
      status: "running",
    });
    vi.mocked(getRunStatus).mockReturnValue(pendingStatus.promise);

    const view = renderPanel(COLLECTOR, 2000, onActiveRunChange);
    await waitFor(() => expect(getRunStatus).toHaveBeenCalledTimes(1));
    onActiveRunChange.mockClear();
    view.unmount();

    await act(async () => {
      pendingStatus.resolve(runStatus("abc123", "done", 900));
      await Promise.resolve();
    });

    expect(getActiveRun).toHaveBeenCalledTimes(1);
    expect(onActiveRunChange).not.toHaveBeenCalled();
  });

  it("suppresses technique refreshes across admission and publishes only the accepted run", async () => {
    const startResponse = deferred<Awaited<ReturnType<typeof startRun>>>();
    const onActiveRunChange = vi.fn();
    const onRunAdmissionChange = vi.fn();
    const streamUrls: string[] = [];

    class FakeEventSource {
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      onerror: (() => void) | null = null;
      close = vi.fn();

      constructor(url: string) {
        streamUrls.push(url);
      }
    }

    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(getActiveRun).mockResolvedValueOnce(NO_ACTIVE_RUN);
    vi.mocked(startRun).mockReturnValue(startResponse.promise);

    const view = renderPanel(COLLECTOR, 2000, onActiveRunChange, onRunAdmissionChange);
    await waitFor(() => expect(getActiveRun).toHaveBeenCalledTimes(1));
    const runButton = screen.getByRole("button", { name: /^Run and send/ });
    await waitFor(() => expect(runButton).toBeEnabled());
    onActiveRunChange.mockClear();
    fireEvent.click(runButton);
    await waitFor(() => expect(startRun).toHaveBeenCalledTimes(1));
    expect(onRunAdmissionChange).toHaveBeenLastCalledWith({
      technique_id: "REP-001",
      vendor: "fortigate",
    });

    // Browsing the catalog can still change the technique while admission is
    // pending. General owner discovery stays out of the exact admission
    // protocol rather than racing it with a second snapshot.
    view.rerender(
      <RunPanel
        technique={makeTechnique({ id: "REP-002", name: "Changed selection" })}
        defaultSeed={1337}
        collector={COLLECTOR}
        vendor="fortigate"
        epsCap={2000}
        anchorEpoch={1752537600}
        onActiveRunChange={onActiveRunChange}
        onRunAdmissionChange={onRunAdmissionChange}
      />,
    );
    await act(async () => {
      await Promise.resolve();
    });
    expect(getActiveRun).toHaveBeenCalledTimes(1);
    expect(onActiveRunChange).not.toHaveBeenCalled();

    await act(async () => {
      startResponse.resolve({
        admission_id: "00000000-0000-4000-8000-000000000001",
        run_id: "run-b",
        vendor: "paloalto",
        total: 49,
        pace: "plan",
        speed: 1,
        projected_s: 14280,
        plan_span_s: 14280,
      });
      await Promise.resolve();
    });

    await waitFor(() => expect(streamUrls).toEqual(["/api/runs/run-b/events"]));
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({
        run_id: "run-b",
        technique_id: "REP-001",
        vendor: "paloalto",
        status: "running",
      }),
    );
    expect(onActiveRunChange.mock.calls.map(([active]) => active?.run_id ?? null)).toEqual([
      "run-b",
      "run-b",
    ]);
    expect(onRunAdmissionChange).toHaveBeenLastCalledWith(null);
    expect(screen.getByRole("button", { name: "Stop run" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: /stop the running REP-007/i })).toBeNull();

    // No general owner snapshot was launched while the exact admission
    // protocol owned the transition, so nothing can replace B afterward.
    onActiveRunChange.mockClear();
    expect(onActiveRunChange).not.toHaveBeenCalled();
    expect(streamUrls).toEqual(["/api/runs/run-b/events"]);
    expect(screen.getByRole("button", { name: "Stop run" })).toBeEnabled();
    expect(screen.queryByText(/REP-007 is already running/i)).toBeNull();
  });

  it("does not attach a run stream when the start response arrives after unmount", async () => {
    const activeRefresh = deferred<ActiveRun>();
    const startResponse = deferred<Awaited<ReturnType<typeof startRun>>>();
    const onActiveRunChange = vi.fn();
    const eventSourceConstructor = vi.fn();

    class FakeEventSource {
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      onerror: (() => void) | null = null;
      close = vi.fn();

      constructor(url: string) {
        eventSourceConstructor(url);
      }
    }

    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(getActiveRun).mockReturnValue(activeRefresh.promise);
    vi.mocked(startRun).mockReturnValue(startResponse.promise);

    const view = renderPanel(COLLECTOR, 2000, onActiveRunChange);
    activeRefresh.resolve(NO_ACTIVE_RUN);
    const runButton = screen.getByRole("button", { name: /^Run and send/ });
    await waitFor(() => expect(runButton).toBeEnabled());
    onActiveRunChange.mockClear();
    fireEvent.click(runButton);
    await waitFor(() => expect(startRun).toHaveBeenCalledTimes(1));
    view.unmount();

    await act(async () => {
      startResponse.resolve({
        admission_id: "00000000-0000-4000-8000-000000000001",
        run_id: "run-after-unmount",
        vendor: "fortigate",
        total: 49,
        pace: "plan",
        speed: 1,
        projected_s: 14280,
        plan_span_s: 14280,
      });
      await Promise.resolve();
    });

    expect(eventSourceConstructor).not.toHaveBeenCalled();
    expect(onActiveRunChange).not.toHaveBeenCalled();
  });

  it("hands a locally completed SSE run directly to the successor owner", async () => {
    let stream: {
      onmessage: ((event: MessageEvent<string>) => void) | null;
      onerror: (() => void) | null;
      close: ReturnType<typeof vi.fn>;
    } | null = null;

    class FakeEventSource {
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      onerror: (() => void) | null = null;
      close = vi.fn();

      constructor(_url: string) {
        stream = this;
      }
    }

    const onActiveRunChange = vi.fn();
    const successorStatus = deferred<RunStatus>();
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce(NO_ACTIVE_RUN)
      .mockRejectedValueOnce(new Error("temporary active-owner failure"))
      .mockResolvedValue({
        run_id: "run-b",
        technique_id: "REP-007",
        vendor: "paloalto",
        status: "running",
        event_count: 3,
        total: 50,
      });
    vi.mocked(getRunStatus).mockReturnValue(successorStatus.promise);
    vi.mocked(startRun).mockResolvedValue({
      admission_id: "00000000-0000-4000-8000-000000000001",
      run_id: "run-a",
      vendor: "fortigate",
      total: 49,
      pace: "plan",
      speed: 1,
      projected_s: 14280,
      plan_span_s: 14280,
    });

    renderPanel(COLLECTOR, 2000, onActiveRunChange);
    fireEvent.click(await screen.findByRole("button", { name: /^Run and send/ }));
    await waitFor(() => expect(stream).not.toBeNull());
    await waitFor(() =>
      expect(onActiveRunChange).toHaveBeenLastCalledWith(
        expect.objectContaining({
          run_id: "run-a",
          vendor: "fortigate",
          status: "running",
        }),
      ),
    );
    onActiveRunChange.mockClear();
    vi.useFakeTimers();

    await act(async () => {
      stream!.onmessage?.({
        data: JSON.stringify({
          type: "done",
          status: "done",
          count: 49,
          manifest: null,
        }),
      } as MessageEvent<string>);
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "run-a", vendor: "fortigate", status: "done" }),
    );
    expect(onActiveRunChange.mock.calls.map(([active]) => active?.run_id ?? null)).not.toContain(
      null,
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });

    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({
        run_id: "run-b",
        technique_id: "REP-007",
        vendor: "paloalto",
      }),
    );
    expect(onActiveRunChange.mock.calls.map(([active]) => active?.run_id ?? null)).not.toContain(
      null,
    );
    expect(getRunStatus).toHaveBeenCalledWith("run-b");
  });

  it("uses the same ownership handoff after dropped-SSE status polling", async () => {
    let stream: {
      onmessage: ((event: MessageEvent<string>) => void) | null;
      onerror: (() => void) | null;
      close: ReturnType<typeof vi.fn>;
    } | null = null;

    class FakeEventSource {
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      onerror: (() => void) | null = null;
      close = vi.fn();

      constructor(_url: string) {
        stream = this;
      }
    }

    const onActiveRunChange = vi.fn();
    const successorStatus = deferred<RunStatus>();
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce(NO_ACTIVE_RUN)
      .mockResolvedValue({
        run_id: "run-b",
        technique_id: "REP-007",
        vendor: "paloalto",
        status: "running",
        event_count: 3,
        total: 50,
      });
    vi.mocked(getRunStatus).mockImplementation((runId) =>
      runId === "run-a"
        ? Promise.resolve(runStatus("run-a", "stopped", 31, 49))
        : successorStatus.promise,
    );
    vi.mocked(startRun).mockResolvedValue({
      admission_id: "00000000-0000-4000-8000-000000000001",
      run_id: "run-a",
      vendor: "fortigate",
      total: 49,
      pace: "plan",
      speed: 1,
      projected_s: 14280,
      plan_span_s: 14280,
    });

    renderPanel(COLLECTOR, 2000, onActiveRunChange);
    fireEvent.click(await screen.findByRole("button", { name: /^Run and send/ }));
    await waitFor(() => expect(stream).not.toBeNull());
    await waitFor(() =>
      expect(onActiveRunChange).toHaveBeenLastCalledWith(
        expect.objectContaining({ run_id: "run-a", status: "running" }),
      ),
    );
    onActiveRunChange.mockClear();

    await act(async () => {
      stream!.onerror?.();
      await Promise.resolve();
      await Promise.resolve();
    });

    await waitFor(() =>
      expect(onActiveRunChange).toHaveBeenLastCalledWith(
        expect.objectContaining({ run_id: "run-b", technique_id: "REP-007" }),
      ),
    );
    expect(onActiveRunChange.mock.calls).toContainEqual([
      expect.objectContaining({ run_id: "run-a", status: "stopped", event_count: 31 }),
    ]);
    expect(onActiveRunChange.mock.calls.map(([active]) => active?.run_id ?? null)).not.toContain(
      null,
    );
    expect(getRunStatus).toHaveBeenCalledWith("run-a");
    expect(getRunStatus).toHaveBeenCalledWith("run-b");
  });

  it("reconciles current ownership when a dropped-SSE run status was evicted", async () => {
    let stream: {
      onmessage: ((event: MessageEvent<string>) => void) | null;
      onerror: (() => void) | null;
      close: ReturnType<typeof vi.fn>;
    } | null = null;

    class FakeEventSource {
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      onerror: (() => void) | null = null;
      close = vi.fn();

      constructor(_url: string) {
        stream = this;
      }
    }

    const onActiveRunChange = vi.fn();
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce(NO_ACTIVE_RUN)
      .mockResolvedValue({
        run_id: "run-b",
        technique_id: "REP-007",
        vendor: "paloalto",
        status: "running",
        event_count: 3,
        total: 50,
      });
    vi.mocked(getRunStatus).mockImplementation((runId) =>
      runId === "run-a"
        ? Promise.reject(new ApiError("run not found", 404, "run not found"))
        : new Promise(() => undefined),
    );
    vi.mocked(startRun).mockResolvedValue({
      admission_id: "00000000-0000-4000-8000-000000000001",
      run_id: "run-a",
      vendor: "fortigate",
      total: 49,
      pace: "plan",
      speed: 1,
      projected_s: 14280,
      plan_span_s: 14280,
    });

    renderPanel(COLLECTOR, 2000, onActiveRunChange);
    fireEvent.click(await screen.findByRole("button", { name: /^Run and send/ }));
    await waitFor(() => expect(stream).not.toBeNull());
    await waitFor(() =>
      expect(onActiveRunChange).toHaveBeenLastCalledWith(
        expect.objectContaining({ run_id: "run-a", status: "running" }),
      ),
    );
    onActiveRunChange.mockClear();

    await act(async () => {
      stream!.onerror?.();
      await Promise.resolve();
      await Promise.resolve();
    });

    await waitFor(() =>
      expect(onActiveRunChange).toHaveBeenLastCalledWith(
        expect.objectContaining({
          run_id: "run-b",
          technique_id: "REP-007",
          vendor: "paloalto",
        }),
      ),
    );
    expect(onActiveRunChange.mock.calls).toContainEqual([
      expect.objectContaining({ run_id: "run-a", status: "reconciling" }),
    ]);
    expect(onActiveRunChange.mock.calls.map(([active]) => active?.run_id ?? null)).not.toContain(
      null,
    );
    expect(getActiveRun).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("button", { name: /stop the running REP-007/i })).toBeEnabled();
  });

  it("does not replace a discovered successor when the old dropped-SSE status returns 404", async () => {
    let stream: {
      onmessage: ((event: MessageEvent<string>) => void) | null;
      onerror: (() => void) | null;
      close: ReturnType<typeof vi.fn>;
    } | null = null;

    class FakeEventSource {
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      onerror: (() => void) | null = null;
      close = vi.fn();

      constructor(_url: string) {
        stream = this;
      }
    }

    const onActiveRunChange = vi.fn();
    const oldStatus = deferred<RunStatus>();
    const successorStatus = deferred<RunStatus>();
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce(NO_ACTIVE_RUN)
      .mockResolvedValue({
        run_id: "run-b",
        technique_id: "REP-007",
        vendor: "paloalto",
        status: "running",
        event_count: 3,
        total: 50,
      });
    vi.mocked(getRunStatus).mockImplementation((runId) =>
      runId === "run-a" ? oldStatus.promise : successorStatus.promise,
    );
    vi.mocked(startRun).mockResolvedValue({
      admission_id: "00000000-0000-4000-8000-000000000001",
      run_id: "run-a",
      vendor: "fortigate",
      total: 49,
      pace: "plan",
      speed: 1,
      projected_s: 14280,
      plan_span_s: 14280,
    });

    const view = renderPanel(COLLECTOR, 2000, onActiveRunChange);
    fireEvent.click(await screen.findByRole("button", { name: /^Run and send/ }));
    await waitFor(() => expect(stream).not.toBeNull());
    await act(async () => {
      stream!.onerror?.();
      await Promise.resolve();
    });
    await waitFor(() => expect(getRunStatus).toHaveBeenCalledWith("run-a"));

    view.rerender(
      <RunPanel
        technique={makeTechnique({ id: "REP-002", name: "Changed selection" })}
        defaultSeed={1337}
        collector={COLLECTOR}
        vendor="fortigate"
        epsCap={2000}
        anchorEpoch={1752537600}
        onActiveRunChange={onActiveRunChange}
      />,
    );
    await waitFor(() =>
      expect(onActiveRunChange).toHaveBeenLastCalledWith(
        expect.objectContaining({ run_id: "run-b", technique_id: "REP-007" }),
      ),
    );
    onActiveRunChange.mockClear();

    await act(async () => {
      oldStatus.reject(new ApiError("run not found", 404, "run not found"));
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(onActiveRunChange.mock.calls.map(([active]) => active?.run_id ?? null)).not.toContain(
      "run-a",
    );
    expect(screen.getByRole("button", { name: /stop the running REP-007/i })).toBeEnabled();
    expect(screen.queryByText(/previous run.*no longer has a status record/i)).toBeNull();
  });

  it("does not let a stale local-terminal probe clear a concurrently discovered successor", async () => {
    let stream: {
      onmessage: ((event: MessageEvent<string>) => void) | null;
      onerror: (() => void) | null;
      close: ReturnType<typeof vi.fn>;
    } | null = null;

    class FakeEventSource {
      onmessage: ((event: MessageEvent<string>) => void) | null = null;
      onerror: (() => void) | null = null;
      close = vi.fn();

      constructor(_url: string) {
        stream = this;
      }
    }

    const onActiveRunChange = vi.fn();
    const terminalProbe = deferred<ActiveRun>();
    const refreshProbe = deferred<ActiveRun>();
    const successorStatus = deferred<RunStatus>();
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.mocked(getActiveRun)
      .mockResolvedValueOnce(NO_ACTIVE_RUN)
      .mockReturnValueOnce(terminalProbe.promise)
      .mockReturnValueOnce(refreshProbe.promise);
    vi.mocked(getRunStatus).mockReturnValue(successorStatus.promise);
    vi.mocked(startRun).mockResolvedValue({
      admission_id: "00000000-0000-4000-8000-000000000001",
      run_id: "run-a",
      vendor: "fortigate",
      total: 49,
      pace: "plan",
      speed: 1,
      projected_s: 14280,
      plan_span_s: 14280,
    });

    const view = renderPanel(COLLECTOR, 2000, onActiveRunChange);
    fireEvent.click(await screen.findByRole("button", { name: /^Run and send/ }));
    await waitFor(() => expect(stream).not.toBeNull());
    await waitFor(() =>
      expect(onActiveRunChange).toHaveBeenLastCalledWith(
        expect.objectContaining({ run_id: "run-a", status: "running" }),
      ),
    );

    await act(async () => {
      stream!.onmessage?.({
        data: JSON.stringify({ type: "done", status: "done", count: 49, manifest: null }),
      } as MessageEvent<string>);
      await Promise.resolve();
    });
    await waitFor(() => expect(getActiveRun).toHaveBeenCalledTimes(2));
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "run-a", status: "done" }),
    );
    onActiveRunChange.mockClear();

    view.rerender(
      <RunPanel
        technique={makeTechnique({ id: "REP-002", name: "Changed selection" })}
        defaultSeed={1337}
        collector={COLLECTOR}
        vendor="fortigate"
        epsCap={2000}
        anchorEpoch={1752537600}
        onActiveRunChange={onActiveRunChange}
      />,
    );
    await waitFor(() => expect(getActiveRun).toHaveBeenCalledTimes(3));

    // The older terminal probe resolves first. Latest-started arbitration must
    // ignore its null rather than briefly unlocking while the newer refresh is
    // still waiting to report B.
    await act(async () => {
      terminalProbe.resolve(NO_ACTIVE_RUN);
      await Promise.resolve();
    });
    expect(onActiveRunChange).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: /checking REP-001/i })).toBeDisabled();

    await act(async () => {
      refreshProbe.resolve({
        run_id: "run-b",
        technique_id: "REP-007",
        vendor: "paloalto",
        status: "running",
        event_count: 3,
        total: 50,
      });
      await Promise.resolve();
    });

    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ run_id: "run-b", technique_id: "REP-007" }),
    );
    expect(onActiveRunChange.mock.calls.map(([active]) => active?.run_id ?? null)).not.toContain(
      null,
    );
    expect(screen.getByRole("button", { name: /stop the running REP-007/i })).toBeEnabled();
  });

  it("says which technique refused the start when the server rejects it", async () => {
    const onActiveRunChange = vi.fn();
    vi.mocked(startRun).mockRejectedValue(
      new ApiError("a run is already in progress", 409, {
        message: "a run is already in progress",
        run_id: "abc123",
        technique_id: "REP-004",
        vendor: "paloalto",
      }),
    );
    vi.mocked(getRunStatus).mockResolvedValue(
      runStatus("abc123", "running", 12, 900, "paloalto"),
    );

    renderPanel(COLLECTOR, 2000, onActiveRunChange);
    fireEvent.click(await screen.findByRole("button", { name: /^Run and send/ }));

    expect(await screen.findByRole("status")).toHaveTextContent(/REP-004 is already running/);
    expect(onActiveRunChange).toHaveBeenLastCalledWith(
      expect.objectContaining({
        run_id: "abc123",
        technique_id: "REP-004",
        vendor: "paloalto",
        status: "running",
      }),
    );
  });

  it("retries a lost reservation response with the same id before starting", async () => {
    const requests: Array<{ admission_id: string; technique_id: string; vendor: string }> = [];
    const pendingStart = deferred<Awaited<ReturnType<typeof startRun>>>();
    vi.mocked(reserveRun)
      // Record the first request even though its response is lost.
      .mockImplementationOnce(async (request) => {
        requests.push(request);
        throw new Error("reservation response reset");
      })
      .mockImplementation(async (request) => {
        requests.push(request);
        return reservation(request.admission_id);
      });
    vi.mocked(startRun).mockReturnValue(pendingStart.promise);

    renderPanel();
    const runButton = screen.getByRole("button", { name: /^Run and send/ });
    await waitFor(() => expect(runButton).toBeEnabled());
    vi.useFakeTimers();

    await act(async () => {
      fireEvent.click(runButton);
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(reserveRun).toHaveBeenCalledTimes(1);
    expect(startRun).not.toHaveBeenCalled();
    expect(screen.getByText(/retrying the same identity/i)).toBeVisible();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });

    expect(reserveRun).toHaveBeenCalledTimes(2);
    expect(startRun).toHaveBeenCalledTimes(1);
    expect(requests).toHaveLength(2);
    expect(requests[0].admission_id).toBe(requests[1].admission_id);
    expect(requests[0].admission_id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(startRun).toHaveBeenCalledWith(
      expect.objectContaining({ admission_id: requests[0].admission_id }),
    );
  });

  it("retains final evidence when a lost start response is already done", async () => {
    const onActiveRunChange = vi.fn();
    const onRunAdmissionChange = vi.fn();
    const completedManifest: Manifest = {
      technique_id: "REP-001",
      technique_name: "Beaconing",
      ndr_uc: "NDR-001",
      intensity: "medium",
      seed: 1337,
      target: "none",
      transport: "none",
      event_count: 49,
      planned_event_count: 49,
      started_at: "2026-09-06T10:00:00+04:00",
      ended_at: "2026-09-06T10:00:01+04:00",
      updated_at: "2026-09-06T10:00:01+04:00",
      anchor_epoch: 1752537600,
      warmup_note: null,
      status: "done",
      partial: false,
      error: null,
    };
    vi.mocked(startRun).mockRejectedValue(new Error("start response reset"));
    vi.mocked(getRunAdmission).mockResolvedValue({
      admission_id: "00000000-0000-4000-8000-000000000001",
      run_id: "fast-finished-run",
      technique_id: "REP-001",
      vendor: "fortigate",
      status: "done",
      event_count: 49,
      total: 49,
    });
    vi.mocked(getRunStatus).mockResolvedValue({
      ...runStatus("fast-finished-run", "done", 49, 49),
      admission_id: "00000000-0000-4000-8000-000000000001",
      manifest: completedManifest,
    });

    renderPanel(COLLECTOR, 2000, onActiveRunChange, onRunAdmissionChange);
    fireEvent.click(await screen.findByRole("button", { name: /^Run and send/ }));

    expect(await screen.findByText(/Run complete.*manifest written/i)).toBeVisible();
    expect(screen.getByTestId("manifest-events")).toHaveTextContent("49 / 49");
    expect(getRunStatus).toHaveBeenCalledWith("fast-finished-run");
    expect(getActiveRun).toHaveBeenCalledTimes(2);
    expect(onRunAdmissionChange).toHaveBeenLastCalledWith(null);
    expect(onActiveRunChange).toHaveBeenLastCalledWith(null);
  });

  it("turns an unauthorized known reservation into a visible owner instead of retrying admission", async () => {
    const onRunAdmissionChange = vi.fn();
    vi.mocked(startRun).mockRejectedValue(
      new ApiError("session expired", 401, "session expired"),
    );
    vi.mocked(getRunAdmission).mockRejectedValue(
      new ApiError("session expired", 401, "session expired"),
    );
    vi.mocked(getRunStatus).mockRejectedValue(
      new ApiError("session expired", 401, "session expired"),
    );

    renderPanel(COLLECTOR, 2000, undefined, onRunAdmissionChange);
    const runButton = screen.getByRole("button", { name: /^Run and send/ });
    await waitFor(() => expect(runButton).toBeEnabled());
    fireEvent.click(runButton);

    expect(await screen.findByText(/admission status is unavailable/i)).toBeVisible();
    expect(screen.getByText(/reopen the URL printed by replicant web/i)).toBeVisible();
    expect(onRunAdmissionChange).toHaveBeenLastCalledWith(null);
    expect(runButton).toBeDisabled();
    expect(screen.getByRole("button", { name: /cancel admission for REP-001/i })).toBeEnabled();
    expect(getActiveRun).toHaveBeenCalledTimes(1);
  });

  it("does not claim a run is active when none is", async () => {
    renderPanel();

    await waitFor(() => expect(getActiveRun).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: /stop the running/i })).toBeNull();
  });
});
