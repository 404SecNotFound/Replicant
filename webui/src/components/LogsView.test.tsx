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

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LogsView } from "./LogsView";
import * as api from "@/lib/api";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, getLogs: vi.fn(), setLogLevel: vi.fn() };
});

function entry(seq: number, level: api.LogLevel, message: string): api.LogEntry {
  return { seq, ts: 1753900000 + seq, level, logger: "replicant.transport", message };
}

beforeEach(() => {
  vi.mocked(api.getLogs).mockResolvedValue({
    level: "info",
    levels: ["debug", "verbose", "info", "warning"],
    entries: [entry(1, "info", "emitted 921 events (410000 bytes) in 1.00s")],
    cursor: 1,
  });
  vi.mocked(api.setLogLevel).mockResolvedValue({ level: "debug" });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("LogsView", () => {
  it("shows the four modes the operator asked for", async () => {
    render(<LogsView />);

    for (const label of ["Debug", "Verbose", "Informational", "Warning"]) {
      expect(await screen.findByRole("button", { name: label })).toBeVisible();
    }
  });

  it("renders records from the buffer", async () => {
    render(<LogsView />);

    expect(await screen.findByText(/emitted 921 events/)).toBeVisible();
  });

  it("marks the active mode as pressed, so the current filter is visible", async () => {
    render(<LogsView />);

    const info = await screen.findByRole("button", { name: "Informational" });
    expect(info).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Debug" })).toHaveAttribute("aria-pressed", "false");
  });

  it("sends the level change to the server", async () => {
    render(<LogsView />);

    fireEvent.click(await screen.findByRole("button", { name: "Debug" }));

    await waitFor(() => expect(api.setLogLevel).toHaveBeenCalledWith("debug"));
  });

  it("polls with a cursor so records are not re-fetched", async () => {
    vi.useFakeTimers();
    try {
      render(<LogsView />);
      await vi.advanceTimersByTimeAsync(0);
      expect(api.getLogs).toHaveBeenLastCalledWith(0);

      await vi.advanceTimersByTimeAsync(1000);
      expect(api.getLogs).toHaveBeenLastCalledWith(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("stops polling once unmounted, so a closed tab costs nothing", async () => {
    vi.useFakeTimers();
    try {
      const view = render(<LogsView />);
      await vi.advanceTimersByTimeAsync(0);
      const before = vi.mocked(api.getLogs).mock.calls.length;

      view.unmount();
      await vi.advanceTimersByTimeAsync(5000);

      expect(vi.mocked(api.getLogs).mock.calls.length).toBe(before);
    } finally {
      vi.useRealTimers();
    }
  });

  it("counts warnings separately, since that is what a failing run produces", async () => {
    vi.mocked(api.getLogs).mockResolvedValue({
      level: "debug",
      levels: ["debug", "verbose", "info", "warning"],
      entries: [
        entry(1, "info", "connecting to collector 10.20.0.50:514 over udp"),
        entry(2, "warning", "datagram is 1893 bytes, above the 1472-byte non-fragmenting limit"),
      ],
      cursor: 2,
    });

    render(<LogsView />);

    expect(await screen.findByText(/1 warning/)).toBeVisible();
    expect(screen.getByText(/2 lines/)).toBeVisible();
  });

  it("surfaces a fetch failure instead of showing a silently empty log", async () => {
    vi.mocked(api.getLogs).mockRejectedValue(new Error("unauthorised"));

    render(<LogsView />);

    expect(await screen.findByText("unauthorised")).toBeVisible();
  });

  it("says what to do when the buffer is empty", async () => {
    vi.mocked(api.getLogs).mockResolvedValue({
      level: "info",
      levels: ["debug", "verbose", "info", "warning"],
      entries: [],
      cursor: 0,
    });

    render(<LogsView />);

    expect(await screen.findByText(/No records yet/)).toBeVisible();
  });
});
