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

import { describe, expect, it, vi } from "vitest";

import { isTerminalStatus, pollRunUntilTerminal } from "./runLifecycle";

const noSleep = () => Promise.resolve();

describe("isTerminalStatus", () => {
  it("treats done/stopped/error as terminal and running as active", () => {
    expect(isTerminalStatus("done")).toBe(true);
    expect(isTerminalStatus("stopped")).toBe(true);
    expect(isTerminalStatus("error")).toBe(true);
    expect(isTerminalStatus("running")).toBe(false);
  });
});

describe("pollRunUntilTerminal", () => {
  it("keeps polling while the backend is still running, then finalizes on a terminal status", async () => {
    // The backend is still emitting after the SSE stream dropped: two 'running'
    // polls, then 'done'. onTerminal must fire only on the terminal poll.
    const statuses = [
      { status: "running", event_count: 10, manifest: null },
      { status: "running", event_count: 25, manifest: null },
      { status: "done", event_count: 42, manifest: { event_count: 42 } },
    ];
    const getStatus = vi.fn(() => Promise.resolve(statuses.shift()!));
    const onProgress = vi.fn();
    const onTerminal = vi.fn();

    await pollRunUntilTerminal({
      getStatus,
      onProgress,
      onTerminal,
      sleep: noSleep,
      isCancelled: () => false,
    });

    expect(getStatus).toHaveBeenCalledTimes(3);
    expect(onProgress).toHaveBeenLastCalledWith(42);
    expect(onTerminal).toHaveBeenCalledTimes(1);
    expect(onTerminal).toHaveBeenCalledWith(
      expect.objectContaining({ status: "done", event_count: 42 }),
    );
  });

  it("does not finalize while the run is active (a dropped stream is not completion)", async () => {
    // If it never reaches terminal, onTerminal must never fire; cancellation is the
    // only way out. This is the exact bug: an SSE error must not end the run.
    let polls = 0;
    const onTerminal = vi.fn();
    await pollRunUntilTerminal({
      getStatus: () => Promise.resolve({ status: "running", event_count: polls, manifest: null }),
      onProgress: () => undefined,
      onTerminal,
      sleep: noSleep,
      isCancelled: () => ++polls >= 5, // give up after a few active polls
    });
    expect(onTerminal).not.toHaveBeenCalled();
  });

  it("retries a transient status fetch failure instead of giving up", async () => {
    const results = [
      Promise.reject(new Error("network blip")),
      Promise.resolve({ status: "done", event_count: 3, manifest: null }),
    ];
    const getStatus = vi.fn(() => results.shift()!);
    const onTerminal = vi.fn();
    await pollRunUntilTerminal({
      getStatus,
      onProgress: () => undefined,
      onTerminal,
      sleep: noSleep,
      isCancelled: () => false,
    });
    expect(getStatus).toHaveBeenCalledTimes(2);
    expect(onTerminal).toHaveBeenCalledTimes(1);
  });

  it("stops immediately when cancelled before the first poll", async () => {
    const getStatus = vi.fn(() => Promise.resolve({ status: "running", event_count: 0, manifest: null }));
    await pollRunUntilTerminal({
      getStatus,
      onProgress: () => undefined,
      onTerminal: () => undefined,
      sleep: noSleep,
      isCancelled: () => true,
    });
    expect(getStatus).not.toHaveBeenCalled();
  });
});
