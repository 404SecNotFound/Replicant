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

// Run lifecycle helpers, kept out of the component so the decision that matters
// for safety is unit-testable: a dropped SSE stream is NOT run completion. The
// backend worker keeps emitting after a transient stream error, so the UI must
// poll authoritative status and keep the run (and its Stop control) active until
// the backend itself reports a terminal state.

export const TERMINAL_STATUSES = ["done", "stopped", "error"] as const;

export function isTerminalStatus(status: string): boolean {
  return (TERMINAL_STATUSES as readonly string[]).includes(status);
}

export interface RunStatusSnapshot {
  status: string;
  event_count: number;
  manifest: unknown | null;
}

export interface PollRunDeps {
  /** Fetch the authoritative run status from the backend. */
  getStatus: () => Promise<RunStatusSnapshot>;
  /** Called on every successful poll with the latest event count. */
  onProgress: (count: number) => void;
  /** Called exactly once, when the backend reports a terminal status. */
  onTerminal: (snapshot: RunStatusSnapshot) => void;
  /** Sleep between polls. Injected so tests need no real timers. */
  sleep: (ms: number) => Promise<void>;
  /** True when the run was superseded or the view unmounted; stops polling. */
  isCancelled: () => boolean;
  intervalMs?: number;
}

/**
 * Poll run status until the backend reports terminal, then finalize once.
 *
 * A transient fetch failure is retried rather than treated as completion. The
 * loop exits without finalizing only when cancelled, so a still-running backend
 * never appears finished to the operator.
 */
export async function pollRunUntilTerminal(deps: PollRunDeps): Promise<void> {
  const interval = deps.intervalMs ?? 1000;
  while (!deps.isCancelled()) {
    let snapshot: RunStatusSnapshot;
    try {
      snapshot = await deps.getStatus();
    } catch {
      await deps.sleep(interval);
      continue;
    }
    deps.onProgress(snapshot.event_count);
    if (isTerminalStatus(snapshot.status)) {
      deps.onTerminal(snapshot);
      return;
    }
    await deps.sleep(interval);
  }
}
