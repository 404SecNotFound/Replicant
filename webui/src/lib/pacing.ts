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

// The delivery shape, as the run form sees it.
//
// A plan carries a per-event time. Replicant used to ignore it and send as fast
// as the rate cap allowed, so a four hour beacon reached the collector as a three
// second burst carrying four hours of timestamps. Measured against a live
// LogRhythm collector: 49 events in 3 seconds, spread over 238 minutes. Nothing
// keyed on the interval between events can work on that.
//
// "burst" and "plan" are implementation words, so the form does not rely on them.
// Each option carries the consequence in plain words with the real numbers in it,
// the same way the run button names its destination rather than leaving two
// switches to imply it.

export type PaceChoice = "plan" | "burst";

/** The pacing preview returned by `POST /api/plan`, priced for this exact run. */
export interface PlanPreview {
  event_count: number;
  /** The span the plan's own event times cover, before any compression. */
  plan_span_s: number;
  /** The span the rendered timestamps will claim once a speed is applied. */
  compressed_span_s: number;
  /** How long delivery actually takes at this pace, speed and rate cap. */
  projected_s: number;
  /**
   * The same figure for every pace, so each option can carry its own duration.
   *
   * Pricing only the selected pace would leave the other option showing either a
   * stale number or nothing while a request is in flight, and comparing the two
   * is the entire reason the control exists.
   */
  projected_by_pace: { plan: number; burst: number };
  pace: PaceChoice;
  speed: number;
}

/** How long this run takes under `pace`, or null before the preview arrives. */
export function projectedFor(pace: PaceChoice, preview: PlanPreview | null): number | null {
  return preview ? preview.projected_by_pace[pace] : null;
}

/** The right pace for a destination: the plan's own time on the wire, burst to a file. */
export function defaultPace(sending: boolean): PaceChoice {
  return sending ? "plan" : "burst";
}

/** A duration an operator reads at a glance. Mirrors `format_span` in `replicant/core/pacing.py`. */
export function fmtSpan(seconds: number): string {
  // Not rounded to a whole second: a burst of 49 events is a fraction of one, and
  // "0s" beside a running progress bar reads as a bug rather than as a fast run.
  if (seconds < 1) return `${seconds.toFixed(1)}s`;
  const total = Math.round(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, "0")}m`;
  if (minutes > 0) return `${minutes}m ${String(secs).padStart(2, "0")}s`;
  return `${secs}s`;
}

/**
 * What this pace will actually do, in a sentence, with this run's own numbers.
 *
 * Falls back to the shape of the answer while the preview is in flight, so the
 * control is never blank and never shows a placeholder number.
 */
export function paceConsequence(
  pace: PaceChoice,
  speed: number,
  preview: PlanPreview | null,
): string {
  if (pace === "burst") {
    const tail =
      "so a rule keyed on the interval between events has nothing to match.";
    if (!preview) {
      return `Sends as fast as the rate cap allows, ignoring the gaps in the plan's timeline. The timestamps still carry those gaps, ${tail}`;
    }
    return `Sends ${preview.event_count} events as fast as the rate cap allows: about ${fmtSpan(preview.projected_by_pace.burst)}. The timestamps still span ${fmtSpan(preview.plan_span_s)}, ${tail}`;
  }

  if (speed === 1) {
    if (!preview) {
      return "Sends each event when the plan says it happens, so the collector sees the real intervals.";
    }
    return `Sends each event when the plan says it happens. This run takes ${fmtSpan(preview.projected_by_pace.plan)}, and event time matches send time throughout.`;
  }

  // Compression preserves relative timing and changes absolute intervals. That is
  // the trade, and it belongs next to the time it saves rather than in a manual.
  const caveat =
    "Event times compress with the schedule, so a rule keyed on the real gaps will not match. Use 1x to validate a rule.";
  if (!preview) {
    return `Sends each event when the plan says it happens, compressed ${speed}x. ${caveat}`;
  }
  return `Sends each event when the plan says it happens, compressed ${speed}x: ${fmtSpan(preview.plan_span_s)} of activity delivered in ${fmtSpan(preview.projected_by_pace.plan)}. ${caveat}`;
}
