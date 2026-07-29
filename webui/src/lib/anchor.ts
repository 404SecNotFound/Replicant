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

// The event-time anchor, as the run form sees it.
//
// Replicant's default anchor is deliberately fixed, so the same seed produces
// byte-identical output. That is right for `--to-file` artifacts and for the
// golden tests, and it is a trap the moment events go to a real collector: the
// syslog header is stamped at send time while the CEF eventtime stays at the
// anchor. On a SIEM that keys on receipt time nothing looks wrong; on one that
// keys on parsed event time, no recent-window rule fires and the operator cannot
// tell that from a broken detection.

export type AnchorChoice = "now" | "fixed";

/** The right anchor for a destination: `now` for the wire, `fixed` for a file. */
export function defaultAnchor(sending: boolean): AnchorChoice {
  return sending ? "now" : "fixed";
}

/**
 * A pre-flight notice for the form, or null when there is nothing to say.
 *
 * This states the consequence rather than re-implementing the server's staleness
 * threshold, so there is no duplicated rule to drift. The authoritative warning
 * still comes back from `POST /api/runs` as `anchor_warning`.
 */
export function anchorNotice(
  anchor: AnchorChoice,
  sending: boolean,
  anchorEpoch: number,
): string | null {
  if (!sending || anchor === "now") return null;
  const when = new Date(anchorEpoch * 1000).toISOString().replace("T", " ").slice(0, 16);
  return (
    `Live send with a fixed anchor. Events will carry an event time of ${when} UTC ` +
    "while the syslog header is stamped now. If your SIEM keys on the parsed event " +
    "time, recent-window rules will not fire."
  );
}
