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

// Shaping the catalog for the left rail: grouping by ATT&CK tactic and filtering.
// Kept out of the component so the ordering and matching rules are unit-testable
// without rendering anything.

import type { Technique } from "@/lib/api";

/** The render paths the catalog actually uses, in rough order of how common they are. */
export const LOG_TYPES = [
  "traffic:forward",
  "dns:dns-query",
  "dns:dns-response",
  "event:vpn",
  "utm:ips",
] as const;

// ATT&CK Enterprise tactic order. This is the kill chain, and it is neither
// alphabetical nor numeric: Reconnaissance (TA0043) and Resource Development
// (TA0042) come first while carrying the highest numbers, and Exfiltration
// (TA0010) sits after Command and Control (TA0011). Sorting by either obvious key
// puts the rail in the wrong order, so the order is stated explicitly.
const TACTIC_ORDER = [
  "TA0043", // Reconnaissance
  "TA0042", // Resource Development
  "TA0001", // Initial Access
  "TA0002", // Execution
  "TA0003", // Persistence
  "TA0004", // Privilege Escalation
  "TA0005", // Defense Evasion
  "TA0006", // Credential Access
  "TA0007", // Discovery
  "TA0008", // Lateral Movement
  "TA0009", // Collection
  "TA0011", // Command and Control
  "TA0010", // Exfiltration
  "TA0040", // Impact
];

export const UNMAPPED = "Unmapped";

export interface TacticGroup {
  tactic: string;
  techniques: Technique[];
}

export interface CatalogFilter {
  query?: string;
  logTypes?: readonly string[];
}

export function logTypeOf(technique: Technique): string {
  return `${technique.log_type}:${technique.subtype}`;
}

function rank(tactic: string): number {
  const index = TACTIC_ORDER.indexOf(tactic.slice(0, 6));
  // An unknown tactic, and the Unmapped bucket, sort after every known one rather
  // than silently landing at the top of the rail.
  return index === -1 ? TACTIC_ORDER.length : index;
}

/**
 * Group techniques by ATT&CK tactic, in kill-chain order.
 *
 * A technique mapped to several tactics appears under each of them: at 24 entries
 * the rail is for finding a technique, and hiding an exfiltration technique from
 * the Exfiltration group because it is also C2 would defeat that.
 */
export function groupByTactic(techniques: Technique[]): TacticGroup[] {
  const groups = new Map<string, Technique[]>();
  for (const technique of techniques) {
    const tactics = technique.tactics.length ? technique.tactics : [UNMAPPED];
    for (const tactic of tactics) {
      const bucket = groups.get(tactic);
      if (bucket) bucket.push(technique);
      else groups.set(tactic, [technique]);
    }
  }
  return [...groups.entries()]
    .map(([tactic, members]) => ({ tactic, techniques: members }))
    .sort((a, b) => rank(a.tactic) - rank(b.tactic) || a.tactic.localeCompare(b.tactic));
}

/**
 * Filter by a free-text query and a set of log types.
 *
 * The query matches the technique id, the name, the use case id, and the ATT&CK
 * technique ids at once, because an engineer arriving from a detection backlog has
 * whichever identifier their ticket happened to carry.
 */
export function filterTechniques(
  techniques: Technique[],
  { query = "", logTypes = [] }: CatalogFilter,
): Technique[] {
  const needle = query.trim().toLowerCase();
  const wanted = new Set(logTypes);
  return techniques.filter((technique) => {
    if (wanted.size && !wanted.has(logTypeOf(technique))) return false;
    if (!needle) return true;
    const haystack = [
      technique.id,
      technique.name,
      technique.ndr_uc,
      ...technique.attack,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(needle);
  });
}
