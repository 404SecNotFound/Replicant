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

import type { ConfigResponse, Technique } from "@/lib/api";

export function makeTechnique(overrides: Partial<Technique> = {}): Technique {
  return {
    id: "REP-001",
    name: "Beaconing",
    ndr_rule: "rule",
    ndr_uc: "UC-001",
    objective: "Prove a detection can catch a beacon by keying on the interval between sessions.",
    logical_log_type: "traffic",
    logical_subtype: "forward",
    logical_families: ["traffic:forward"],
    log_type: "traffic",
    subtype: "forward",
    native_log_type: "traffic",
    native_subtype: "forward",
    native_signature_id: "00013",
    native_action: "accept",
    native_metadata_scope: "primary",
    native_metadata_semantics: "Primary FortiGate category and subtype",
    attack: ["T1071.001"],
    tactics: ["TA0011 Command and Control"],
    intensities: ["low", "medium", "high"],
    implemented: true,
    safety_notes: null,
    signature_id: "00013",
    action: "accept",
    cef_fields_held: [],
    cef_fields_varied: [],
    native_cef_fields_held: [],
    native_cef_fields_varied: [],
    native_cef_fields_unavailable: { held: [], varied: [] },
    native_cef_fields_by_logical_family: {
      "traffic:forward": { held: [], varied: [], unavailable: { held: [], varied: [] } },
    },
    params: {},
    distributions: {},
    benign_baseline: null,
    transferability: "transfers",
    transferability_note: null,
    references: [],
    ...overrides,
  };
}

export function makeConfig(overrides: Partial<ConfigResponse> = {}): ConfigResponse {
  return {
    default_seed: 1337,
    eps_cap: 2000,
    default_intensity: "medium",
    hostname: "FGT-LAB-01",
    anchor_epoch: 1752537600,
    accepted_as: "FGT-LAB-01",
    vendor: "fortigate",
    vendors: ["fortigate", "paloalto", "checkpoint"],
    terminal_enabled: true,
    ...overrides,
  };
}
