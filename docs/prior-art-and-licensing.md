# Replicant: Prior Art and Licensing Survey

Prepared: 2026-07-16. Scope: survey existing open-source tools that generate security telemetry or emulate adversaries, so the Replicant project knows what already exists, what it can reuse under permissive licenses (with correct attribution), and precisely what gap it fills.

Replicant (as described in the project brief) is a Python tool that fabricates SAFE, SYNTHETIC firewall / NGFW network-security telemetry in CEF, streams it over syslog to a SIEM (LogRhythm first), and grounds its scenarios in MITRE ATT&CK. It does not execute real attacks, scan real hosts, or run malware. It writes realistic log text so detection engineers can build and validate detection rules when they have no live telemetry.

## Method and verification notes

- Web access was limited to WebSearch and a single web-fetch tool, per instructions. No curl/wget.
- Licenses were verified from the actual `LICENSE` file or the GitHub repository license label wherever the fetch succeeded. Each verified item is marked "(verified)". Anything not directly confirmed is marked `[Unverified]` or `[Inference]`.
- The GitHub API intermittently dropped responses in this environment. Where the JSON API failed, the raw `LICENSE`/`README` file on `raw.githubusercontent.com` was fetched instead, which is equally authoritative.

### Key caveat about the Replicant repository itself

The repository `https://github.com/404SecNotFound/Replicant` returned no content on every attempt (repo page, API, and raw README on both `main` and `master`). Listing the public repositories for the user `404SecNotFound` (id 46477113) returned four repos and **no repository named `Replicant`**:

- `Active-Directory-Pentest-Detection-Pack` (MIT) - 127 Sigma rules mapped to ATT&CK.
- `OpenCTI-Deployment-Toolkit` (MIT).
- `LLM-Pentest-Reliability` (MSc dissertation work, no license set).
- `CyberSecurityCollections` (fork).

[Inference] Replicant is not yet public (private, unpushed, or not yet created). This survey therefore describes Replicant from the project brief, not from published code. The owner's other public work (ATT&CK-mapped Sigma detection packs, SIEM/LogRhythm and detection-engineering focus, MIT licensing) is consistent with the stated Replicant concept and with a permissive open-source release.
Source: https://api.github.com/users/404SecNotFound/repos

---

## Quick comparison matrix

"Safe synthetic" = produces fabricated log text without executing any real attack, scan, or malware. "NGFW CEF over syslog" = emits next-generation-firewall events in CEF, delivered over syslog on demand.

| Tool | Primary purpose | Safe synthetic (no real attack)? | NGFW CEF over syslog? | License (verified) |
|---|---|---|---|---|
| Atomic Red Team | Execute atomic ATT&CK tests on real hosts | No (runs real commands) | No | MIT |
| MITRE / Apache CALDERA | Automated adversary emulation via live agents | No (runs real actions) | No | Apache-2.0 |
| Splunk Attack Range | Build a lab, run attacks, collect/replay data | Partial (runs real tools or replays captured data) | No | Apache-2.0 |
| Splunk Eventgen | Template/token event generator | Yes | No (no ATT&CK, no NGFW CEF out of the box) | Apache-2.0 |
| Datadog Stratus Red Team | Detonate cloud attack techniques | No (real cloud API calls) | No | Apache-2.0 |
| CMU SEI GHOSTS | Simulate realistic user/NPC activity | No (drives real app/network activity) | No | MIT-style (CMU/SEI) |
| flog | Fake common-format log generator | Yes | No (no CEF/firewall/ATT&CK) | MIT |
| AttackGen | LLM-generated IR tabletop scenarios | N/A (produces text scenarios, not logs) | No | GPL-3.0 |
| OTRF Security-Datasets (Mordor) | Pre-recorded attack datasets to replay | No (static captures from real attacks) | No | MIT |
| Endgame/Elastic RTA | Scripts that emulate techniques to produce telemetry | No (runs real scripts) | No | AGPL-3.0 (endgameinc); Elastic License 2.0 (elastic/detection-rules) |
| DetectionLab | Pre-built detection lab infrastructure | No (it is lab infra, not a generator) | No | MIT |
| flowsynth | Compile a flow DSL into pcap/hex packets | Partial (synthetic packets, not syslog/CEF) | No (pcap output) | Apache-2.0 |
| tcpreplay | Replay captured pcap onto a NIC | No (transmits real captured packets) | No | GPL-3.0 |
| Cisco Talos EvidenceForge | Multi-format synthetic security logs from YAML scenarios | Yes | No (batch files; firewall = Cisco ASA syslog, not NGFW CEF) | MIT |
| summved log-generator | Multi-source SIEM log generator w/ ATT&CK chains | Yes | Partial (CEF + firewall + syslog, but generic, not NGFW-accurate) | GPL-3.0 |

---

## Per-tool findings

### 1. Red Canary Atomic Red Team
- URL: https://github.com/redcanaryco/atomic-red-team
- One line: a library of small, portable "atomic" tests that execute individual MITRE ATT&CK techniques.
- Primary purpose: run real technique tests on real endpoints to see whether detections fire.
- Safe synthetic syslog without real attacks: **No.** Atomics execute actual commands on the host to generate genuine telemetry.
- License: **MIT (verified)** from `LICENSE.txt`, "Copyright (c) 2018 Red Canary, Inc." Source: https://github.com/redcanaryco/atomic-red-team/blob/master/LICENSE.txt
- Reuse ideas for Replicant: the per-technique YAML schema is the strongest borrowable pattern. Each atomic is a YAML doc keyed by ATT&CK technique id with `display_name`, `supported_platforms`, `input_arguments` (name, description, type, default), and an `executor` block. Replicant's technique catalog can mirror this shape (ATT&CK id, name, tunable inputs, and one or more CEF templates instead of executors). MIT permits code and schema reuse with attribution.

### 2. MITRE CALDERA (now Apache CALDERA)
- URL: https://github.com/mitre/caldera and https://github.com/apache/caldera ; docs https://caldera.mitre.org
- One line: an automated adversary-emulation platform with a C2 server, agents, and ATT&CK-mapped abilities.
- Primary purpose: chain ATT&CK "abilities" into "adversary" profiles and run them as live "operations" against instrumented hosts.
- Safe synthetic syslog without real attacks: **No.** CALDERA deploys agents that execute real actions.
- License: **Apache-2.0 (verified)** via the `apache/caldera` repository license label (spdx `Apache-2.0`); MITRE contributed CALDERA to the Apache Incubator. Sources: https://api.github.com/repos/apache/caldera , https://www.mitre.org/news-insights/news-release/mitre-contributes-caldera-apache-incubator-expand-open-cybersecurity
- Reuse ideas: the three-layer planning model (ability, adversary profile, operation) is a clean way to structure Replicant scenarios: primitive event templates, a named adversary/campaign that orders them, and a run that emits them with timing. Apache-2.0 is compatible with reusing code in an Apache-2.0 project, with attribution and NOTICE handling.

### 3. Splunk Attack Range
- URL: https://github.com/splunk/attack_range
- One line: tooling to build a small detection lab and run or replay attack data into Splunk.
- Primary purpose: stand up vulnerable hosts, execute attacks (Atomic Red Team, PurpleSharp) or replay pre-recorded `attack_data`, and collect telemetry for detection development.
- Safe synthetic syslog without real attacks: **Partial.** It can replay pre-recorded datasets, but its core workflow runs real attack tooling in a lab. It does not fabricate NGFW CEF on demand.
- License: **Apache-2.0 (verified)** from `LICENSE` on the `develop` branch. Source: https://github.com/splunk/attack_range/blob/develop/LICENSE
- Reuse ideas: the `attack_data` replay concept (curated, labeled datasets replayed into a SIEM) and config-driven scenario selection. Apache-2.0, reusable with attribution.

### 4. Splunk Eventgen (SA-Eventgen)
- URL: https://github.com/splunk/eventgen
- One line: a template- and token-driven event generator for Splunk.
- Primary purpose: replay sample files and substitute tokens (timestamps, random IPs, values from lists) to produce arbitrary volumes of realistic-looking events.
- Safe synthetic syslog without real attacks: **Yes.** It fabricates events from templates and never runs attacks. However, it is not ATT&CK-grounded and ships no NGFW CEF firewall model.
- License: **Apache-2.0 (verified)**; description "Splunk Event Generator: Eventgen", default branch `develop`. Source: https://api.github.com/repos/splunk/eventgen
- Reuse ideas: this is the most directly relevant templating engine. Its token-replacement design (a sample template plus rules for timestamp tokens, random/rotating tokens, and lookup-list tokens, driven by rate/volume config) maps almost one-to-one onto Replicant's need to expand one CEF template into many realistic events. Apache-2.0 allows code reuse with attribution.

### 5. Datadog Stratus Red Team
- URL: https://github.com/DataDog/stratus-red-team ; https://stratus-red-team.cloud
- One line: "granular, actionable adversary emulation for the cloud."
- Primary purpose: detonate self-contained cloud attack techniques (AWS, Azure, GCP, Kubernetes) to validate cloud detections.
- Safe synthetic syslog without real attacks: **No.** It performs real cloud API calls and creates real resources. Cloud-focused, not firewall syslog.
- License: **Apache-2.0 (verified)**. Source: https://api.github.com/repos/DataDog/stratus-red-team
- Reuse ideas: the CLI verb model and packaging of each technique are worth copying at the design level. Stratus wraps each technique with `warmup`, `detonate`, `revert`, `cleanup`, plus embedded metadata and detection notes. Replicant could adopt analogous verbs (for example `list`, `emit`, `stream`, `stop`) and ship per-technique metadata (ATT&CK id, description, expected detection) beside each CEF template. Apache-2.0, reusable with attribution.

### 6. CMU SEI GHOSTS
- URL: https://github.com/cmu-sei/GHOSTS ; https://cmu-sei.github.io/GHOSTS/
- One line: a framework that drives realistic simulated user ("NPC") activity for cyber ranges and exercises.
- Primary purpose: make lab hosts look alive by having simulated users browse, email, and run applications, producing organic host and network telemetry.
- Safe synthetic syslog without real attacks: **No** in the sense relevant to Replicant. GHOSTS generates genuine activity by actually driving applications; it is benign, but it is not fabricated firewall CEF and not an attack tool either.
- License: **MIT-style permissive grant (verified), Carnegie Mellon University / SEI copyright.** GitHub labels it `NOASSERTION`, but the `LICENSE.md` text is a standard MIT permission grant ("free of charge ... to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell") with CMU/SEI copyright, a DoD funding notice, "[DISTRIBUTION STATEMENT A] approved for public release and unlimited distribution", and reference DM18-0429. It is **not** non-commercial and **not** SEI-restricted. Source: https://raw.githubusercontent.com/cmu-sei/GHOSTS/master/LICENSE.md
- Reuse ideas: persona and timeline modeling (how NPCs are scheduled over a day) is a useful reference for making Replicant's baseline "normal" firewall traffic look human. Reuse is allowed with attribution: retain the CMU copyright and permission notice, and preserve the distribution/DM markings if code is copied.

### 7. flog
- URL: https://github.com/mingrammer/flog
- One line: "a fake log generator for common log formats."
- Primary purpose: emit fake Apache (common/combined/error), RFC3164, RFC5424, and JSON log lines at a chosen rate/volume, to stdout or files.
- Safe synthetic syslog without real attacks: **Yes**, but only generic formats. No CEF, no firewall fields, no ATT&CK, and it writes to stdout/files rather than streaming to a network syslog destination.
- License: **MIT (verified)**; topics include `syslog`. Source: https://api.github.com/repos/mingrammer/flog
- Reuse ideas: the small, ergonomic CLI (format + rate + count/interval + output + optional gzip/splitting) is a good template for Replicant's command surface. MIT, reusable with attribution.

### 8. AttackGen (mrwadams)
- URL: https://github.com/mrwadams/attackgen
- One line: an LLM-driven tool that builds tailored incident-response tabletop scenarios from ATT&CK threat-group data.
- Primary purpose: generate narrative IR exercise scenarios, not logs.
- Safe synthetic syslog without real attacks: **Not applicable.** It outputs scenario text, not telemetry, and emits no syslog.
- License: **GPL-3.0 (verified).** Source: https://api.github.com/repos/mrwadams/attackgen
- Reuse ideas: conceptually useful for "pick an ATT&CK group, produce a scenario," which Replicant could echo when composing firewall campaigns. **Do not copy code.** GPL-3.0 is copyleft and incompatible with keeping Replicant under a permissive Apache-2.0/MIT license; take inspiration only (ideas and workflow, not source).

### 9. OTRF Security-Datasets (formerly Mordor)
- URL: https://github.com/OTRF/Security-Datasets
- One line: a curated library of pre-recorded security event datasets captured from executed attacks.
- Primary purpose: provide ready-made, labeled datasets (mostly host/Windows/EDR) to replay for detection research.
- Safe synthetic syslog without real attacks: **No.** The datasets are static captures produced by running real attacks; Replicant's aim is on-demand fabrication, not replay of fixed captures. Coverage is host-centric, not NGFW CEF.
- License: **MIT (verified)**, "Copyright (c) 2021 Open Threat Research Forge." Source: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/LICENSE
- Reuse ideas: the dataset-metadata schema (YAML describing each dataset: ATT&CK mappings, platform, tags, provenance) is a good model for labeling Replicant scenarios. The datasets themselves are a reference corpus of real event field shapes to imitate. MIT, reusable with attribution.

### 10. Elastic / Endgame Red Team Automation (RTA)
- URLs: original https://github.com/endgameinc/RTA ; current home inside https://github.com/elastic/detection-rules (see the `rta` directory).
- One line: a set of Python scripts that emulate ~50 ATT&CK techniques to produce endpoint artifacts and telemetry for detection testing.
- Primary purpose: run scripted technique emulations that create real host activity mapped to ATT&CK.
- Safe synthetic syslog without real attacks: **No.** RTA executes real scripts on the host.
- License: two distinct, both copyleft/restricted:
  - `endgameinc/RTA`: **AGPL-3.0 (verified)** from `LICENSE.txt` ("GNU Affero General Public License ... version 3", "Copyright (C) 2018 info@endgame.com"). Source: https://raw.githubusercontent.com/endgameinc/RTA/master/LICENSE.txt
  - `elastic/detection-rules` (where RTA now lives): **Elastic License 2.0 (verified)** from `LICENSE.txt` (source-available, not OSI open source; prohibits offering the software as a hosted/managed service and prohibits removing the license-key functionality). Source: https://raw.githubusercontent.com/elastic/detection-rules/main/LICENSE.txt
- Reuse ideas: the per-technique Python module layout (one module per ATT&CK technique) is a familiar structure, but **do not copy code** from either location. AGPL-3.0 and Elastic License 2.0 are both incompatible with a permissive Apache-2.0 release. Conceptual inspiration only.

### 11. DetectionLab
- URL: https://github.com/clong/DetectionLab
- One line: automation to build a lab complete with security tooling and logging best practices.
- Primary purpose: provision a ready-instrumented detection lab (Windows domain, Splunk, osquery, Sysmon, Zeek, Suricata) via Packer/Vagrant/Terraform/Ansible.
- Safe synthetic syslog without real attacks: **No.** DetectionLab is infrastructure, not a log generator.
- License: **MIT (verified).** Source: https://api.github.com/repos/clong/DetectionLab
- Reuse ideas: limited for Replicant directly; useful as a target environment to ship logs into during testing. MIT.

### 12. flowsynth (Secureworks)
- URL: https://github.com/secureworks/flowsynth
- One line: "a tool for rapidly modeling network traffic" that compiles a flow-description language into pcap or hexdumps.
- Primary purpose: write a small synth-file describing flows and events, and render it to libpcap-format packets (often to feed Snort/Suricata testing).
- Safe synthetic syslog without real attacks: **Partial.** Output is fabricated packets (no real attack), but it is pcap/hex, not syslog or CEF.
- License: **Apache-2.0 (verified)** from the `LICENSE` file. Source: https://raw.githubusercontent.com/secureworks/flowsynth/master/LICENSE
- Reuse ideas: the compiler architecture is a strong conceptual match for Replicant: a plain-text DSL is parsed into an intermediate timeline of events, then rendered into an output format. Replicant can adopt the same "scenario file to intermediate events to emitter" pipeline, swapping the packet renderer for a CEF/syslog emitter. Apache-2.0, reusable with attribution.

### 13. tcpreplay (AppNeta)
- URL: https://github.com/appneta/tcpreplay
- One line: a suite to replay previously captured pcap traffic onto a network interface.
- Primary purpose: transmit real captured packets (with rate/loop controls) for testing network devices and IDS.
- Safe synthetic syslog without real attacks: **No.** It requires a real capture and sends real packets on the wire; it does not fabricate logs.
- License: **GPL-3.0 (verified)** from `docs/LICENSE` (the author's files are GPLv3; some bundled files carry other licenses and are marked as such). Source: https://raw.githubusercontent.com/appneta/tcpreplay/master/docs/LICENSE
- Reuse ideas: only the replay-timing concepts (packets-per-second, throughput, loop). **Do not copy code**; GPL-3.0 is incompatible with a permissive Replicant.

### 14. Cisco Talos EvidenceForge  (closest broad competitor)
- URL: https://github.com/Cisco-Talos/EvidenceForge ; announcement https://blog.talosintelligence.com/introducing-evidenceforge-synthetic-security-logs-that-dont-look-as-fake/
- One line: "generate realistic synthetic security logs for cybersecurity threat hunting training and research."
- Primary purpose: from a YAML scenario (environment, personas, optional attack storyline), deterministically generate temporally consistent multi-format logs written to an output directory, plus a `GROUND_TRUTH.md`.
- Safe synthetic syslog without real attacks: **Yes.** Generation is fully deterministic with no LLM calls at generation time and no real attack execution. It is ATT&CK-grounded at the scenario-authoring stage (TTP research via agent skills).
- Firewall / NGFW CEF over syslog: **No.** Its outputs are batch dataset files across ~20 formats (Windows Security, Sysmon, 13 Zeek types, eCAR EDR/XDR, syslog RFC3164/5424, bash history, Snort, web access, HTTP proxy, and a Cisco ASA emitter). The only firewall coverage is **Cisco ASA syslog**, not next-generation-firewall CEF, and there is no live syslog streaming to a SIEM such as LogRhythm.
- License: **MIT (verified)**, "Copyright (c) 2026 Cisco Systems, Inc." (README license badge and License section). Source: https://raw.githubusercontent.com/Cisco-Talos/EvidenceForge/main/README.md
- Reuse ideas (richest of any tool here, and MIT so reusable with attribution):
  - Canonical event model: a single `SecurityEvent` object is the one source of truth feeding every emitter, so two formats cannot disagree about a port or timestamp. Replicant should keep one internal event object that renders to CEF (and later other formats).
  - Jinja2 templates per output format, which fits Replicant's CEF-template approach.
  - Causal ordering rules (DNS precedes connection, Kerberos precedes logon) and realistic timing (Hawkes-process bursts, day-of-week variation) to defeat the "uniform random timing" tell.
  - Ground-truth documentation generated per run (what happened, when, IOCs) and baseline-only runs that explicitly record "no malicious events."
  - A four-pillar quality rubric (parseability, plausibility, causality, timing; 20 sub-scores with hard gates) that Replicant can adapt to score CEF fidelity and LogRhythm parseability.
  - YAML scenario schema (environment, personas, time_window, baseline_activity, storyline, output) as a model for Replicant scenario files.
- Note: EvidenceForge also ships a "Research Report: analysis of existing tools" design doc (`docs/design/synthetic-log-generation-research.md`), which is itself a prior-art survey worth reading before finalizing Replicant's design.

### 15. summved log-generator  (closest capability match)
- URL: https://github.com/summved/log-generator
- One line: a Node.js/TypeScript "enterprise SIEM log generator" with MITRE ATT&CK integration and multi-stage attack chains.
- Primary purpose: generate realistic multi-source logs (12+ sources including Firewall) and stream them to SIEMs for rule testing and training.
- Safe synthetic syslog without real attacks: **Yes.** It fabricates logs; attack "chains" are scripted log sequences, not real exploitation.
- Firewall / NGFW CEF over syslog: **Partial and important.** It supports **CEF** output and **Syslog (RFC3164/5424)** and HTTP transport, streams on demand to Splunk/ELK/Wazuh/QRadar/Sentinel, includes a **Firewall** source, and maps events to ATT&CK techniques and attack chains (APT29, Ransomware, Insider). This is the single closest tool to Replicant's stated capability. Its shortfalls: firewall is one generic source among a dozen (not a high-fidelity NGFW vendor schema), it is not tuned to LogRhythm parsing/MPE, and it is GPL-3.0.
- License: **GPL-3.0 (verified)** from README license badge and License section. Source: https://raw.githubusercontent.com/summved/log-generator/main/README.md
- Reuse ideas: excellent conceptual reference for CLI surface (`--mitre-technique`, attack-chain execution, `--mode syslog|http`), SIEM transport design, and performance patterns (worker threads, memory buffer, batch). **Do not copy code**; GPL-3.0 is incompatible with a permissive Replicant. Inspiration only.

### Adjacent / minor tools (lighter review)

These surfaced in open-ended searches and are relevant context. Licenses here are `[Unverified]` unless stated.

- Azure Sentinel "Syslog-cef-data-replicator" - Python console app that replays user-supplied sample events as Syslog/CEF toward a collector. It replays events you provide; it does not fabricate ATT&CK-grounded firewall events. Repo `Azure/Azure-Sentinel` is MIT `[Inference: repo-level license]`. Source: https://github.com/Azure/Azure-Sentinel/blob/master/Tools/Syslog-cef-data-replicator/README.md
- jamesfed/PANOSSyslogCEF - a Palo Alto PAN-OS syslog template that formats NGFW logs as CEF. It is a device-side template, not a generator, but it is a useful reference for real NGFW-to-CEF field mappings. `[Unverified]` license. Source: https://github.com/jamesfed/PANOSSyslogCEF
- kfortney/fakelogit - fake log generator noted to include Palo Alto and Fidelis CEF formats. `[Unverified]` license. Source: https://github.com/kfortney/fakelogit
- Aiz9/Fake-log-generators - Python scripts generating Syslog/CEF/JSON security-like events. `[Unverified]` license. Source: https://github.com/Aiz9/Fake-log-generators
- openobserve/syslog_log_generator - a synthetic syslog log generator. `[Unverified]` license. Source: https://github.com/openobserve/syslog_log_generator
- Microsoft Security blog: AI-assisted synthetic attack-log generation for detection engineering. A method/write-up rather than a reusable permissive tool. Source: https://www.microsoft.com/en-us/security/blog/2026/05/12/accelerating-detection-engineering-using-ai-assisted-synthetic-attack-logs-generation/

---

## 1. Gap analysis

Claim under test: "no existing tool provides safe, on-demand, ATT&CK-grounded synthetic NGFW CEF telemetry over syslog for detection building."

Verdict: **Refuted as an absolute, but confirmed for the specific niche Replicant targets.** At least one tool (summved log-generator) already emits synthetic CEF firewall logs over syslog with ATT&CK mapping on demand, and Cisco Talos EvidenceForge already produces safe, deterministic, ATT&CK-grounded synthetic logs (including syslog and a Cisco ASA firewall emitter). So Replicant is not the first tool in this general space, and the survey should not claim outright novelty. What no tool does is deliver the full combination Replicant is aiming for. Be precise about how the closest tools fall short:

- **summved log-generator** (GPL-3.0, Node/TypeScript): the closest by feature list. It streams CEF over syslog, includes a firewall source, and runs ATT&CK-mapped attack chains. But firewall is one generic source among 12+, the CEF is not modeled on a specific real NGFW vendor schema (for example FortiGate or Palo Alto field-for-field), it is not tuned to LogRhythm's parser/MPE, and it is GPL-3.0, so its code cannot be reused in an Apache-2.0 project. It is a strong conceptual benchmark, not a foundation Replicant can build on legally.
- **Cisco Talos EvidenceForge** (MIT, Python): the strongest engine for consistency, causal ordering, timing realism, ground-truth, and quality scoring, and it is permissively licensed. But it writes batch dataset files rather than streaming live syslog to a SIEM on demand, it is host-centric (Windows/Sysmon/Zeek/EDR), and its only firewall output is Cisco ASA syslog, not NGFW CEF. It solves "realistic dataset on disk," not "live NGFW CEF stream into LogRhythm."
- **Splunk Eventgen and flog** are safe synthetic generators with no attack execution, but neither is ATT&CK-grounded and neither ships an NGFW CEF firewall model. They provide the templating mechanics, not the firewall/ATT&CK content.
- **Atomic Red Team, CALDERA, Stratus Red Team, Endgame/Elastic RTA** all run real actions to produce telemetry. They are the opposite of "safe fabricated logs." They are also not firewall-CEF focused.
- **Splunk Attack Range, DetectionLab** are lab/orchestration infrastructure; **OTRF Security-Datasets/Mordor** is static pre-captured data. None fabricate NGFW CEF over syslog on demand.
- **flowsynth and tcpreplay** operate at the packet/pcap layer, not the syslog/CEF log layer.

The defensible, specific gap Replicant fills: a **safe, permissively licensed, Python, on-demand generator whose primary and high-fidelity focus is next-generation-firewall telemetry in CEF, streamed live over syslog to a SIEM (LogRhythm first), driven by an ATT&CK-grounded firewall technique catalog, with the CEF modeled on a real NGFW vendor schema and validated against the target SIEM's parser.** No surveyed tool occupies that exact position. The nearest permissive tool (EvidenceForge) does not stream NGFW CEF over syslog; the nearest CEF-over-syslog tool (summved) is generic and GPL-3.0.

Positioning recommendation: describe Replicant as firewall/NGFW-specialized, LogRhythm-first, and streaming (live syslog), not as "the first synthetic log generator." Differentiate on NGFW CEF fidelity, LogRhythm parser alignment, a firewall-centric ATT&CK technique catalog, safe-by-design fabrication, and a permissive license.

---

## 2. Licensing and reuse

### Reuse decision table

"Reuse code into Apache-2.0 Replicant?" answers whether source code may be copied/adapted into a permissively licensed (Apache-2.0) Replicant. Ideas and public interfaces are never copyrightable; this column is about copying source.

| Tool | License (verified unless noted) | Reuse code into Apache-2.0 Replicant? | Attribution required? |
|---|---|---|---|
| Atomic Red Team | MIT | Yes | Yes (retain MIT notice / copyright) |
| CALDERA (apache/mitre) | Apache-2.0 | Yes | Yes (retain notices; propagate NOTICE) |
| Splunk Attack Range | Apache-2.0 | Yes | Yes (retain notices / NOTICE) |
| Splunk Eventgen | Apache-2.0 | Yes | Yes (retain notices / NOTICE) |
| Datadog Stratus Red Team | Apache-2.0 | Yes | Yes (retain notices / NOTICE) |
| CMU SEI GHOSTS | MIT-style (CMU/SEI), verified | Yes | Yes (retain CMU copyright + permission notice + DM18-0429 / distribution statement) |
| flog | MIT | Yes | Yes (retain MIT notice) |
| AttackGen | GPL-3.0 | No | Inspiration only; do not copy code |
| OTRF Security-Datasets (Mordor) | MIT | Yes | Yes (retain MIT notice) |
| Endgame RTA | AGPL-3.0 | No | Inspiration only; do not copy code |
| Elastic detection-rules (RTA) | Elastic License 2.0 | No (source-available, use restrictions) | N/A; do not copy code |
| DetectionLab | MIT | Yes | Yes (retain MIT notice) |
| flowsynth | Apache-2.0 | Yes | Yes (retain notices / NOTICE) |
| tcpreplay | GPL-3.0 | No | Inspiration only; do not copy code |
| Cisco Talos EvidenceForge | MIT | Yes | Yes (retain MIT notice) |
| summved log-generator | GPL-3.0 | No | Inspiration only; do not copy code |

### Licenses to avoid copying code from (hard rule for an Apache-2.0 project)

- **AGPL-3.0: `endgameinc/RTA`.** Strongest copyleft, with a network-use clause. Copying any of its code would force Replicant to become AGPL. Do not copy.
- **GPL-3.0: AttackGen, summved/log-generator, tcpreplay.** Copyleft; copying code would force Replicant to GPL and is incompatible with Apache-2.0/MIT. Do not copy. Ideas, workflows, and CLI concepts are fine to be inspired by; source is not.
- **Elastic License 2.0: `elastic/detection-rules` (the current RTA home).** Source-available, not OSI open source. It forbids providing the software as a hosted/managed service and forbids disabling license-key functionality. Do not copy code into Replicant.
- **Clarification on "SEI-restricted":** GHOSTS is often assumed to carry a restrictive SEI license. It does not. Its `LICENSE.md` is a permissive MIT-style grant with CMU/SEI copyright and a public-release distribution statement, so it is safe to reuse with attribution. Preserve the CMU copyright line, the permission notice, and the DM/distribution markings if you copy code.

Permissive and safe to reuse (MIT / Apache-2.0 / BSD-style), all compatible with an Apache-2.0 Replicant provided notices are retained: Atomic Red Team, CALDERA, Splunk Attack Range, Splunk Eventgen, Stratus Red Team, GHOSTS, flog, Security-Datasets, DetectionLab, flowsynth, EvidenceForge.

### How to credit (recommended mechanics)

- Keep a `NOTICE` file and/or a `THIRD_PARTY_NOTICES.md` in the Replicant repo. For each reused component list: component name, source URL, copyright line, and license (with a copy of the license text in a `licenses/` directory).
- For **MIT** components: reproduce the original copyright line and the MIT permission notice.
- For **Apache-2.0** components: retain copyright, patent, trademark, and attribution notices; if the upstream ships a `NOTICE` file, include the relevant parts in Replicant's `NOTICE`; mark any files you modify as changed.
- For **GHOSTS (CMU/SEI)**: additionally preserve the CMU copyright ("Copyright 2017-2026 Carnegie Mellon University"), the permission notice, and the distribution/DM markings if code is copied.
- Even where you only take design inspiration (CALDERA planning model, Stratus CLI verbs, EvidenceForge canonical-event and quality-scoring patterns, summved CLI surface), a short "Acknowledgements" section naming those projects is good practice and costs nothing.

### MITRE ATT&CK usage and attribution

- ATT&CK is free to use for research, development, and commercial purposes under the MITRE ATT&CK Terms of Use. The license text: "The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy." (verified). Source: https://attack.mitre.org/resources/legal-and-branding/terms-of-use
- Required attribution string to include wherever ATT&CK content is reproduced (technique ids, names, tactic mappings): **"© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."** Update the year to match the ATT&CK version/content you ship.
- Trademarks: "MITRE ATT&CK" and "ATT&CK" are registered trademarks of The MITRE Corporation. Use them to refer to the framework, do not imply MITRE endorsement of Replicant, and follow the ATT&CK FAQ branding guidance.
- Practical placement: put the attribution string in the README, in a `NOTICE`/`ATTRIBUTION` file, and ideally in the header/comments of the technique-catalog file that carries ATT&CK ids. The ATT&CK STIX data (in `mitre-attack/attack-stix-data`) is provided under the same Terms of Use; if Replicant bundles or derives from that data, ship the attribution alongside it.

---

## 3. Firewall vendor names, formats, and documentation

Added 2026-07-29. Sections 1 and 2 cover the open-source prior art and MITRE
ATT&CK. They said nothing about the firewall vendors whose log formats Replicant
actually emulates, which was a gap: the question "do we have permission from the
vendors to do this?" had no answer in the repository. This section answers it.

**Not legal advice.** This is an engineering assessment of where the exposure is
and what has been done about it. A public release connected to an employer, or
use in customer delivery, is a different risk profile and warrants counsel.

### 3.1 What Replicant actually uses

| Thing used | What it is | Assessment |
|---|---|---|
| `Fortinet`, `Palo Alto Networks`, `Check Point` in CEF headers | Word marks, as field values | Required by the format. A CEF record identifies its device vendor and product; there is no way to emit a FortiGate-shaped record without the string `Fortinet`. Purely identifying, no logos, no stylized marks, no affiliation claim. |
| Field names (`FTNTFGTlogid`, `deviceInboundInterface`, `dpt`) | Wire-format identifiers | Functional. Short names and a field ordering are not creative expression. |
| Log IDs and signature IDs (`0000000013`, `54802`, `39426`) | Numeric identifiers | Facts. |
| Severity mapping rules | Documented behaviour | Facts about how the product behaves. |
| Vendor documentation pages | Public docs, cited per file | Read and implemented against, which is ordinary interoperability work. The exposure would be reproducing substantial portions, not reading them. |
| CEF itself | ArcSight format, now Open Text | `[Unverified]` current distribution terms of the CEF specification. Replicant implements the format from vendor mapping documentation rather than from the ArcSight spec document. |

No vendor logos, icons, or brand assets exist anywhere in the repository
(verified: no vendor image files, and the only images are Replicant's own
screenshots). No text claims partnership, certification, endorsement, or
approval (verified by grep).

### 3.2 The `[Constructed]` claim, verified

Every sample line in the vendor reference docs, and every golden line in the test
suite, is marked `[Constructed]`: assembled from documented field and format
rules rather than copied from the vendors' published examples. The whole
copyright posture rests on that being true, and until 2026-07-29 it was asserted
rather than checked. It has now been checked against Fortinet's own published CEF
examples.

Fortinet's `traffic:forward` example (FortiOS 7.4.3 docs) against Replicant's:

| Field | Fortinet's published example | Replicant golden line |
|---|---|---|
| Header | `CEF: 0\|` (with a space) | `CEF:0\|` (no space, per the CEF spec) |
| Device serial | `FGT5HD3915800610` | `FGVMSYNTH0000001` |
| Hostname | `FGT-A-LOG` | `FGT-LAB-01` |
| Version / action | `v6.0.3`, `close` | `v7.4.3`, `accept` |
| Virtual domain | `vdom1` | `root` |
| Source | `10.1.100.11:54190` | `10.20.30.40:51544` |
| **Destination** | **`52.53.140.235`** (a real, routable address) | **`203.0.113.25`** (IANA documentation range) |
| Bytes | `3652` / `146668` | `8421` / `61325` |

And across the other record types:

| | Fortinet's example | Replicant |
|---|---|---|
| DNS qname | `detectportal.firefox.com` (a real domain) | `updates.example.net` (IANA documentation domain) |
| DNS resolved IPs | `104.80.89.26, 104.80.89.24` (real) | absent, or `.invalid` for the NXDOMAIN case |
| IPS attack / id | `Eicar.Virus.Test.File` / `29844` | `Apache.Struts.OGNL.Remote.Code.Execution` / `40449` |
| IPS request path | `/virus/eicar.com` | `/struts2/index.action` |
| User, MAC | `bob`, `a2:e9:00:ec:40:01` | absent |

**Conclusion: constructed, not copied.** Three things establish it beyond the
values simply differing:

1. **Every value differs.** Not one field carries Fortinet's sample data through.
2. **The header spacing diverges.** Fortinet's documentation prints `CEF: 0|`
   with a space after the colon; Replicant emits `CEF:0|` per the CEF
   specification. A verbatim copy would have carried the space through. This is
   the cleanest single piece of evidence that the lines were built from the rules
   rather than transcribed.
3. **Real-world values were systematically replaced with documentation-range
   equivalents.** Fortinet's examples use a live AWS address, a real Mozilla
   domain, and real resolved IPs. Replicant substitutes `203.0.113.0/24`,
   `example.net`, and `.invalid` throughout. That substitution is the opposite of
   copying, and it falls directly out of safety rule 2.

What legitimately *does* match is the field ordering and the `FTNTFGT` prefixing.
That is the wire format. Matching it is the entire point of the tool, and it is
functional rather than expressive.

One item to keep in view: `FTNTFGTattack=Apache.Struts.OGNL.Remote.Code.Execution`
is a vendor signature name used as a factual identifier in emitted output. It is
not drawn from the Fortinet example above (which uses the EICAR test signature).
`[Unverified]` whether that string matches a real Fortinet IPS signature name
exactly.

### 3.3 What was done, and what is left

Done:

- `NOTICE` gained a trademark and non-affiliation section naming each vendor.
- The README states the non-affiliation position and links to this section.
- The `[Constructed]` claim is verified above rather than asserted.

Open, and worth a decision before any public release:

- `[Unverified]` the current distribution terms of the ArcSight/Open Text CEF
  specification. Replicant implements from vendor mapping docs, not from the
  spec document, which is the safer route, but the terms have not been read.
- The three vendor reference documents under `docs/` are derived works from
  vendor documentation. The sample lines are cleared above; the **field-mapping
  tables** have not been reviewed for how closely they track their sources in
  structure and wording. That is the remaining copyright surface.
- Whether any of this changes if Replicant is published under, or used in
  connection with, an employer's name. That is a question for counsel, not for
  this document.

---

## Sources

- Replicant owner repos: https://api.github.com/users/404SecNotFound/repos
- Atomic Red Team license: https://github.com/redcanaryco/atomic-red-team/blob/master/LICENSE.txt
- CALDERA (Apache): https://api.github.com/repos/apache/caldera ; https://www.mitre.org/news-insights/news-release/mitre-contributes-caldera-apache-incubator-expand-open-cybersecurity
- Splunk Attack Range license: https://github.com/splunk/attack_range/blob/develop/LICENSE
- Splunk Eventgen: https://api.github.com/repos/splunk/eventgen
- Datadog Stratus Red Team: https://api.github.com/repos/DataDog/stratus-red-team
- GHOSTS license: https://raw.githubusercontent.com/cmu-sei/GHOSTS/master/LICENSE.md
- flog: https://api.github.com/repos/mingrammer/flog
- AttackGen: https://api.github.com/repos/mrwadams/attackgen
- OTRF Security-Datasets license: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/LICENSE
- Endgame RTA license (AGPL-3.0): https://raw.githubusercontent.com/endgameinc/RTA/master/LICENSE.txt
- Elastic detection-rules license (Elastic License 2.0): https://raw.githubusercontent.com/elastic/detection-rules/main/LICENSE.txt
- DetectionLab: https://api.github.com/repos/clong/DetectionLab
- flowsynth license (Apache-2.0): https://raw.githubusercontent.com/secureworks/flowsynth/master/LICENSE
- tcpreplay license (GPL-3.0): https://raw.githubusercontent.com/appneta/tcpreplay/master/docs/LICENSE
- Cisco Talos EvidenceForge (MIT, capabilities): https://raw.githubusercontent.com/Cisco-Talos/EvidenceForge/main/README.md ; https://blog.talosintelligence.com/introducing-evidenceforge-synthetic-security-logs-that-dont-look-as-fake/
- summved log-generator (GPL-3.0, capabilities): https://raw.githubusercontent.com/summved/log-generator/main/README.md
- MITRE ATT&CK Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use
- Adjacent tools: https://github.com/Azure/Azure-Sentinel/blob/master/Tools/Syslog-cef-data-replicator/README.md ; https://github.com/jamesfed/PANOSSyslogCEF ; https://github.com/kfortney/fakelogit ; https://github.com/Aiz9/Fake-log-generators ; https://github.com/openobserve/syslog_log_generator
