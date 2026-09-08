# Run manifest contract

This document defines the runtime contract for individual `RunManifest` and
`ScenarioManifest` JSON records. A manifest is execution and audit evidence. It
does not by itself prove that a person authorized the run or that a collector
received the events.

## Lifecycle

Request validation and deterministic planning happen first. An invalid request
or a planning failure produces no output and no manifest. Once planning succeeds,
the lifecycle is:

1. **Preflight.** Replicant exclusively creates a unique manifest with
   `status="running"` before it opens a collector socket or output file. The
   rendered-event count starts at zero, `planned_event_count` is the completed
   plan size, `ended_at` is `null`, and `updated_at` equals `started_at`. For a
   non-empty plan, `partial` starts as `true`. If this durable create fails, no
   telemetry is sent or written.
2. **Checkpoint.** A CEF record is counted immediately after rendering and before
   an event callback, file write, or collector send observes it. Replicant
   coalesces manifest replacements to about once per second. It also flushes dirty
   progress before a plan-paced wait that would carry the durable record beyond
   that cadence. Each checkpoint keeps `status="running"`, advances `updated_at`,
   and recalculates `partial`.
3. **Terminal replacement.** A handled completion, kill-switch stop, or emission
   error atomically replaces the same path with the exact in-memory count,
   `ended_at`, `updated_at`, terminal `status`, `partial`, and any bounded error
   description. An emission error is recorded and then re-raised unchanged. If
   finalization itself fails, the last confirmed durable record remains the audit
   baseline and the raised exception carries both that record and the later
   in-memory count.

A process or power interruption can leave `status="running"` with `ended_at=null`.
That non-terminal state is the crash signal. It does not follow that `partial`
must be true: all planned records may have rendered immediately before the
terminal replacement failed.

## Count semantics

| Field | Meaning |
|---|---|
| `planned_event_count` | Number of records in the completed plan before output begins. |
| `event_count` | Individual-run CEF records rendered so far. |
| `total_event_count` | Scenario-run CEF records rendered so far. |
| `partial` | `true` exactly when the rendered count is below `planned_event_count`. |
| `send_stats` | Individual-run socket statistics, or `null` when there was no collector. |

Rendered is deliberately not a synonym for sent or received. A record can render,
then encounter a callback, file, or transport failure. For an individual live
run, `send_stats.sends` counts records the emitter handed to the kernel;
`send_stats.bytes`, `errors`, and `oversize` describe that socket activity. UDP
handoff does not confirm collector receipt. Scenario manifests currently do not
carry `send_stats`.

`status` and `partial` answer different questions:

| `status` | Meaning |
|---|---|
| `running` | No terminal manifest replacement completed. |
| `done` | The orchestrator completed normally. |
| `stopped` | The kill switch ended the run. |
| `error` | Emission raised an error that was recorded before it was re-raised. |

An `error` record can have `partial=false` when all planned records rendered but a
later destination operation failed. A `running` record can also have
`partial=false` when all records rendered but finalization did not complete.

## Rate semantics

`Settings.eps_cap` is a positive hard ceiling for collector sends. A positive
per-run `--rate` or API rate may lower that ceiling but cannot raise it. Values
above the configured cap are rejected during request preflight.

The manifest `rate` field records the effective sending ceiling only when a
collector emitter is active. It is `null` for dry renders and file-only runs,
because those paths are unthrottled. A live run that also mirrors records with
`--to-file` is still a sending run, records the effective rate, and acquires the
host send lock. The send lock permits one collector-sending run per host and user;
it does not coordinate separate hosts aimed at the same collector.

## Durable publication

Replicant never updates manifest JSON in place:

- Initial publication writes and fsyncs a same-directory temporary file, links
  it to an unused final name with exclusive-create semantics, removes the
  temporary name, and fsyncs the parent directory.
- Checkpoints and terminal records write and fsync a new same-directory temporary
  file, atomically replace the established path, and fsync the parent directory.
- Newly created directory components are made from the top down and their parent
  entries are fsynced before the manifest is published.
- Readers therefore see either the previous complete JSON document or the next
  complete JSON document, never an in-place partial write.

The guarantee depends on the operating system and storage stack honoring file
and directory `fsync`. Replicant refuses known unsupported directory-fsync
platforms and filesystems during preflight rather than silently claiming the
stronger guarantee. It cannot detect storage hardware or mount configurations
that report successful flushes without honoring them.

## Scenario advisory relationship

The scenario manifest follows the same preflight, checkpoint, and terminal
lifecycle. Its deterministic coverage data is present in the initial manifest.
The separate advisory Markdown file is written only after emission and manifest
finalization return without an emission error, including a handled stop. An error
manifest is therefore guaranteed when finalization succeeds; a paired advisory
is not.

## Validation evidence relationship

Tier 0 and Tier 1 validation runs use the same individual-run manifest lifecycle.
The manifest remains execution evidence only. Validation then writes a separate
bounded directory under `evidence/<run-id>/` containing the resolved contract,
validation result, observed telemetry sample, derived renderer mapping, report,
and replay recipe.

For Tier 0, `send_stats` is `null` and the report opening states that no collector
was configured. For Tier 1, `send_stats` describes handoff to the loopback
receiver only. Neither state proves a live collector accepted the records or a
SIEM rule fired. See [offline detection validation](offline-detection-validation.md)
for the eight-file evidence contract and replay semantics.
