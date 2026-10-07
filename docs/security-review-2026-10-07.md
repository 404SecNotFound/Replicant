# Security review response, 2026-10-07

## Scope

An adversarial review of the whole repository at commit `ef97905`, run after the
three earlier reviews (2026-08, 2026-09-08, 2026-09-26) were closed. It covered
the web layer, the send path, the lock, the configuration boundary, the systemd
unit, the container image, the CI workflows and the frontend dependency tree,
and it was explicitly scoped to find what those reviews had not: nothing below
re-reports a closed item. Each finding was reproduced before it was acted on.
The catalog half of the same review, which measured the 26 techniques against
their own catalog text, is recorded separately in
`catalog-review-2026-10-07.md`.

The full suite at the reviewed head was 2099 passed, 3 skipped, 0 failed, with
ruff, black and mypy clean. That is stated because the headline finding below
sat inside a function with its own passing tests.

## Findings and disposition

| ID | Severity | Finding | Disposition |
|---|---:|---|---|
| N-01 | Medium | The duration parser's whole-string check, `(?:\d+\s*[smhd]?\s*)+`, had every optional part able to match empty, so a non-matching tail backtracked through 2^N splits of an N-digit run. Measured on the unfixed code: 0.3 s at 22 digits, 1.2 s at 24, 5.0 s at 26, quadrupling per two digits, so about 80 minutes at 36 and a day at 40. Reachable by one authenticated 40 byte `POST /api/plan` or `/api/runs`, by the confined web terminal's duration prompt, and by `--duration`. The 64 KiB body cap and pre-body authentication did not help, because the payload is small and authenticated. | Fixed. `parse_duration` scans tokens with `match` from the end of the previous token, which is linear, and raises on the first byte that belongs to no token. Accepted and rejected inputs are unchanged and the existing table of both still passes. Guard: `tests/test_review_2026_10_07.py`, forty digits under a one second budget, at the parser and at the `RunRequest` boundary. Positive control: on the unfixed code the guard had to be killed at 30 s. |
| N-02 | Low | `RunBody.duration` had no validator, so a malformed duration raised inside the handler and `/api/plan` and `/api/runs` answered 500 with a traceback on stderr. | Fixed. The same validator the CLI and menu models use is attached to `RunBody`, so the answer is 422 naming the field. |
| N-03 | Low | A basename over NAME_MAX made `Path.resolve` raise ENAMETOOLONG out of `confined_output_path`, a 500 from the API and a traceback in the menu's output prompt loop, which catches only `ConfinementError`. | Fixed. The helper bounds the name at 255 bytes and turns any `OSError` from the lookup into a `ConfinementError`, so every refusal has the same shape. |
| N-04 | Low | The terminal bridge keyed its per-client cap on `session:<cookie value>` and logged the key when it refused a session. The browser session id, a 12 hour bearer credential, therefore reached the log ring, `GET /api/logs`, the SSE log stream and the journal under systemd. The redactor masked only `token=` shapes. | Fixed. The key is a SHA-256 digest prefix of the session id, still stable per session, and the redactor also masks `replicant_session=` and `session:` followed by a credential-length value as a backstop. |
| N-05 | Low | `MAX_FRAME_BYTES` (64 KiB) was checked after a terminal frame was received, by which point uvicorn had buffered up to its 16 MiB default. Authenticated and capped at four sessions, so about 64 MiB, but the body-cap reasoning (bound before read) had not been applied to the websocket. | Fixed. `uvicorn_config` passes `ws_max_size=MAX_FRAME_BYTES` and a small `ws_max_queue`. |
| N-06 | Low, label | README said one sending run per host is enforced. The lock lives under `REPLICANT_CONFIG_DIR`; the shipped unit sets its own, so a service run and an operator CLI run on the same host both send at twice the cap. The module docstring and the 2026-08 record already said per user; the README and the unit did not. | Fixed as a label. README, the unit comments and `CLAUDE.md` rule 4 now say per configuration directory and how to make one cap cover both. A fixed per-host lock path was considered and declined: it would need a world-writable directory or a privileged one, and the per-directory scope is the one the code actually keeps. |
| N-07 | Low, build-time | `npm audit` reports 8 advisories (6 high, 2 moderate) in the frontend's development tree: braces, micromatch, fast-glob, chokidar, source-map-js, postcss-selector-parser, postcss-nested, all reached through tailwindcss 3.4.x. `npm audit --omit=dev` is zero, so nothing shipped in the wheel is affected. The 2026-08 F-14 "zero advisories" claim no longer holds. | **Open, disclosed.** The only fix npm offers is tailwindcss 4, a major toolchain migration (configuration format, the type-scale rungs that `cn()` must know, the design contract in `docs/webui-factory-design.md`). That is a UI change of its own and is not bundled into a security closeout. Tracked in `CHANGELOG.md` under Unreleased. |
| N-08 | Info | `/api/health` is unauthenticated and discloses the version; run responses carry absolute manifest and output paths. Authenticated and by design. | Noted, no change. |
| N-09 | Info | The session cookie's `Secure` flag follows `request.url.scheme`; behind a TLS proxy with proxy headers off (the default) it is never set. Mitigated by `SameSite=Strict` and `httpOnly`. [Inference] | Documented here: `--forwarded-allow-ips` naming the proxy is what turns `Secure` on. |
| N-10 | Info | Tier 1 ingest validation sends to a receiver Replicant binds on `127.0.0.1:0`, which accepts records from any local process, so a local user could forge a validation PASS. Rule 1 holds: the bind is loopback and the send goes only to that socket. | Noted, no change. A local user who can write to the loopback socket can also edit the evidence pack. |
| N-11 | Info | A `duration` of `100000d` keeps the single build slot busy for about 17 s on REP-012; the engine's 200,000 event cap bounds memory for all techniques. | Noted. One authenticated caller can turn plan pricing into 503s for others for that long; the admission timeout and build gate from the 2026-09-26 review already bound the damage. |

## Related change: scenarios can carry their foils

Not a security finding, recorded here because it came out of the same review.
`compose()` dropped every negative-control event, so a scenario run was
attack-only: the one condition the catalog header says lets any detection score
perfectly. `--controls {positive,both,negative}` now exists on
`replicant scenario run` with `positive` as the default, so every existing run,
manifest and advisory means what it meant. `both` composes each foil-emitting
stage's foil onto the same timeline; stage statistics and the advisory describe
the attack stream only; the manifest records `controls` and
`negative_event_count`. Guard: `tests/test_scenario_controls.py`. The web UI does
not run scenarios, so it is unaffected.

## Checked and found sound

- **Rule 1.** Every `socket()` and `getaddrinfo` in `replicant/` is on the
  configured collector, the loopback validation receiver (bind `127.0.0.1:0`,
  never `0.0.0.0`), or the server's own listener. No `urlopen`, `requests` or
  `httpx` at runtime. Fail-closed holds: a send with no collector and no file
  raises before any output, and an empty host is rejected at the model.
- **Authentication and CSRF.** Token compared with `compare_digest` on bytes.
  Every mutating route (`/api/validate`, `/api/connect/test`,
  `/api/run-admissions`, `/api/plan`, `/api/runs`, `/api/runs/{id}/stop`,
  `/api/session/logout`, `PUT /api/logs/level`) requires the token and, when
  cookie-authenticated, a matching `Origin`. Unauthenticated `/api` writes are
  answered 401 before the body is read. The terminal websocket repeats the
  policy, Host, credential and Origin checks inline. `--no-auth` refuses a
  non-loopback bind without the acknowledgement flag.
- **Open redirect.** `/\evil.example?token=x` becomes `Location: /%5Cevil.example`
  and `//evil/?token=x` becomes `/`.
- **Paths.** `/api/evidence/{id}` with encoded slash and dot-dot variants is a
  404; docs are served from a fixed allowlist; `confined_output_path` rejects a
  symlink before resolving; `confined_cafile` requires a regular, non-symlinked
  file directly inside `ca/`; `evidence/pack.py` only writes ZIPs.
- **Input.** No `subprocess`, `eval`, `exec` or `pickle`; only `yaml.safe_load`
  and `safe_dump`. A seed of 10^40 and an anchor of 10^20 are handled. The
  terminal child is an `execve` of a fixed argv with an allow-listed environment
  and `REPLICANT_WEB_CONFINED=1`, which the menu honours for output, CA file and
  profile save, and the Rich prompts offer no shell escape.
- **TLS.** `create_default_context` gives TLS 1.2 minimum, hostname checking
  and `CERT_REQUIRED`; `tls_verify=False` is explicit and reported in the probe.
- **Resource bounds.** Body 64 KiB, one validation at a time and never beside a
  run, build gate of one plus four waiters, 16 streams, 4 terminal sessions,
  admission TTL, evidence pruning, engine cap of 200,000 events (checked across
  all techniques at `duration=100000d`).
- **Send lock.** `flock` with the pid; a real second process in the same
  configuration directory is refused; web runs, scenario runs and ingest
  validation all acquire it.
- **Unit, CI, container.** `ProtectSystem=strict` with minimal `ReadWritePaths`,
  no capabilities, `MemoryMax`, token kept out of the journal; CI has
  `permissions: contents: read` and no `pull_request_target`; the image runs as
  uid 10001 with no web extra. The installer's self-test sends to 127.0.0.1 only.

## The lesson

The suite was green, the three prior reviews were closed, and the worst finding
was a one-line regular expression with its own passing tests. Its tests fed it
well-formed and malformed strings and asserted the verdicts, which were all
correct. Nothing asserted how long a verdict could take. **A guard that checks
the answer and not the cost has not bounded the cost**, which is the body-cap
lesson of 2026-09-26 again, one layer down: that review bounded what the server
would read, and this one bounds what it will do with eight bytes of it.
