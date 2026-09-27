# Security review response, 2026-09-26

## Scope

This record covers the **web layer** findings of the 2026-09-26 review: the
FastAPI server, the embedded terminal bridge, and the systemd unit that runs
them. Each finding was reproduced by the review against a live server before it
was acted on. The menu half of M-03 (`replicant/cli/menu.py` honouring
`REPLICANT_WEB_CONFINED=1`) is a separate change and is recorded with it.

The review started at commit `1d517fb`.

## Findings and disposition

| ID | Severity | Finding | Disposition |
|---|---:|---|---|
| H-01 | High | `/api/validate` had no concurrency limit. One REP-004 high validation peaks at about 830 MB for about 10 s, and 12 concurrent calls had the server OOM-killed. Every validation also left a directory and a ZIP of about 1.1 MB under `manifests/evidence/`, and nothing ever removed them. | Fixed. One validation at a time, **and never beside a run**: both are refused with 409 in the shape the single-run lock already uses (`validation_in_progress`, `run_in_progress`). Plan pricing, samples and validation also share one bounded build gate, so a whole-plan build cannot be multiplied through `/api/plan` either. Evidence packs are pruned to the newest `--evidence-keep` (default 20) after every web validation. |
| M-02 | Medium | Request bodies were read in full before the token check and nothing capped their size. An unauthenticated 400 MB POST to `/api/runs` grew RSS to about 1.3 GB before the 401. | Fixed. An ASGI middleware refuses a declared `Content-Length` over 64 KiB before reading anything and counts streamed bytes for a chunked body, answering 413 either way. An unauthenticated write to `/api/*` is now answered 401 before its body is read. |
| M-03 | Medium | The terminal child inherited the server's whole environment (`os.environ.copy()`), and the menu let a web-token holder write arbitrary files through the output path, save collector profiles and read any CA file path, which bypassed the F-07 `_confined_output` confinement. | Web half fixed. The child runs with an allow-listed environment (PATH, HOME, LANG, LANGUAGE, LC_*, TZ, PYTHONPATH, REPLICANT_CONFIG_DIR) plus TERM and `REPLICANT_WEB_CONFINED=1`, set unconditionally. The menu's handling of that variable is the other half and ships separately. |
| M-04 | Medium | The terminal "off on a non-loopback bind" rule was decided from the bind address alone. With a loopback bind behind a reverse proxy and `--allowed-host` set, a websocket carrying the allowed Host and Origin got a live terminal. | Fixed. The terminal defaults on only when nothing but this machine can reach the server: a loopback bind **and** no non-loopback `--allowed-host` **and** no `--collector-allow`. `--enable-terminal` still turns it on in every case. |
| M-05 | Medium | `/api/connect/test` had no rate limit and no destination policy: measured at 311 probes a second, distinguishing open from closed ports, which is an internal port scanner. Runs could also target any host and port. | Fixed. (a) Connect tests are metered per browser session, or per launch token for scripts: 10 per 60 s, 429 with `Retry-After`, plus a global ceiling of 30 so minted sessions do not multiply the allowance. (b) `--collector-allow CIDR[:PORT]` (repeatable) restricts where web callers may connect-test and send; IP literals only. Unset keeps the current behaviour and logs a warning at startup. (c) `failed` and `refused` verdicts keep their classification but no longer return exception text. |
| L-06 | Low | `tls_cafile` accepted over HTTP opened any path the service account could read, and the error revealed whether it existed and what it was. | Fixed. From the web, `tls_cafile` is a bare file name that must be a regular, non-symlinked file directly inside `<config>/ca/`. Every refusal returns the same message. Applies to connect tests and runs. The CLI is unchanged. |
| L-07 | Low | An abandoned run reservation held the single-run lock forever: `POST /api/run-admissions` and then nothing, and every `/api/runs` got 409 with status `reserved`. | Fixed. `reserved` and `admitting` expire after 60 s. The expired admission is published as an error, so a watching client learns why. The clock is injectable for tests. |
| L-08 | Low | A non-ASCII token caused a 500 on every route including `/api/health`: `compare_digest` on a `str` holding non-ASCII raises `TypeError`, and the cookie middleware authenticates every request. | Fixed. The comparison is on bytes (`token.encode()` against the supplied value encoded with `surrogatepass`), so any such value is a 401. |
| L-09 | Low | The per-client terminal cap was keyed on the peer address, which uvicorn rewrites from `X-Forwarded-For` when the peer is a trusted proxy, and it trusts 127.0.0.1 by default. | Fixed. The cap is keyed on the authenticated browser session (or the launch token for scripts; the peer only under `--no-auth`). uvicorn is started with proxy headers off and `forwarded_allow_ips` passed explicitly, so neither the default nor `FORWARDED_ALLOW_IPS` widens it; `--forwarded-allow-ips` names a real proxy. |
| L-10 | Low | The systemd unit was lightly hardened: `ReadWritePaths=/opt/replicant` made the code and venv writable, `ProtectSystem=full` rather than `strict`, and no memory, task, capability, address-family, device, kernel, proc or syscall restrictions. | Fixed. `ProtectSystem=strict` with `ReadWritePaths` limited to `.config`, `manifests` and `out`, plus the settings listed in `docs/deployment-boundary.md`. `MemoryMax=1536M`, `TasksMax=256`. `systemd-analyze security` moved from 8.4 EXPOSED to 1.2 OK. |
| S-01 | Suspected | Server-sent-event streams were uncapped, and each run stream polls through the default executor. | Fixed. Run and log streams share a cap of 16 live streams, 429 beyond it. A slot is released when its stream ends, and also when a never-started generator is collected. |

## Decisions worth arguing with

**Validation is also refused while a run holds the lock.** The request allowed
either. Refusing means an operator cannot validate one technique while another
emits for four hours. It was chosen because the failure being fixed is memory,
and a REP-004 high run holds about 400 MB of plan while a validation of the same
technique peaks at about 830 MB. With the two exclusive the server's peak is the
larger of them, which is what `MemoryMax=1536M` is sized against.

**Plan pricing waits rather than refuses.** The run form re-prices on every
change and the newest request is the one whose answer matters, so `/api/plan`
and samples wait up to 30 s for the build slot. Only four may wait at once,
because each waiter holds a worker thread; past that, and on timeout, the answer
is 503. The form already treats a failed preview as "no numbers yet".

**The allow list matches IP literals only.** A hostname would be resolved again
by the transport at send time, so checking a resolution here would be checking a
different lookup than the one that picks the destination. With the list set, a
hostname collector is refused from the web.

**Setting `--collector-allow` turns the terminal off by default.** The menu in
the terminal is a separate process and the web allow list does not govern it,
so leaving the terminal on would hand the restricted operator a way round their
own restriction. `--enable-terminal` is the explicit override.

**`ProcSubset=pid` is not set.** It was in the first draft of the unit and hid
`/proc/net/route`, which the connect test reads to print the route beside the
destination. That disclosure is what exposed the transposed-address lab defect
recorded in `CLAUDE.md`, so the unit keeps `ProtectProc=invisible` and drops
`ProcSubset`. `verify-systemd-unit.sh` now asserts the route table is readable.

**`PrivateDevices=yes` was observed, not assumed.** systemd.exec(5) says the
private `/dev` keeps `ptmx` and a private devpts instance. The verify script
opens a real terminal session over the websocket under that unit, and the menu
starts in its PTY.

## Positive controls

Each guard was run against the code with its fix reverted in isolation and
observed to fail, then restored. The mutations and the tests that went red:

| Finding | Reverted | Went red |
|---|---|---|
| H-01 | validation slot check in `begin_validation` | `test_a_second_validation_is_refused_while_one_runs` |
| H-01 | validation check in `reserve` | `test_a_run_and_a_validation_exclude_each_other` |
| H-01 | the `prune_evidence` call | `test_the_web_server_prunes_evidence_after_each_validation` |
| H-01 | the run-id name filter | `test_evidence_retention_only_considers_run_ids` |
| H-01 | the symlink skip, with deletion resolving the path | `test_evidence_retention_never_follows_a_symlink` |
| M-02 | `BodyLimitMiddleware` | both oversized-body tests in `test_web_body_limits.py` |
| M-02 | the pre-body auth middleware | `test_an_unauthenticated_write_is_refused_without_reading_its_body` |
| M-03 | the spawn back to `os.environ` | `test_the_spawned_child_really_receives_the_minimal_environment` |
| M-03 | the environment filter | `test_the_terminal_child_environment_is_minimal` |
| M-04 | `for_bind` back to the bind address alone | three terminal-policy tests |
| M-05 | the connect-test charge | `test_connect_tests_are_rate_limited` |
| M-05 | the allow-list check | `test_the_allow_list_is_enforced_on_connect_tests_and_runs` |
| M-05 | the summary replacement | both generic-summary tests |
| L-06 | `confined_cafile` | both arbitrary-path tests |
| L-07 | admission expiry | both abandoned-reservation tests |
| L-08 | the `str` comparison | `test_a_non_ascii_token_does_not_break_every_route` |
| L-09 | the session key | `test_the_terminal_cap_is_keyed_on_the_session_not_the_peer` |
| L-09 | the explicit uvicorn proxy settings | both forwarded-header tests, one of them against a live uvicorn |
| S-01 | the stream slot | `test_streams_past_the_cap_are_refused_and_freed_on_disconnect` |
| L-10 | the whole unit, back to `1d517fb` | 8 of the new `verify-systemd-unit.sh` checks, under systemd 252 |

The body-limit, stream and forwarded-header guards run against a real uvicorn on
a loopback port, because `TestClient` neither delivers a body in pieces nor
applies proxy headers, and it buffers a whole streamed response.

The two headline reproductions were repeated against the hardened unit under
systemd: 12 concurrent REP-004 high validations returned one 200 and eleven 409
with the same process still serving, and a 400 MB unauthenticated POST was
answered 413 at once.

## New operator surface

- `replicant web --collector-allow CIDR[:PORT]`, repeatable. IPv6 with a port is
  bracketed: `[2001:db8::/32]:6514`. A malformed entry refuses startup.
- `replicant web --evidence-keep N`, default 20.
- `replicant web --forwarded-allow-ips IP`, repeatable. Unset trusts no proxy.
- `<config>/ca/` holds CA bundles a web caller may name by file name.
- The startup banner has a `sends to` line naming the allow list, or saying any
  destination is allowed.

## Residual operational constraints

- The rate limit is per session and per launch token. A launch-token holder can
  mint browser sessions, so the global ceiling of 30 per minute is the real
  bound on probes from one server.
- The allow list governs the web API only. The CLI and the Rich menu keep the
  operator's shell authority, the same line `_confined_output` draws.
- `REPLICANT_WEB_CONFINED=1` confines the menu only once the menu half of M-03
  is merged. Until then the environment is minimal but the menu still accepts
  paths.
- `MemoryMax` and the one-validation rule are sized from REP-004 high, the
  largest plan in the catalog today. A larger technique should re-measure them.
