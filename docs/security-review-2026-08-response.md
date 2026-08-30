# Response to the external security review of 2026-08-02

Reviewed commit `23fdc28` (v0.5.0). This records what was accepted, what was
accepted with a changed remedy, what was deferred, and what was rejected, with the
reasoning in each case. It is a decision record, not a status board: where a
finding is deferred, the reason is stated so the decision can be argued with
rather than rediscovered.

Every finding below was **reproduced before being acted on**. Two were not
reproducible as described and are marked accordingly.

## Status as of 2026-08-04

Every finding except F-14 is now closed. F-08 was closed on 2026-08-30 by the
operator choosing the documented-and-enforced single-process scope over a
host-level lease; see its row below. F-14 is the one item still open, and it
needs a supported-platform decision rather than an implementation.

| finding | state |
|---|---|
| F-01, F-02, F-03, F-06, F-07 | fixed (PRs #41, #42) |
| F-05 | fixed in two parts: frame validation and bounded queue (#43), then session limits and non-blocking termination (#50) |
| F-04 | fixed (#51). The cookie now holds a short-lived session id from `SessionStore`, never the launch token, and no credential appears in a stream URL |
| F-09 | fixed (#49), together with the same defect re-reported by a later review |
| F-10 | fixed (#54). `resolve_endpoint` uses AF_UNSPEC, so IPv6 collectors work |
| F-11 | closed by #46: the connect test returns a structured verdict carrying the exception type and message |
| F-12 | fixed (#53). Each SSE consumer gets its own queue, seeded with bounded history |
| F-13 | fixed (#48) |
| F-15 | fixed (#54). PEP 639 SPDX metadata, verified in a built wheel |
| **F-14** | **partially.** The one non-breaking upgrade applied. The rest need vite 8 and vitest 4, which drop Node 18, which the installer declares as its floor. That is a supported-platform decision, not a bump |
| **F-08** | **closed 2026-08-30.** Operator chose the documented and enforced single-process scope over a host-level lease. `replicant/core/sendlock.py` takes an advisory `flock` for the duration of any run that opens a socket to a collector, so a second sending run on the host is refused rather than allowed to deliver twice the cap, and the refusal names the holding pid. A lease keyed on collector destination was the alternative and was declined: expiry, clock drift and orphaned leases are worse failure modes than the one being fixed, and `flock` is released by the kernel on exit so there is nothing stale to clean up. Scope stated rather than implied: per host and per user, not across hosts. `--no-send` and `--to-file` never acquire it. Guarded by `tests/test_sendlock.py`, which spawns a real second process, because a same-process re-entry would pass against code that locked nothing |

The original response follows.

## Summary

| | count | findings |
|---|---|---|
| Accepted and fixed | 5 | F-01, F-02, F-03, F-06, F-07 |
| Accepted, remedy differs from the recommendation | 2 | F-03, F-07 |
| Deferred with reasons | 8 | F-04, F-05, F-08, F-09, F-10, F-11, F-12, F-14 |
| Accepted as documentation only | 1 | F-13 |
| Not adopted | 1 | F-15 (deferred, see below) |
| Research programme | 7 | R-01..R-07, product decision, not a fix list |

## Accepted and fixed

### F-01 Terminal origin validation ignores scheme and port — **P0, fixed**

Reproduced exactly. `http://localhost:9999` and `https://localhost:31337` were
both accepted as the origin of a server on `localhost:9787`.

Accepted without reservation. An origin is `(scheme, host, port)` and the code
implemented a host allowlist. The consequence is concrete on the machine
Replicant is designed for: an analyst laptop running several development servers,
where any of them could drive the PTY using the ambient session cookie.

`AccessPolicy.allows_origin` compares the parsed triple against the request's own
`Host` header. That choice is deliberate and differs slightly from the review's
"configure one canonical browser origin": deriving the expectation from the
request keeps a TLS-proxy deployment correct without adding a configuration knob
that can be set wrong, and without trusting `X-Forwarded-*`.

Origin is now required on **every** terminal handshake rather than only
cookie-authenticated ones, as recommended.

**One recommendation not implemented, deliberately.** The review asks for exact
scheme comparison. `Host` carries no scheme, so the only way to compare it is an
explicitly configured public origin. The gap it leaves is not reachable: serving
`https` on an authority means holding that port, and holding the port means being
the server rather than attacking it. The limit is asserted as a decision in
`tests/test_web_origin.py` rather than left silent.

### F-02 Failed runs write no manifest — **P0, fixed**

Reproduced exactly: a run against a closed TCP port raised
`ConnectionRefusedError` and left the manifest directory empty.

Accepted without reservation. Safety rule 5 says every run writes a manifest, and
the failure path is the one that most needs it: a run can reach a collector
part-way and leave nothing durable saying what was attempted.

`run()` and `run_scenario()` now write the manifest on every exit path and
re-raise the original exception unchanged. Manifests carry `status`
(`done`/`stopped`/`error`) and a bounded `error` string.

**Partially implemented.** The review also asks for separate planned, rendered,
attempted and handed-to-transport counts, transport statistics, catalog hash and
profile version. Those belong with R-07 (content-addressed experiment bundles)
and are deferred to it rather than half-built here. What ships now is the audit
guarantee itself.

### F-03 Repository Markdown can execute same-origin code — **P1, fixed**

Reproduced: `marked` returned `<img src=x onerror=...>` unchanged, and the Docs
tab passed it to `dangerouslySetInnerHTML`.

Accepted, and the original comment in the source was wrong. It argued repository
files are trusted because anyone who can edit `docs/*.md` can edit the
application. Documentation is reviewed under a different bar than executable
code, which is exactly why that reasoning fails.

**Remedy differs from the recommendation.** The review suggests sanitising the
parsed output with an allowlist, which means adding a sanitiser dependency.
Instead the `html` token is overridden so raw HTML renders as visible text.
Escaping the whole source would have destroyed the fenced code blocks the CEF
references are made of; overriding one token is narrower, adds no dependency, and
none of the five served documents contains a raw tag, so nothing renders
differently.

**A second hole was found while fixing the first.** `marked` does not filter link
protocols, so `[click](javascript:...)` produced a working `href`. Neutralising
raw HTML alone would have left that open. The `link` renderer now drops anything
that is not `http:`, `https:`, `mailto:`, a fragment or a relative path.

A Content-Security-Policy is also sent (`script-src 'self'`, `object-src 'none'`,
`base-uri 'none'`, `frame-ancestors 'none'`), plus `X-Content-Type-Options` and
`Referrer-Policy`. It is defence in depth behind the Markdown fix, not instead of
it. `style-src` permits inline styles because the bundled UI sets them; removing
that needs a nonce pipeline through the build, which is a separate change.

### F-06 `--no-auth` leaves HTTP open but rejects every terminal session — **P1, fixed**

Reproduced. Accepted without reservation: the startup warning described a state
the code could not reach, which is worse than either behaviour on its own.

The websocket path now honours `require_auth` the same way the HTTP dependency
does. `--no-auth` drops the credential and never the Host or Origin checks, which
is asserted by a test.

### F-07 Web file output can truncate arbitrary paths — **P1, fixed**

Reproduced. `FileSink` opens with mode `w`, which follows symlinks and truncates,
and the API accepted any string.

Accepted. A stolen web token should be worth the collector-run authority it
carries and no more.

**Remedy is narrower than the recommendation.** The review suggests returning an
opaque artifact identifier. Web output is instead confined to a server-chosen
directory, with the basename taken from the request and the resolved path
returned as `output_path`. An opaque id would need a lookup table and a download
endpoint, which is more surface for the same guarantee.

**The CLI is deliberately unchanged.** A caller already holding a shell has the
same filesystem authority anyway, so restricting `--to-file` there would buy
nothing and break ordinary use.

## Accepted as documentation only

### F-13 Drift messages reverse past and future — **P2**

Confirmed incidentally while reproducing F-02: the default historical anchor is
reported as a positive number of days *in the future*. Accepted as a real defect.
Not fixed in this pass because it is cosmetic and the fix belongs with the wider
message-formatting work in F-11. Recorded so it is not rediscovered.

## Deferred, with reasons

These are accepted as valid and not yet done. None is dismissed.

- **F-04 durable token in stream URLs** — accepted. The fix is a session-exchange
  design (short-lived id, expiry, rotation, revocation), not a patch, and doing it
  badly is worse than the current state. Sized as its own change.
- **F-05 malformed terminal messages can strand a PTY** — accepted, and the
  largest item in the P1 block: frame schema, bounded queue, task supervision,
  partial-write backpressure, timed termination. Attempting it alongside the
  others would have produced a shallow version of each.
- **F-08 eps cap is not process-wide** — accepted as described, but the remedy
  needs a decision first. A host-level lease keyed on collector destination is a
  real design change with its own failure modes, and the alternative the review
  offers -- state and enforce a single-process scope -- may be the honest answer
  for a lab tool. Not something to pick unilaterally.
- **F-09 duration parser accepts malformed values** — confirmed (`-1h` → 3600,
  `1h garbage` → 3600). Low impact because the value only shortens a synthetic
  run, but the fix is straightforward and should land with the next reliability
  pass.
- **F-10 no IPv6 in transports** — accepted as a real compatibility gap.
- **F-11 connect-test error detail swallowed** — accepted.
- **F-12 run event streaming is destructive and single-consumer** — accepted.
- **F-14 development dependency advisories** — accepted. Production audit is
  clean and the vulnerable Vitest UI is not what `npm test` runs, so this is a
  contributor-workstation risk rather than a shipped one. Needs a Node matrix
  check alongside the upgrade.
- **F-15 packaging license metadata deprecation** — accepted; the deadline is
  2027-02-18 and the change is trivial, so it rides with the next release rather
  than alone.

## The finding the review did not make

Writing the F-01 tests exposed something worth more than the finding itself:
**every pre-existing terminal websocket test was passing on the Host gate.**
`TestClient` sends `Host: testserver` regardless of `base_url`, so connections
were refused before the origin was ever read, and
`test_terminal_websocket_rejects_a_foreign_origin` would have passed with the
origin check deleted entirely.

The first version of the new tests had the same defect. It was caught by
reverting the fix and observing that the tests stayed green.

**Rule adopted:** a security test must be run against the unfixed code and
observed to fail. A guard that has never failed is a guard of unknown value.
Every websocket test now sets `Host` explicitly and the suite carries a positive
control, so a gate that rejects everything cannot masquerade as a gate that
discriminates.

## The research programme (R-01..R-07)

Not adopted or rejected here. The review's strongest product claim is that the
highest-value next addition is an evaluation layer -- protocol correctness,
distributional realism, semantic behaviour, downstream detection utility -- rather
than another technique. That argument is sound and matches what the project has
learned the hard way twice: telemetry that is byte-valid can still be untestable,
and a control whose effect is unmeasured tends to be wrong.

It is weeks of work and a change of direction, so it is a decision for the
project owner rather than something to start inside a security patch.

## Standing caveat

None of this is confirmed against a live SIEM. The review notes the same limit.
Suites H and I in `tasks/uat-plan.md` remain unexecuted, so vendor and detection
fidelity stay unverified where the repository already marks them so.


## What a second review found that this one did not

An independent end-to-end review on 2026-08-03 found eight further defects, all
reproduced before being acted on and all now fixed (PRs #47, #48, #49). Two are
worth recording here because they say something about where this review's
attention did not reach.

**Detection content was wrong on two of three vendors.** Check Point and Palo
Alto both hardcoded failure semantics into the `event:system` login path, so
every successful administrative login in REP-018 rendered as a rejected one,
contradicting its own message field. The security review looked at transport,
web and process safety and never at whether the emitted telemetry means what it
claims, which is the product's core promise.

**The test that should have caught it covered one half of the field.** The Check
Point golden line for that path is a *failed* login, and the golden test only
ever fed it a failure. The suite passed while the only case the engine actually
produces was never rendered. A catalog-wide scan afterwards showed 100% of
`event:system` events are successes, so the hardcode was never once correct.

> A golden-line test that covers one verdict of a two-verdict field is not a
> test of that field.

## Defects this session found that neither review did

Both were found by running the software rather than reading it, which is the
same lesson the systemd unit taught in v0.3.0.

- **A configured collector did not mean send.** The web form's destination
  switch defaulted off and the API defaulted `no_send=True`, so a verified
  collector plus a technique plus the run button produced a run that rendered
  every event and delivered none. PR #31 had made that visible with a labelled
  button and a warning and left the default that causes it, and this document's
  own record wrongly described it as fixed. Measured: CLI 200 datagrams, web 200
  datagrams, identical parameters, so the send path was never broken. Only its
  default was.
- **The single-run lock was invisible.** Only one run may be active, which is
  correct because concurrent runs multiply the eps cap. But the form's `running`
  flag is per-panel state, so a reload showed an idle form while the server was
  hours into a plan-paced run, and pressing the button produced a 409 naming a
  hex id the operator could not resolve, see or stop.

Both surfaced during a live lab session, and both read to the operator as "the
web UI is broken".
