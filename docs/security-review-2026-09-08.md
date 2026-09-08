# Security review response, 2026-09-08

## Scope

This urgent review covered the code paths most likely to cross Replicant's safety
boundaries:

- collector destination construction and fail-closed behavior;
- web authentication, browser sessions, cookies, and cross-origin writes;
- CLI, HTTP, and shared model validation;
- Python and frontend dependency advisories;
- regression coverage for each accepted finding.

The review started at commit `9ba5425`. While the response branch was open,
`455fe6c` landed on `main` with the server-side launch-token exchange and
thread-safe session lifecycle. This response was rebased onto that implementation
and keeps the complementary findings below. The combined tree was tested, rather
than preserving a competing frontend token-exchange implementation.

## Findings and disposition

| ID | Severity | Finding | Disposition |
|---|---:|---|---|
| SR-01 | High | An empty collector host is accepted by the model. On common platforms `getaddrinfo("", port)` can select the local machine, turning an absent destination into a socket peer and violating the fail-closed rule. | Fixed. Collector hosts are trimmed, must be non-empty, and cannot contain whitespace. The CLI and HTTP boundaries have regression tests. |
| SR-02 | High advisory, build-time exposure | `browserslist` 4.28.6 is affected by GHSA-c83g-rgw3-j3cx and GHSA-73wf-gq98-2v4g. The package is a frontend build dependency, not shipped runtime application code. | Fixed. The lockfile selects 4.28.9 and the final `npm audit` reports zero vulnerabilities. |
| SR-03 | Medium | A valid launch token can create unexpired browser sessions until memory is exhausted. Expiry sweeping does not bound entries created within the 12-hour TTL. | Fixed. The store retains at most 256 sessions and evicts the oldest when full. A repeated bootstrap navigation reuses its valid existing session. |
| SR-04 | Medium | Existing persisted web tokens are read without repairing file permissions. An older install, restored backup, or accidental `chmod` can leave the master credential group or world readable indefinitely. | Fixed. Startup restores the config directory to mode `0700` and the token to mode `0600` before reuse. Failure to secure either prevents credential reuse. |
| SR-05 | Low | Logout was unauthenticated. A cross-site form could force logout when used through a browser that does not enforce `SameSite=Strict`. | Fixed. Logout uses the normal authentication dependency and matching-Origin rule for cookie-authenticated writes. |
| SR-06 | Low | Negative seeds reach NumPy as an exception, and zero-length requested run durations produce inconsistent planning behavior. These surface as CLI tracebacks or HTTP 500 responses instead of input errors. | Fixed. Shared settings and request models reject negative seeds and zero-length run windows. Zero remains valid for scenario stage offsets. |
| SR-07 | Low | Invalid ad-hoc collector values can escape the CLI as raw Pydantic tracebacks. | Fixed. Collector construction errors are rendered as concise operator-facing refusals. |

## Related fixes already on current main

The current base branch now exchanges a tokenized browser navigation for an
httpOnly session cookie before serving JavaScript. It also serializes session
lifecycle operations with a lock. Those changes close the persistent-token replay
and concurrent dictionary mutation paths observed on the original review base.
This response extends that design with a hard capacity limit, session reuse, and
logout Origin enforcement.

## Verification

The rebased combined tree is required to pass:

```text
env REPLICANT_CONFIG_DIR=/private/tmp/replicant-test-config-final .venv/bin/pytest -q
.venv/bin/ruff check replicant tests
.venv/bin/black --check replicant tests
.venv/bin/mypy replicant
npm ci
npm test -- --run
npm run build
npm audit --json
```

The Python dependency audit found no advisory in Replicant's installed third-party
runtime dependencies. It did report PYSEC-2026-3721 for the local virtual
environment's `pip` 26.1.2 executable, fixed in `pip` 26.2. `pip` is environment
tooling, not a declared Replicant dependency or shipped artifact.

## Residual operational constraints

- Browser and API credentials remain bearer credentials. Protect the token file,
  use TLS when the web UI is exposed beyond loopback, and rotate the token after
  suspected disclosure.
- Session eviction is intentionally oldest-first. A party that already holds the
  launch token can displace browser sessions, but cannot make server memory grow
  beyond the fixed cap.
- This review does not replace live-vendor validation for Palo Alto or Check Point.
  Existing `[Unverified]` markers remain in force.
