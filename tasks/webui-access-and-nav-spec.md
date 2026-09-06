# Spec: make the web UI directly reachable and easier to navigate

Author: DJR. Captured 2026-07-28. Original status: not started.
Current status: implemented in v0.3.0; authentication and active-run identity
hardened in PR #101 on 2026-09-06. The context and numbered requirements below
are preserved as the original design record.

## Context

Replicant currently serves its web UI on a random loopback port with a
mandatory per-session token in the query string, and rejects any request whose
Host header is not localhost. Reaching it from another machine requires an SSH
tunnel. Getting from `git clone` to a usable page takes too many steps. Fix the
access path and the in-app navigation.

## Current authentication and run-identity contract (2026-09-06)

The shipped flow is stricter than the original first-load wording below:

- A tokenized browser `GET` is bootstrap only. Before serving the SPA or any of
  its module graph, the server exchanges a valid launch token for a fresh,
  short-lived `replicant_session` id in an httpOnly `SameSite=Strict` cookie and
  returns a `303` to the same path without `token`. The redirect is `no-store`.
  An invalid launch token is also stripped before document load, but earns no
  session.
- Once bootstrapped, browser `fetch`, EventSource, and WebSocket traffic is
  cookie-only. No frontend module reads the token value, retains it, or replays
  it. Bearer, `X-Replicant-Token`, and query-token API clients remain
  supported, but those programmatic paths do not mint browser sessions.
- Session ids live in the server process for 12 hours, expire independently of
  the persistent launch token, and can be revoked one browser at a time with
  `POST /api/session/logout`. Issuance, expiry, validation, and revocation are
  serialized because FastAPI may execute synchronous dependencies in worker
  threads.
- The selected vendor changes the catalog's native detection metadata. While a
  start request is awaiting admission, the vendor selector and tab navigation
  are disabled with an explicit reason. The browser first reserves a
  client-generated idempotency key through `POST /api/run-admissions`; the
  acknowledged owner is visible as an unclaimed `reserved` request awaiting
  start, becomes `admitting` while the plan is prepared, and is promoted in
  place to `running`. Retrying a lost
  reservation response uses the same key. A lost start response is reconciled
  through `GET /api/run-admissions/{id}`, with no fixed waiting window or empty
  active-probe inference. A terminal admission is followed through its exact
  run status before active-owner confirmation, preserving the final count and
  manifest. While a locally started run or a
  run restored from `/api/runs/active` is active, the vendor selector remains
  disabled. Stopping a restored run enters
  a visible stopping state. A single watcher follows natural completion
  or the stop, retains the lock across transient failures, and carries the latest
  rendered count and final manifest from the status endpoint. A missing bounded
  status record after either restoration or a local SSE disconnect reconciles
  through the active endpoint while retaining the previous owner. The run
  handle plus start, active,
  status, and conflict responses carry the resolved vendor, so a restored page
  aligns its selector and catalog to the owner instead of the configured default
  before presenting it. If initial owner discovery fails, the application keeps
  the run controls fail-closed rather than presenting an idle default profile.
  The backend resets worker stop state before publishing a running owner and
  closes an SSE subscriber only after its terminal item publication barrier.
  After terminal state, an active-owner probe transfers directly to a successor
  and its vendor or confirms that the selector may unlock. Local SSE completion
  and its dropped-stream polling fallback use the same terminal handoff, so a
  live stream cannot be relabeled or remounted under another profile.

For frontend development, run the backend and Vite separately:

```bash
replicant web --port 8000 --no-browser
cd webui
VITE_PROXY=http://127.0.0.1:8000 npm run dev
```

Open the Vite origin with the launch URL's `?token=...` value. Vite proxies only
that tokenized root navigation to the backend for the exchange; the clean
redirect returns to Vite for the source UI. `/api` and `/ws` are proxied as
normal. All three proxy rules must keep `changeOrigin: false`: cookie-authenticated
writes and terminal WebSockets compare the browser `Origin` with `Host`, so
rewriting only `Host` to the backend target makes a legitimate development
request appear cross-origin.

Do not change the runtime safety invariants: a run still sends only to the
single operator-configured collector, entity pools stay synthetic (RFC1918 +
IANA documentation ranges + `.invalid`), the engine still performs no I/O and
issues no attack. Those are unrelated to this work and must survive it.

## Part 1: serving and access

1. Add `--host` and `--port` to `replicant web`.
   - `--port` defaults to a FIXED port (pick one and document it, e.g. 8787).
     Random-by-default goes away. If the port is occupied, fail with a clear
     message naming the port and the flag, do not silently pick another.
   - `--host` defaults to 127.0.0.1. Accepts any local address or 0.0.0.0.

2. The Host header allowlist currently hardcodes localhost. Replace it with a
   check against the address the server was actually told to bind, plus
   localhost, plus any value passed via a repeatable `--allowed-host` flag.
   Binding to 0.0.0.0 should not require the operator to defeat their own Host
   check to use the thing.

3. Token handling:
   - Keep the token. Persist it to a file under the config dir so it survives
     restarts, instead of regenerating per session. Add `--rotate-token` to
     force a new one.
   - Accept the token via an `Authorization: Bearer` header OR the existing
     query param, and set an httpOnly session cookie on first successful load
     so the token does not have to stay in the URL bar.
   - Add `--no-auth`. When passed, print a loud multi-line warning naming the
     bind address and stating that the embedded terminal is exposed. Refuse
     `--no-auth` outright when the bind address is not loopback unless
     `--i-understand-this-is-unauthenticated` is also passed.

   > **Current implementation, 2026-09-06:** the cookie is set on a `303`
   > bootstrap response before the first SPA document is served. JavaScript URL
   > cleanup remains defense in depth, not the credential exchange. Explicit
   > header and query API authentication never create a session.

4. When `--host` is not loopback, disable the Terminal (PTY) tab by default.
   Add `--enable-terminal` to turn it back on. The CLI and the Rich menu
   already cover everything the terminal tab does, so this costs the operator
   nothing in the common case.

5. On startup print, in this order: the URL to open (using the bind address,
   not 127.0.0.1, when bound elsewhere), the token state (persisted / rotated /
   disabled), and whether the terminal tab is on. Drop the `gio` browser-open
   attempt when no display is present, it currently prints an "Operation not
   supported" error on every headless start.

6. Add `scripts/replicant-web.service`, a systemd unit template that runs
   `replicant web` from the venv as a non-root user with `Restart=on-failure`,
   plus four lines in the README on installing it. Target state is: enable the
   unit once, then reach the UI at IP:port from any machine on the segment.

## Part 2: navigation

The catalog is 24 techniques and a flat list. Restructure the left rail:

7. Group techniques by MITRE ATT&CK tactic, collapsible, with the count per
   group. A technique mapped to several tactics appears under each. This is
   already the top item on the roadmap.

8. Add a filter box above the rail that matches on ID, name, use case ID, and
   ATT&CK technique ID simultaneously. Filtering collapses empty groups.

9. Add toggle filters for vendor applicability and log type
   (`traffic:forward`, `dns:dns-query`, `dns:dns-response`, `event:vpn`,
   `utm:ips`).

   > **Resolved 2026-07-29, DJR: the vendor half is dropped. Log type shipped.**
   >
   > Vendor applicability does not partition the catalog. All three vendor
   > profiles implement all six render paths (`traffic:forward`,
   > `dns:dns-query`, `dns:dns-response`, `utm:ips`, `event:vpn`,
   > `event:system`) and the catalog uses five of them, so every one of the 24
   > techniques applies to every one of the 3 vendors. The toggle could not have
   > excluded a single entry.
   >
   > A control whose output cannot change is decoration, and worse than absent
   > because it implies a distinction the data does not contain. Same call as
   > REP-016, which was left unbuilt rather than shipped dishonestly.
   >
   > Re-open this if a vendor is ever added that lacks a render path. The check
   > is one grep: `git grep -n 'key == (' replicant/profiles/` should show the
   > same set for every profile.
   >
   > Measured while deciding, in case it is useful later: `action` is the only
   > other axis that splits the catalog (6 values: accept 10, deny 5, pass 4,
   > reset 2, tunnel-up 2, ssl-login-fail 1). `benign_baseline` and `implemented`
   > are uniform across all 24 and would be equally inert.

10. Add a Docs tab that renders the markdown already in `docs/` (the three
    vendor CEF references and the technique catalog expansion research), so the
    reference material is reachable without leaving the UI.

11. Surface `--anchor` in the run form as a visible control with `now` and
    `fixed` options, defaulting to `now` for live sends and `fixed` for file
    output. The anchor trap (CEF eventtime pinned to the determinism anchor
    while the syslog header is stamped at send time) currently costs a
    first-time user a debugging session against their SIEM. Show a warning in
    the form when a live send is about to go out with a non-now anchor.

## Part 3: tests and docs

12. Cover: fixed-port bind, non-loopback bind, Host allowlist accept and
    reject, token via header and via cookie, `--no-auth` refusal on a
    non-loopback bind without the acknowledgement flag, terminal tab disabled
    by default when non-loopback.

13. Update the README Quick Start so the web path is: install, run one command,
    open IP:port. Remove the SSH tunnel instructions from the happy path and
    keep them in a note for operators who want the UI to stay loopback-only.

## Note for whoever implements this

The enforced loopback bind and the per-session token were added deliberately in
the pre-publication safety hardening pass (see CHANGELOG 0.1.0, "Security
hardening"). This spec relaxes the bind on purpose, so the compensating
controls in item 3 and item 4 are the point, not optional polish. Do not
weaken them to make the happy path shorter.
