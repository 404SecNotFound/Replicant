# Spec: make the web UI directly reachable and easier to navigate

Author: DJR. Captured 2026-07-28. Status: not started.

## Context

Replicant currently serves its web UI on a random loopback port with a
mandatory per-session token in the query string, and rejects any request whose
Host header is not localhost. Reaching it from another machine requires an SSH
tunnel. Getting from `git clone` to a usable page takes too many steps. Fix the
access path and the in-app navigation.

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
