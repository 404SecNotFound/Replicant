# Replicant backlog and recommendations

Captured 2026-07-19 from DJR's ideas, with Claude's recommendations. These are post-Phase-4 items.
Sequencing recommendation: finish Phase 4 (scenario composition) first, then 1, then 3, then 2.

## 1. Linux install script (ops / distribution)

Goal: one script to prep a fresh Linux box and install Replicant.

Recommended shape (`scripts/install.sh`, Apache header, documented in README):
- Detect the distro/package manager (apt / dnf / yum / pacman); install prereqs: Python 3.11+ with `venv` + `pip`, Node.js + npm (needed to build `webui/`), git, and build-essential where required.
- Create `.venv`, `pip install -e ".[web]"`.
- Build the frontend: `(cd webui && npm ci && npm run build)` so `replicant web` serves the built SPA (dist is gitignored).
- Self-verify: `replicant list` and a loopback `replicant run REP-001 --to-file /tmp/replicant-selftest.log --no-send` (and optionally a `--test` connect against an in-script UDP listener).
- Idempotent; use sudo only for package installs; clear failure messages; a `--no-web` flag for headless/CLI-only installs.
- Optional companions: a `replicant doctor` self-check command, a systemd unit template for running `replicant web` as a service, and a `pipx install .` path for CLI-only users.

Safety note to include in the script and docs: pulling packages from PyPI/npm at install time is install-time egress and is distinct from the runtime rule that the only network egress is the operator-configured collector. Do not let the installer imply a change to that rule.

Scope: small, standalone. Do early (unblocks Linux deployment and testing).

## 2. Docs tab (web UI, Phase 5)

Goal: an in-app documentation surface for platform docs, learning pages, and objectives.

Recommended shape:
- A third top-nav tab in `webui/src/App.tsx` (Emitter / Terminal / Docs), styled with the existing signal-instrument system.
- Backend: a `/api/docs` endpoint in `replicant/web/server.py` that lists and serves markdown pages (from `docs/` or a `docs/webui/` set), so content updates without a frontend rebuild. Token-gated like the other endpoints.
- Frontend: a `DocsView` with a left TOC + a sanitized markdown renderer (react-markdown or similar small dep).
- Suggested pages: overview / what Replicant is, getting started, the safety model (the five rules), how detection works, per-technique deep dives (can reuse the detail-panel catalog data), ATT&CK mapping, scenarios (after Phase 4), objectives / FAQ.
- Complements the per-technique detail panel (technical) with the broader learning and objectives layer.

Scope: moderate web feature. Pairs with item 3.

## 3. Group techniques (and future rules) by MITRE tactic (web UI, Phase 5)

Goal: the left rail groups techniques under their ATT&CK tactic; click a tactic to expand and show the contained techniques/rules. Scales as rules are added later.

Recommended shape:
- The technique catalog already carries `attack.tactics` per entry, so no backend data change is needed for the 11 techniques.
- Restructure `webui/src/components/CatalogTable.tsx` into collapsible tactic groups (Discovery, Command and Control, Exfiltration, Credential Access, Initial Access, Reconnaissance, ...), each with a count; expanding a group reveals its techniques and preserves the existing selection + detail-panel behavior.
- Decision to make: techniques that map to multiple tactics (e.g. REP-004 DNS tunnel is C2 + Exfil). Recommended: list a technique under each tactic it maps to, with a flat/grouped toggle (default grouped once there are enough entries).
- Connects to scenarios (which are tactic chains) and sets the structure for a future "rules" library; each tactic header can later link to its Docs learning page.

Scope: small-to-moderate web change. Good first Phase 5 item after the install script.

## Sequencing

1. Phase 4 complete and reviewed (2026-07-20); PR #7 open against `main`, DJR merges.
2. Item 1 (Linux install script) - quick, unblocks Linux testing.
3. Item 3 (group-by-tactic left rail) - small, high impact, sets up the rules structure.
4. Item 2 (Docs tab) - larger, content-heavy; pairs with tactic learning pages.

Items 2 and 3 are a natural "Phase 5: web UI + learning" batch. Item 1 is ops/distribution and can slot in anytime.
