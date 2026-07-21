# Linux install script (design spec)

**Status:** approved for implementation, 2026-07-20.
**Branch:** `feature/linux-install-script` (off `main` at `b03c577`, which includes Phase 4).
**Backlog item:** 1 of 3 in `tasks/backlog-and-recommendations.md`.

---

## 1. Goal

One script that takes a fresh Linux box from a `git clone` to a **verified** working Replicant install, without the operator reading the README and running six commands by hand.

The emphasis is on *verified*. An installer that exits 0 having produced something broken is worse than no installer, so the script ends by exercising the real pipeline end to end.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Install shape | In-repo operator setup | `replicant web` resolves `FRONTEND_DIST` as `parents[2]/webui/dist`, i.e. relative to the package source (`replicant/web/server.py:55`). An editable in-repo install is what makes the SPA resolvable at all; a site-packages install would have no `webui/` beside it. |
| Prerequisites | Verify, then install only what is missing, after explicit consent | `sudo` on a box the operator may not own is the script's only irreversible act. It must be visible and declinable. |
| Self-verification | Smoke plus a real loopback transport check | Catches the failures an install actually produces: missing console script, broken optional dep, unusable socket path. |
| `replicant doctor` | Deferred to its own item | "Did this install succeed" (shell, runs before the venv exists) and "is my runtime healthy" (collector reachable, config valid) are different questions. Merging them produces a command that does neither well. |
| Server changes | None | Considered adding a warning for a missing frontend build, then found `_mount_frontend` already serves a page naming the exact build command (`replicant/web/server.py:338-344`). No change needed. |

## 3. Approach

A single self-contained `bash` script composed of small functions. Rejected alternatives:

- **A committed `tools/verify_install.py`.** More readable verification, but that file is `replicant doctor` under another name, in a worse location, without tests. It recreates what section 2 deliberately deferred.
- **Makefile-driven.** Adds `make` as a prerequisite, which undercuts the fresh-box premise, and handles interactive consent poorly.

The loopback check runs its UDP listener through `.venv/bin/python` rather than `nc` or `socat`. Those are not reliably present across distributions, whereas by that point in the script the venv interpreter is guaranteed.

## 4. File and contract

**`scripts/install.sh`** - Apache header, executable, `set -Eeuo pipefail`. The `-E` is load-bearing: without `errtrace` the ERR trap is not inherited into shell functions, and every step of this installer runs inside one. A `BASH_VERSION` guard rejects `sh scripts/install.sh` with a clear message rather than failing obscurely on the first bashism.

- Resolves the repo root from its own path, so it runs from any working directory.
- Safe to re-run against an existing install. Note this is re-runnable, not non-mutating: `pip install --upgrade pip` runs every time, and `npm ci` removes and reinstalls `node_modules` before `npm run build` overwrites `dist/`. An existing `.venv` is reused rather than recreated, but it is validated against the Python minimum first and the operator is told to `rm -rf` it if it is stale or half-built.
- Exits 0 only when every step including verification passed.

### Flags

| Flag | Effect |
|---|---|
| `--no-web` | CLI-only install. Skips the node/npm prerequisites and the frontend build. |
| `--dev` | Install the `dev` extra (pytest, black, ruff, mypy) instead of `web`. |
| `--yes` | Non-interactive. Assumes yes at the prerequisite consent prompt. |
| `--dry-run` | Print every action that would be taken; change nothing. |
| `--help` | Usage. |

## 5. Steps

1. **Preflight.** Confirm the host is Linux. Confirm the resolved root is the Replicant repo (a `pyproject.toml` naming `replicant`). Parse flags.
2. **Detect package manager.** `apt-get`, `dnf`, `yum`, `pacman`, or `zypper`. If none is recognised, degrade to check-only: report what is missing with generic instructions and exit non-zero rather than guessing at package names.
3. **Check prerequisites.** Python >= 3.11 (probe `python3.13`, `python3.12`, `python3.11`, then `python3`, comparing the reported version, with a numeric guard so an interpreter that prints a notice on stdout cannot corrupt the comparison), the `venv` module, and unless `--no-web`, Node and `npm`. Node >= 18 is required by Vite 5; `webui/package.json` declares no `engines` field, so this bound comes from Vite's documented requirement rather than from the repo. [Unverified] against a live build.

   `git` is reported if absent but does not block and is never installed: the repository is necessarily already cloned by the time this script runs, and nothing in it shells out to git. `pip` is not probed separately, since the `venv` module provides it.

   **[Unverified] distribution caveat.** The package mappings install each distribution's default `python3`, which on several current LTS releases is below 3.11 (Ubuntu 22.04 ships 3.10, Debian 11 ships 3.9, RHEL/Rocky/Alma 8 and 9 ship 3.6/3.9, and their default `nodejs` module is below 18). On those hosts the flow consents, installs, re-checks, and then fails with `still missing after install`, having changed the system for no benefit. This has not been verified against live repositories from the macOS development host. Resolving it properly means either version-qualified package names per distribution (`python3.11`, `dnf module enable nodejs:20`) or refusing before the sudo step when the mapping demonstrably cannot reach the minimum. Tracked as the first follow-up after real-hardware validation.
4. **Install what is missing.** Print a summary of missing items and the exact command about to run, prompt `y/N` (bypassed by `--yes`), then run it under `sudo`. Never upgrade or reinstall anything already satisfied.
5. **Virtual environment.** Create `.venv` with the selected interpreter if absent; upgrade `pip` inside it. An existing `.venv` is reused.
6. **Install the package.** `pip install -e ".[web]"`, or `".[dev]"` under `--dev`.
7. **Build the frontend** (skipped by `--no-web`). `npm ci` when `webui/package-lock.json` exists, otherwise `npm install`; then `npm run build` (`tsc -b && vite build`). Assert `webui/dist/index.html` exists afterwards. This step matters because `dist/` is gitignored (`webui/.gitignore:2`), so a fresh clone never carries a build.
8. **Verify.** Three checks against the freshly installed venv:
   - `.venv/bin/replicant list` exits 0 and lists the catalog.
   - `.venv/bin/replicant run REP-001 --intensity low --to-file <tmp> --no-send` writes output whose first line matches `^CEF:0\|`.
   - A real loopback send: start a UDP listener on `127.0.0.1` on an ephemeral port via `.venv/bin/python`, run `replicant run REP-001 --intensity low --host 127.0.0.1 --port <ephemeral> --transport udp` against it, and assert datagrams arrived. The listener is bound before the run starts and torn down after, with a timeout so a failed send cannot block the script, and its PID is global so the cleanup trap can reap it on a signal.

     An earlier draft pinned `--duration 2m` and justified it as avoiding events-per-second pacing. That reasoning was wrong and the measurement disproved it: `eps_cap` defaults to 2000 and the pacing loop only sleeps once a one-second window fills, so the cap is never approached and the run completes in well under a second either way. What `--duration 2m` actually did was truncate the plan, because REP-001 at low intensity has `interval_s: 300`, so a 120-second window admitted only the callback at t=0 and the strongest verification claim in the installer rested on a single datagram. The default duration is used instead, which delivers roughly 49 events just as fast.

   Temporary files are removed on both success and failure.
9. **Report.** Print what was installed and the next commands (`replicant menu`, `replicant web`), including how to activate the venv.

## 6. Safety

The script states in its own header, and the README repeats, that **install-time egress to PyPI and npm is distinct from the runtime rule that the only egress is the operator-configured collector**. The installer must not read as though that rule has loosened.

- Verification transmits synthetic data to `127.0.0.1` only. Nothing external is contacted.
- `sudo` is used solely for package-manager installs, never for the venv, pip, npm, or verification. Running the *whole script* under `sudo` defeats this and leaves `.venv`, `node_modules`, `dist/` and `manifests/` root-owned inside the operator's clone, so the script warns when it detects `EUID == 0`.
- Nothing is written outside the repository. Verification runs `replicant` with the working directory forced to the repo root, because `replicant run` writes a run manifest to the **relative** path `manifests/`; invoked from the operator's arbitrary CWD it would scatter manifests there and fail outright on a read-only directory. Temporary verification files are tracked in `TMP_FILES` and removed by a `cleanup_tmp` trap on `EXIT`, `INT`, and `TERM`, which also reaps the loopback listener. The manifests the verification run produces land in the repo's gitignored `manifests/` directory and are deliberately kept as an audit record (safety rule 5).

## 7. Errors

`set -Eeuo pipefail` plus an `ERR` trap reporting the failing line, exit status, failing command, and the step that was running. Every step prints an `[ok]`, `[warn]`, or `[fail]` status line so a failure is locatable at a glance. The verification commands capture stderr to a tracked temp file and print its tail on failure, rather than discarding it.

The table below applies to `die` paths. A failure caught by the ERR trap rather than by an explicit `die` exits with the failing command's own status.

| Code | Meaning |
|---|---|
| 0 | Success, verification included |
| 1 | Usage error |
| 2 | Unsupported distribution / no known package manager |
| 3 | Prerequisites missing and installation declined |
| 4 | Virtualenv or pip install failure |
| 5 | Frontend build failure |
| 6 | Verification failure |

## 8. Testing

- `bash -n scripts/install.sh` for syntax, and `shellcheck` if it is available on the machine.
- `--dry-run` exercised locally to walk the full decision path (flag parsing, package-manager detection, prerequisite evaluation, step sequencing) without mutating anything. This exists partly because the development host is macOS, where the real path cannot run.
- **Not covered by pytest.** This is a shell script with no Python surface; adding a subprocess test that shells out to it on a non-Linux host would assert nothing useful. The suite count is unchanged by this item.
- Final confirmation is a real run on a Linux host by the operator. Distribution package names and the `sudo` path cannot be genuinely validated from macOS, and the spec should not pretend otherwise.

## 9. Non-goals

- **System-wide or `/opt` deployment, systemd units, a service user.** Requires solving frontend-dist placement, config location, and log paths first. Its own item.
- **`replicant doctor`.** Deferred, per section 2.
- **macOS and Windows support.** The README already covers manual macOS setup; this script targets Linux only and says so.
- **Container images.** A `Dockerfile` is a different distribution question.
- **CI wiring.** The repo has no CI today; adding one is separate work.
