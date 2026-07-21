# Lessons

Patterns worth not repeating. Append after any correction or review finding.

---

## A test that cannot fail is worse than no test

**2026-07-20, Phase 4 review.** `test_events_sorted_by_eventtime` did this:

```python
times = [e.eventtime for e in plan.events]
assert times == sorted(times)
```

`compose()` sorts by `eventtime` immediately before returning, so the assertion was true by construction and could never fail. It read like timeline coverage while verifying nothing, and it sat directly on top of a Critical bug: SCEN-001 emitted bulk exfil roughly 17 hours *before* the recon that precedes it.

**Rule:** before writing an assertion, ask what production change would make it fail. If the answer is "none", it is decoration. Assert the *semantic* property (stage k begins at or after `anchor + offset_k`), not the property the code just finished enforcing.

**Corollary:** when fixing a bug, prove the new test fails against the old behaviour. Here that meant composing the scenario both ways in memory and showing the pre-fix window (`07-15 00:00`) sits below the intended start.

---

## Parametrize over the whole catalog, not the convenient entry

**2026-07-20, Phase 4 review.** Every scenario test exercised SCEN-001 only. SCEN-001 happens to be the one chain where the hard-coded advisory text was accidentally true (all stages host-based; the chain really does contain both C2 and exfil). SCEN-003 exposed the advisory listing Exfiltration as a gap and then asserting "C2 and exfil share dst" four lines later, plus a "victim threads the chain" claim that held in 1 of 4 stages.

**Rule:** when a data file drives behaviour, parametrize across every entry in it (`ALL_SCENARIOS = [s.id for s in SCEN.scenarios]`), not one hand-picked example. Cache the composition if the larger entries are expensive; determinism makes that safe.

---

## Do not infer a rule where the domain needs an explicit flag

**2026-07-20, Phase 4.** The tempting fix for the timeline bug was generic: "shift any stage whose events start before its anchor." That would have corrupted REP-008, whose warm-up baseline is *supposed* to precede its anchor. Two behaviours that look identical to a heuristic had opposite intent.

**Rule:** when two cases are indistinguishable from the data but differ in intent, make the caller declare it (`align: "next-off-hours"`) instead of guessing. An opt-in flag that changes nothing by default cannot regress existing behaviour.

---

## Documenting a limitation in a test comment does not count

**2026-07-20, Phase 4 review.** The off-hours anchoring quirk was accurately described in a comment inside `test_scenario_composer.py`, and the test deliberately routed around it. The knowledge never reached the design spec, the composer, the advisory, or the catalog, so the shipped flagship scenario still tripped over it and the operator-facing advisory printed a span derived from the bug.

**Rule:** a caveat that only exists where tests are read is invisible to the operator. Put it where the consequence lands: the spec, the emitted artifact, and the data file that triggers it.

---

## Check your own invocation before reporting a tool as broken

**2026-07-21, UAT r2.** `python -m pytest -q` stopped printing its `N passed` summary. I reported it upward as a possible repo or plugin quirk and offered to investigate. The cause was mine: `pyproject.toml:82` already sets `addopts = "-q"`, so my extra `-q` made it `-qq`, and double-quiet suppresses the summary line. Nothing was wrong with the repo, pytest, or the venv.

**Rule:** when a tool behaves oddly, read its config for the flags it already applies *before* attributing the behaviour to the tool, the environment, or the codebase. A wrong attribution is expensive twice: it wastes the investigation, and it plants a false defect in whatever record it reaches.

**Corollary:** verifying by exit code was right and should have come first. `EXIT=0` settled correctness immediately; the missing summary line was cosmetic and never evidence of failure.

---

## A plan document rots, and nothing fails when it does

**2026-07-21, UAT r2.** `tasks/uat-plan.md` was 2 days old and already wrong in six places: it gated on "179 tests green" (actual 235), named a product-under-test commit three PRs stale, listed the use-case detail panel as unbuilt after PR #6 shipped it, required untracked `re-fresh-*.md` files to be present, and carried three "open" defects of which two were already fixed. Executing it as written would have produced failures that were really just stale expectations, and would have spent DJR's manual-testing time re-confirming closed defects.

Code has tests that break when reality moves. A plan, a spec, or a runbook has nothing. It reads exactly as authoritative on day 60 as on day 1.

**Rule:** before executing any plan older than the last merge, re-verify its factual claims against the current tree — counts, commit ids, "not built yet" statements, and open-defect lists especially. Cheap: five greps closed all six here. Record the re-verification date next to each claim so the next reader knows how stale it is.

**Corollary:** when revising a signed-off document, retitle the old verdict to its original scope rather than editing it in place. Round 1's GO covered Phases 1/1.5/2/3 against `8fe3d31`; silently letting it appear to cover Phase 4 and an installer that did not exist when it was signed would have been the single worst outcome of the edit.

---

## A dry run cannot find what only a real run creates

**2026-07-21, installer validation.** `scripts/install.sh` had been "verified" for weeks by `--dry-run`, PATH-shimmed function harnesses, and reasoning about package names. One real run in `ubuntu:22.04` found two High defects in under a minute:

1. The predicted one. It installed packages, re-checked, then died `still missing after install` (exit 3) having mutated the host for no benefit.
2. **One nobody had predicted.** `apt-get install -y` carried no `--no-install-recommends`, so apt pulled its full recommended closure: `tilix` (a GUI terminal emulator), `libgtk-3-bin`, `libvte`, `ubuntu-mono`, `humanity-icon-theme`. Onto a headless server. For a tool whose audience runs it next to a SIEM.

The second defect was **structurally invisible** to every verification method used. `--dry-run` prints the command it would run; it never resolves a dependency tree, so the GTK stack does not exist until apt actually computes it. No amount of re-reading the script would have surfaced it.

**Rule:** when a component's whole job is to interact with an external system, a test that stops short of that interaction is not a weak test, it is a different test. It verifies your model of the system, not the system. Get a real one: a container is minutes of setup and settles questions that inference cannot.

**Corollary:** the fix direction also came from the real run, not from the spec. The plan proposed version-qualified package names. Measurement showed Ubuntu 22.04's `python3.11` is `3.11.0~rc1`, a release candidate that was never updated, so that fix would have silently placed operators on a pre-release interpreter. The correct design was to ask the package manager what it would install and refuse before taking sudo when the answer is insufficient.

---

## In a function whose stdout is data, every diagnostic goes to stderr

**2026-07-21, installer fix.** I wrote a resolver whose stdout is read by the caller as a package list:

```bash
while IFS= read -r name; do packages+=("$name"); done < <(resolve_packages_for "$logical")
```

Inside it I called the script's own `warn` helper, which prints to stdout. That warning would have been consumed as a **package name** and passed to `apt-get install`. Caught on the first container run only because a second bug masked it first.

The second bug: the resolver signalled failure with `return 1`, which under `set -E` tripped the ERR trap and printed a generic `installation failed` banner ahead of the specific, actionable refusal message. Returning non-zero for an *expected* outcome is what caused it.

**Rule:** a function that returns data on stdout has a contract as strict as a return type. Diagnostics go to stderr, always. And an expected negative result is not an error: signal it in the data (empty output) rather than through an exit status that error-handling machinery will interpret as a crash.

---

## The dangerous failure is the one that reports success

**2026-07-21, UAT case INST-18.** The installer's `verify_cmd` allocated a temp file for stderr capture:

```bash
err="$(mktemp -t replicant-verify-err.XXXXXX)"   # unchecked
if ! ( cd "$REPO_ROOT" && "$@" ) >/dev/null 2>"$err"; then
```

Where `mktemp` fails, and it does on a read-only or full `/tmp` or in a hardened container, `err` is empty. `2>""` cannot open, so **the command never runs**, and the function returns 0. The installer printed `[ok] catalog loads` for a check it had not performed. Live output showed `mktemp: Permission denied` on stderr and the green tick on stdout, simultaneously.

Note the shape of it. This was not verification that broke. It was verification that **lied**, in the direction of reassurance, in a script whose entire stated purpose is to prove an install works. A crash would have been strictly safer: loud, obvious, and it would not have shipped.

**Rule:** for any check whose output is a claim about the world, ask what happens when the *check's own machinery* fails, not just when the thing under test fails. If a broken harness can produce a pass, the harness is worse than nothing, because it converts an unknown into a false assurance. Fail closed: no evidence means no pass.

**Corollary:** the tell was an unchecked assignment whose result becomes a redirect target. An empty string there is never a benign default, so treat "allocate a resource that something later depends on" as a checked operation every time.

**Corollary:** prove the bug before fixing it, and prove the fix with a control. Here that meant showing `verify_cmd /bin/false` took the success path with a broken `mktemp` and the failure path with a working one, then re-running both against the real function after the change. Without the control, "it returns non-zero now" proves nothing about whether the command actually ran.

---

## Do not assert a guarantee the mechanism does not provide

**2026-07-21, first real CI run.** `test_scenario_loopback_udp_delivers` asserted:

```python
assert len(received) == result.event_count > 0
```

SCEN-001 emits 1133 datagrams as fast as the socket accepts them. When the kernel receive buffer fills before the reader thread drains it, UDP drops the surplus. That is not a defect, it is the protocol working as specified. On an idle laptop nothing is dropped and the test is green. On a contended CI runner it failed at 890/1133.

The test therefore reported "transport regression" when the true cause was CPU scheduling. Two costs, and the second is worse: the failure is misdirecting, and it is intermittent, which is how a suite stops being believed. A test that cries wolf gets muted, and then the one real failure gets muted with it.

The fix was not to loosen the assertion and move on. The exact-delivery claim moved to a **TCP** test, where the transport genuinely guarantees it, and the UDP test now asserts what UDP actually promises: something arrived, nothing extra arrived, and the bulk got through. Coverage got stronger, not weaker.

**Rule:** before asserting equality on anything crossing a boundary, ask what the boundary guarantees. UDP does not guarantee delivery, filesystems do not guarantee ordering, `sleep(n)` does not guarantee elapsed wall time, and a network call does not guarantee a bounded latency. Assert the real contract, and put the strict assertion where the strict guarantee actually exists.

**Corollary:** verify a concurrency or timing fix under the condition that broke it, not under the condition you develop in. Five passes on an idle machine proved nothing here. Three passes with every core saturated proved something.

**Corollary:** this is also the argument for CI existing at all. The flake had been latent for weeks and passed every local run. Its first execution on shared, contended hardware surfaced it immediately.
