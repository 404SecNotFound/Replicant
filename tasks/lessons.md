# Lessons

Patterns worth not repeating. Append after any correction or review finding.

---

## A second theme is an audit of the first one

**2026-07-29, light theme.** Building the light palette meant measuring contrast
pair by pair instead of judging it. Four defects fell out, and **three of them were
in the dark theme that had been shipping for weeks**:

- `--text-4` is documented in the design spec as "decoration only, never body
  text". It was body text in seven places, at 2.78:1. Failing in dark. Nobody had
  noticed, because at 9.5px a faint label reads as *intentionally* faint.
- Near-white on the red fill: 3.02:1.
- 11 of xterm's 16 default ANSI colours fail on our light card, and 6 of 16 on our
  dark one, so the embedded Rich menu was already partly illegible.

The design spec said "WCAG AA contrast (tokens above verified)". The tokens had been
verified; the *usage* never was. A palette can be correct while every screen built
from it is not, and no amount of re-reading the palette shows that.

**Rule:** measure contrast on the **rendered page**, walking real elements and
resolving each one's effective background through its ancestors, not on the token
table. Tokens are inputs. What ships is the composition.

**Corollary:** the second theme is worth building partly *because* it forces the
first one through a check nobody would otherwise run. Any parallel implementation
does this: a second vendor profile, a second transport, a second platform. The value
is not only the new thing.

**Corollary:** target the existing theme's own measured ratios rather than a fresh
standard. It makes the new one a translation instead of a second design, and it
turns "is this right?" into a comparison instead of a judgement call.

---

## Child effects run before parent effects, so the DOM is not what you think

**2026-07-29, terminal recolour.** The theme class was applied in an effect in
`App`. `TerminalView` resolves its xterm palette by reading the CSS variables off
the document, also in an effect. React runs **child** effects before **parent**
effects, so the child read the variables while the outgoing theme's class was still
on `documentElement`.

The visible result: clicking the toggle switched the entire application to light and
left the terminal pane black. Every test passed. jsdom has no cascade and no layout,
so nothing in the suite could have observed it, and reading either component alone
shows correct code. The bug lives only in the ordering *between* them.

**Rule:** when a child reads state from the DOM that a parent writes, do not leave
the write to a parent effect. Write it synchronously where the change originates
(the event handler), so it is already true before any child renders or re-runs.

**Corollary:** "resolve it from the stylesheet so there is one source of truth" was
still the right call, and it is why the fix is three lines rather than a duplicated
palette in TypeScript. The defect was in *when* it was read, not in reading it.

---

## The environment a process runs in decides what "printing" means

**2026-07-29, systemd unit verification.** The web server's startup banner prints
the URL with the token in it. That is correct on a terminal: the operator needs
something to click. The unit ran perfectly in a container on the first try, and the
journal showed this:

```
replicant[175]:   URL : http://127.0.0.1:9787/?token=BuvY6dvcTqyDs1-CSdPueC8Jtv...
```

Under systemd, **stdout is the journal**. So a codebase that had just gone to the
trouble of writing the token `0600` in a `0700` directory was also writing it in
cleartext to a file readable by root and the whole `systemd-journal` group, on every
single start. The 0600 was not wrong; it was simply bypassed by a different exit.

Nothing about reading the unit file or the server code would have shown this. It
needed the process to actually run under the supervisor it ships for.

**Rule:** when code writes a secret, enumerate every sink it reaches, not just the
one you designed. stdout, stderr, logs, argv (visible in `ps`), environment
(visible in `/proc/PID/environ`), crash reports, and shell history are all sinks. A
protection applied at one of them means nothing if another is unguarded.

**Corollary:** the fix has to be conditional on context, not global. Suppressing the
token everywhere would break the interactive path that legitimately needs it, so the
banner keys on `sys.stdout.isatty()`. And it is now asserted where the consequence
lands: a check greps the live journal for the live token.

---

## Check the premise of a spec item before building it

**2026-07-29, web UI navigation.** The spec asked for "toggle filters for vendor
applicability and log type". Log type splits the catalog five ways and is useful.
Vendor applicability splits it **zero** ways: all three profiles implement all six
render paths, the catalog uses five, so every one of the 24 techniques applies to
every one of the 3 vendors. The control could never exclude a single entry.

It would have taken twenty minutes to build and would have looked, to an operator,
exactly like a working filter. This is the same failure as a test that cannot fail,
moved into the UI: a control whose output cannot change is decoration, and it is
worse than nothing because it invites the operator to trust it.

**Rule:** before implementing a filter, a toggle, a grouping, or a badge, run the
data through it and count. If the result is one bucket, the control is inert. Say so
and hand the decision back rather than shipping a surface that implies a distinction
the data does not contain.

**Corollary:** the same query answers the design question. `action` was the only
other axis that splits the catalog (6 values); `benign_baseline` and `implemented`
are uniform across all 24 and would have been equally inert. Measuring once ruled out
two more bad options for free.

---

## Pick-a-value decisions get measured, not reasoned about

**2026-07-29, fixed web port.** Choosing the default port, I reasoned about
collisions from memory: 8787 is RStudio Server's default, otherwise it looked fine,
and it was what the spec suggested. The first real start failed instantly with
`Address already in use`. `lsof` showed DJR's own `mpe_studio.api` had been holding
127.0.0.1:8787 for nearly three days, on the very machine the tool is developed on.

The whole value of a fixed port is that the URL stays predictable. A default that
collides on the author's own box does not have that property, and no amount of
reasoning about likelihood would have found it. One `lsof` would have.

**Rule:** when picking a constant that has to coexist with an environment you do not
control (a port, a path, a filename, an env var, a config key), query the environment
before choosing. It is one command, and the alternative is discovering the conflict
from a user.

**Corollary:** the failure path validated itself for free here. Because the code was
already written to refuse a busy port with a message naming the port and the flag,
the collision produced a correct, actionable error instead of a confusing one. Build
the loud-failure path before you need it and the accident becomes a test.

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

---

## A number from a throwaway script is a claim, not a measurement

**2026-07-30, sizing the CI paths filter.** The question was how many recent commits were documentation-only, to decide whether a `paths` filter was worth adding. A shell loop answered: 12 of the last 60, and it printed a tidy list of plausible commit subjects.

The number was fabricated. The loop was:

```sh
files=$(git show --pretty=format: --name-only "$c" | sort -u)
for f in $files; do case "$f" in docs/images/*|tasks/*|...) ;; *) only=0; break;; esac; done
```

**zsh does not word-split unquoted parameter expansions.** In bash `$files` splits on newlines and the loop tests one path per iteration; in zsh it stays a single word, so the loop ran once against the entire multi-line blob. `docs/images/*` then matched the whole blob, because `*` spans newlines. Every commit whose sorted file list merely *began* with a docs path was classified documentation-only.

It survived because the output looked right. The subjects all began `docs:`, the count was plausible, and nothing errored. It was caught only by spot-checking one entry against `git show`, which listed `replicant/cli/menu.py` and two test files. Re-measured correctly: 34 of 112.

**Rule:** a measurement is not evidence until one of its results has been checked by hand, against a different tool. Pick the row that would be most embarrassing if wrong and verify that one. The failure mode here is not a crash, it is confident precision, which is far more expensive because it gets quoted in a commit message and then in a decision.

**Corollary:** do not write analysis in shell. `for f in $x` means different things in bash and zsh, and the version that gives a wrong answer gives it silently. Use a language with real lists, and keep the script so the result can be re-derived and audited.

**Corollary:** the same applies to the correctness of any reimplementation of somebody else's matcher. `tests/test_ci_paths_filter.py` reimplements GitHub's glob semantics and says so in its docstring, including what it does not model. That labelling is the difference between a guard and a false assurance.

## A default is a change to every caller that never named the value

Making plan pacing the default for a live send was the intended behaviour, and I reasoned
carefully about the blast radius: four test files inherited a 238 minute timeline and were
fixed to say `pace="burst"`. Then I shipped it, and CI hung for fifty minutes on two
container jobs, because `scripts/install.sh` verifies the install with a live loopback send
and had never named a pace either.

The local suite was green the entire time. The callers I thought about were the ones with
tests; the caller that mattered ran unattended and had none.

**Rule:** when changing a default, enumerate callers by grepping the whole repository for
the operation, not by fixing whatever the test suite complains about. A green suite after a
default change is evidence about the suite, not about the change. `tests/test_shipped_commands.py`
now fails if anything under `scripts/` or `.github/workflows/` sends to a collector without
naming a pace, which is the class of guard that would have caught it.

**Corollary:** two guards can cancel each other out. The runtime rate floor added alongside
the schedule then masked the catch-up check beside it: once the loop ran late the floor set
the deadline to roughly now, so a lag measured against that deadline read zero and the
resync never fired. Each was correct alone. Test the interaction, not just the parts.

## `git branch -r` is a local cache, not the remote

I reported that nine merged branches needed cleaning up and offered a sweep. Eight of them
had not existed on the remote for some time; `git branch -r` was listing stale
remote-tracking refs that had never been pruned. `git branch -r --merged` happily confirmed
they were merged, because they were — existence was the thing never checked.

**Rule:** `git ls-remote --heads origin` is the authoritative answer, and `git fetch --prune`
is what reconciles the local view. Any claim about what exists on a remote must come from one
of those, never from `git branch -r`. The failure mode is a confident, specific, wrong
statement — the same shape as the measurement lesson above.
