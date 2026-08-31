# LinkedIn post (primary)

How many rules in your SIEM have fired in the last 90 days?

Now the harder question. Of the ones that haven't, how many are quiet because the behaviour is genuinely absent, and how many are quiet because the rule is broken?

A rule that has never fired looks identical to a rule that can never fire. Both pass review. Both get a green tick in the coverage sheet. You find out which is which at the worst possible time.

I've released Replicant to close that gap. It generates safe, synthetic, vendor-accurate firewall telemetry in CEF, streams it to your collector over syslog, and ties every behaviour to a named detection use case. Eleven techniques, three vendor profiles (FortiGate, PAN-OS, Check Point), deterministic under a seed so you can pin a dataset to a rule and diff after a tuning change.

It writes log text. It never executes anything, scans anything, or touches real infrastructure.

Then I pointed the same argument at my own code, and this is the part worth sharing.

The installer had passed weeks of verification. Dry runs, function stubs, shellcheck, all clean. The first time it ran on real Linux it broke three times.

The third one is the one that stopped me. Its own verification function allocated a temp file with an unchecked mktemp. When mktemp failed, the redirect couldn't open, the command never ran, and the function returned success anyway. So it printed a green [ok] for a check it had not performed. Permission denied on stderr and the green tick on stdout, at the same moment.

That is not verification that broke. That is verification that lied, in the direction of reassurance, inside the script whose entire job is proving the install works.

Which is the coverage spreadsheet, exactly. I built a tool because that pattern costs detection teams real incidents, then shipped the same pattern in the tool.

A dry run verifies your model of a system. It doesn't verify the system.

All three are fixed and regression-guarded in CI, which now runs the installer inside real Debian, Rocky and Ubuntu containers.

Apache-2.0, free, and the limitations are in the README rather than buried in an issue tracker.

github.com/404SecNotFound/Replicant

#DetectionEngineering #SIEM #SecurityOperations #ThreatDetection #OpenSource

---

# Shorter variant

How many rules in your SIEM have fired in the last 90 days?

Of the ones that haven't: how many are quiet because the behaviour is absent, and how many because the rule is broken?

A rule that has never fired looks identical to a rule that can never fire.

Replicant is my attempt at closing that gap. Safe, synthetic, vendor-accurate firewall CEF, streamed to your collector, every behaviour mapped to a named detection use case. Eleven techniques, three vendor profiles, deterministic under a seed so you can regression-test a rule instead of guessing.

It writes log text. It never executes, scans, or touches real infrastructure.

One thing I'll admit publicly, because it makes the point better than any feature list. My installer's verification function printed a green [ok] for a check it had never run: an unchecked mktemp meant the command silently never executed and the function returned success anyway. Verification that lied, in the direction of reassurance, inside the script whose whole job is proving things work.

Which is the coverage spreadsheet, exactly.

A dry run verifies your model of a system. It doesn't verify the system.

Apache-2.0: github.com/404SecNotFound/Replicant

#DetectionEngineering #SIEM #SecurityOperations #OpenSource

---

## Posting notes

- **First two lines are the hook.** LinkedIn truncates around there, so the two questions have to carry the click. Do not add a preamble above them.
- **The repo link in the post body suppresses reach.** If that matters, move the URL to the first comment and put "link in the comments" in the body.
- **Best window for this audience:** Tuesday to Thursday morning your time. Avoid Friday.
- **Consider attaching `docs/images/webui-run.png`.** LinkedIn weights posts with a native image, and it is a real screenshot of a live run rather than a stock graphic.
- **Expect three kinds of reply.** Is it safe to run in production (it emits only to the collector you configure and every entity is synthetic). Which SIEMs (SIEM-agnostic, standard CEF over syslog; validated against LogRhythm first). And at least one person asking whether this is just a poor man's BAS platform (it is not a control-validation platform; it produces the telemetry so you can test the detection logic itself, and it costs nothing).
- **Do not post before the repo is public.** The link 404s for everyone but you until visibility flips.
