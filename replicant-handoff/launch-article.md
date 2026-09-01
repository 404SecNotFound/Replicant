# A rule that has never fired looks identical to a rule that can never fire

*Replicant generates FortiGate, PAN-OS and Check Point CEF that your parser will actually accept, streams it to your collector, and never touches a real host. Apache-2.0.*

---

Take the SIEM you are responsible for and ask one question: how many of its rules have fired in the last ninety days?

Then the harder one. Of the rules that have not fired, how many are silent because the behavior genuinely has not occurred, and how many are silent because the rule is broken?

Most teams cannot separate those two piles. Both are quiet. Both pass review. Both sit in the content pack with a use-case ID next to them and a green tick in the coverage spreadsheet. One of them is a control. The other is a hypothesis wearing a control's clothes, and you find out which at the worst possible moment.

The gap is not writing the logic. It is that nothing in the workflow forces you to watch it fire, so the one check that would catch a wrong rule is the one that gets skipped.

## Why the usual options do not close it

**Fidelity without control.** Replaying production traffic, or running the real attack in a lab, both give you realism and both take away shaping. You cannot ask a pcap to produce exactly the case your rule cares about, at the volume that trips your threshold, on demand. The real attack additionally needs the offensive tooling, a conversation with your security team you did not want, and it does not reproduce: run it twice, get two datasets.

**Control without fidelity.** Hand-crafting a few log lines is fast and proves your parser works. It does not prove your detection works. A rule with a threshold of "more than 200 unique destination ports in 60 seconds" is not exercised by four lines pasted into a test file. You validate the syntax and assume the statistics.

**And the generic generators miss the thing that actually matters.** Most write plausible-looking records rather than a specific product's records. Your SIEM's parser does not accept plausible. It accepts the exact field order, the exact escaping, the exact signature ID, and the exact per-action field set, or it drops the event into a parsing-failure queue where your rule never sees it. A generator that gets the shape roughly right tests nothing, because the event never reaches the logic under test.

So validation gets deferred. The rule ships. The spreadsheet goes green.

## What Replicant does

It fabricates firewall telemetry in CEF, streams it over syslog to your collector, and ties every generated behavior to a named detection use case.

```bash
replicant run REP-002 --intensity high --seed 1337 --to-file ./scan.log --no-send
```

That is a vertical port scan, deterministic under seed 1337, written as FortiGate CEF. It emits 4,000 events: 4,000 unique destination ports against a single host, mostly denied, with source, destination and protocol held constant. Which is what a vertical scan looks like on the wire, and what your threshold logic actually has to catch. Point it at a collector with `--host` instead of a file and it streams over syslog.

The format is exact, not approximate. One line from that run:

```
CEF:0|Fortinet|Fortigate|v7.4.3|00013|traffic:forward deny|4|deviceExternalId=FGVMSYNTH0000001
FTNTFGTlogid=0000000013 cat=traffic:forward FTNTFGTsubtype=forward FTNTFGTlevel=warning
FTNTFGTvd=root FTNTFGTeventtime=1752586800 src=10.20.30.139 spt=7069
deviceInboundInterface=port2 dst=10.20.40.224 dpt=28971 deviceOutboundInterface=port1
proto=6 act=deny FTNTFGTpolicyid=0 FTNTFGTservice=tcp/28971 FTNTFGTpolicytype=policy
externalId=14801 out=0 in=0 FTNTFGTsentpkt=1 FTNTFGTrcvdpkt=0
```

The accept record from the same run carries `FTNTFGTpolicyid=7`, `app`, `FTNTFGTtrandisp` and a session duration with real byte counts. This deny record carries none of them, zeroes the counters, and adds `FTNTFGTpolicytype`. FortiOS emits a different field set per action, and the profile reproduces that split rather than emitting one shape with the action swapped. That is the level at which a SIEM parser cares.

Twenty-four techniques ship today, each mapped to a detection use case rather than only to an ATT&CK ID, from periodic C2 callback, vertical port scan and DNS tunneling through DGA NXDOMAIN clusters, DNS-over-HTTPS policy bypass, first-contact with a newly registered domain, and proxy-relay lag. Every entry added past the original eleven is anchored to a peer-reviewed detection paper with measured results. The use-case IDs are a taxonomy, not a standard; remap them to whatever your content pack calls these.

Three vendor profiles render the same technique into their own CEF dialect: FortiGate, Palo Alto PAN-OS, and Check Point. One catalog and one engine drive all three; only serialization differs. FortiGate is the verified profile, pinned field-for-field to a golden oracle; PAN-OS and Check Point ship as beta, modeled from public documentation and marked `[Unverified]` until a live appliance confirms them.

## Four decisions

**It is deterministic.** Same seed plus technique plus parameters produces byte-identical output within a release. This is the feature that turns validation into regression testing: pin a dataset to a rule, re-run after a tuning change, diff. Without it you are comparing a rule change against a data change and learning nothing. Run the same scenario twice at one seed and diff: byte-identical, the paired advisory document included. (Emitted packet counts vary per flow as of this release, so a dataset pinned to an older version is regenerated, not assumed.)

**The CEF is pinned to an oracle, not to intent.** Each vendor profile has a reference document with eight golden sample lines, and a test reproduces every one byte-for-byte from the profile and serializer. When someone reorders a field six months from now, the test fails. "Looks right" is not a passing condition.

**Scenarios chain techniques into a timeline.** Individual techniques validate individual rules; real detection work is correlation. Three curated scenarios compose techniques into one deterministic multi-stage timeline sharing one victim host and one adversary IP. SCEN-001 runs external recon, then C2 an hour later, then bulk exfil aligned to the next off-hours window: twelve hours of timeline in a single reproducible file. The longest chain is four stages.

Each run writes an advisory document beside its manifest, mapping the chain to ATT&CK tactics, naming the cross-stage correlation key, and flagging catalog tactics the chain does not cover. That advisory is deliberately bounded. It gives you coverage and correlation context, it does not write rule logic, and it says so in its own header. Detection design is yours. A generated rule you did not reason through is another hypothesis in a costume, which is the exact problem this tool exists to remove.

**It writes log text and nothing else.** This one is about getting the tool approved, not about features. Replicant never executes commands, scans hosts, resolves or contacts real infrastructure, or moves data. Every entity is synthetic: RFC1918 plus the RFC 5737 documentation ranges, with DNS parents drawn from the reserved documentation domains and the non-resolvable `.invalid` TLD, none of which it ever resolves. At run time the only network egress is the collector you configure, and if you configure none, sends fail closed rather than defaulting to something convenient. Installing pulls packages from your distribution, PyPI and npm; that is install-time, and the runtime rule is unchanged. On a send to a non-loopback collector, every line carries a synthetic marker with the run id by default, so lab data stays separable from production and a mistaken injection is traceable and reversible: Replicant is a detection-lab tool, not a production SIEM component, and it says so in a deployment-boundary document. Every run writes a manifest recording seed, technique, parameters, entities, target, counts, times, and the marking decision.

You can hand that paragraph to whoever signs off on tooling in your environment.

## I pointed the argument at myself

There is an obvious way for a project like this to be hypocritical, and I walked into it three times.

The install script had been verified for weeks. Not carelessly: `--dry-run` walked the full decision path, PATH-shimmed function stubs exercised the branches, shellcheck was clean, and the package names were reasoned through against vendor documentation. Every check passed. Note that last one.

The first time it ran on real Linux, it broke in two ways. **All of this is the installer. None of it is the generator**, which has been under test since the first commit and is pinned to golden lines.

**The predicted one, and it was worse than predicted.** On Ubuntu 22.04 the script installed the distribution's default Python, re-checked, found it still below the 3.11 minimum, and died. Not merely unhelpful: it took sudo, changed the host, and then failed. The documented fix was to use version-qualified package names, and measurement showed that fix was wrong on the distribution that most needed it, because Ubuntu 22.04 ships `python3.11` as `3.11.0~rc1`, a release candidate that was never updated. Following the plan would have quietly moved operators onto a pre-release interpreter.

**The one nobody predicted, and could not have.** On Ubuntu, `apt-get install` without `--no-install-recommends` pulled the full recommended closure, which included `tilix`, GTK, and a desktop icon theme. A GUI terminal emulator, installed onto a headless server, by a tool whose audience runs it next to a SIEM. No amount of re-reading the script would have found it: `--dry-run` prints the command it would run, it never resolves a dependency tree, so the GTK stack does not exist until apt actually computes it. It took about sixty seconds to find once a real package manager was involved.

**And then the one that actually matters.** Fixing those, I wrote a test case for the error path, ran it, and found this: the installer's own verification function allocated a temp file with an unchecked `mktemp`. Where mktemp fails, on a read-only or full `/tmp`, the path came back empty, the redirect could not open, **the command never ran, and the function returned success anyway**. So the installer printed a green `[ok] catalog loads` for a check it had not performed. The live output showed `mktemp: Permission denied` on stderr and the green tick on stdout, at the same moment.

That is not verification that broke. That is verification that lied, in the direction of reassurance, inside the script whose entire stated purpose is to prove an install works.

Which is the coverage spreadsheet, exactly. A green tick that means nothing, in a system built to tell you whether things work. I wrote a tool because that pattern costs detection teams real incidents, and then shipped the same pattern in the tool.

A dry run verifies your model of a system. It does not verify the system. A test that stops short of the real interaction is not a weaker version of the real test; it is a different test, answering a different question, and the difference only shows up when it matters.

All three are fixed, and all three are now regression-guarded in CI, which runs the installer inside real Debian, Rocky and Ubuntu containers and asserts the outcomes: including that a refusal leaves zero packages installed, and that no desktop package ever comes along again.

## Before you point it at a SIEM

One caveat that will cost you an afternoon if you meet it cold, and it is the same class of problem.

Event times derive from a fixed anchor, which is what makes runs byte-identical. The syslog header, though, is stamped at send time. So the header says now and the CEF `eventtime` says whenever the anchor is. If your SIEM keys on receipt time, the run looks normal. If it keys on the parsed event time, which is the correct behaviour for an accurate timeline and an ordinary LogRhythm MPE mapping, the events land outside every recent-window rule and nothing fires.

Which is indistinguishable from your detection being broken. Pass `--anchor now` when sending live, and Replicant warns you if you forget.

## What it does not do

Stated plainly, because a limitations section you have to go looking for is marketing.

**The end-to-end claim is not proven yet, and this is the big one.** Everything above is measured on loopback. A rule firing in a real SIEM on Replicant's telemetry has not been observed end to end, so the honest posture is "generates vendor-accurate CEF, detection-unverified." The generator is the verified half: the FortiGate CEF is byte-checked against its oracle. Whether the whole path delivers and the rule fires is the activation milestone, and until it clears every "it fires" reading is loopback-only. This release also flags, per technique, whether a green result exercises your shipped rule or only its parser: a synthetic GeoIP tag, a `.invalid` DGA label or a domain with no registration date exercises the parse and threshold path, not the enrichment your production rule keys on, and the catalog now says so.

FortiGate is the profile modeled field-for-field first and is the verified oracle. The Palo Alto and Check Point profiles are beta: grounded in vendor documentation and published samples but marked `[Unverified]` against live builds, as are two FortiGate signature IDs. Confirm those against your own appliance before you rely on them for customer work.

The installer is verified against live package repositories on Debian 12 and Rocky 9, which install, and Ubuntu 22.04, where the correct behaviour is a refusal. AlmaLinux, RHEL proper, Arch and openSUSE carry package mappings that have not been exercised. The sudo elevation path is unverified too, because the container runs that validated everything else execute as root.

Scenario composition is CLI and menu only; the web UI has no scenario surface yet. The two ops surfaces that turn an offline run into a CI signal, a detection-regression check and a GitHub Action, are positioned but not built: they wait behind the end-to-end milestone above.

None of that is buried in an issue tracker. It is in the README, the CHANGELOG and the release notes, because the alternative is you finding out during an engagement.

## Get it, and one ask

On Linux:

```bash
git clone https://github.com/404SecNotFound/Replicant.git
cd Replicant
./scripts/install.sh          # Apache-2.0, Python 3.11+
```

Anywhere else, or if you prefer to see what you are installing:

```bash
python3 -m venv .venv && ./.venv/bin/pip install -e ".[dev]"
./.venv/bin/replicant list
```

CLI-first, no Node toolchain: `pip install replicant` (add `[web]` for the browser UI), or run it in a container with `docker build -t replicant . && docker run --rm replicant list`. `pip install replicant` needs the package on PyPI, which is pending; until then install the wheel attached to the release with `pip install ./replicant-0.10.0-py3-none-any.whl`.

A headless CLI, a terminal menu and a browser UI, all over the same orchestrator, so anything the menu does the CLI does headless and scriptable.

**The ask.** Two of the three vendor profiles are `[Unverified]` against live builds. If you have a PAN-OS or Check Point box and ten minutes, the single most useful thing you can do is run one technique against it and tell me where the reference doc is wrong. Open an issue with the real line next to mine. That is worth more to this project than any number of stars.

And for the rest: you will not know how many of your rules are hypotheses until you make them fire. That is a Tuesday afternoon, not a project.

---

*Replicant uses MITRE ATT&CK. Copyright 2026 The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation. ATT&CK is a registered trademark of The MITRE Corporation. Use does not imply endorsement.*
