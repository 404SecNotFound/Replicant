# LinkedIn post draft, v0.7.0

Replaces the approved v0.5.2 draft, which is now three releases stale (v0.6.0
Factory UI, v0.6.1 diagrams, v0.7.0 catalog fixes). Nothing here is published
until DJR says so.

The angle is deliberately not "we shipped features". The most interesting thing
that happened to this project this month is a defect class, and detection
engineers are the audience most likely to recognise it in their own tooling.

---

## Draft A: the defect class (recommended)

I build a tool that generates synthetic firewall telemetry so detection
engineers can test rules without waiting for a real attack. Its entire value
rests on one claim: the telemetry is what the catalog says it is.

An external review found three places where it wasn't. Every one of them had a
green test suite over it. 952 tests, all passing.

One technique models an internal host relaying traffic for an outside client.
The whole point of it is timing correlation: inbound leg, short unpredictable
lag, outbound leg. A detection that keys on a fixed window should struggle with
it. The catalog said the lag was jittered.

The code computed that lag with an integer divide that floored every value to
zero, then clamped it to one second. Every preset. Every event. The technique
whose stated purpose was defeating naive fixed-window correlation was emitting
a perfect fixed window.

A second one declared a 120 second scan window and finished in six. A third
shipped a benign look-alike, so a detection has to separate signal from
plausible noise rather than alerting on the only pattern present, except the
look-alike ran for minutes against a twelve hour session. Any duration
threshold separated them instantly. The control wasn't controlling anything.

None of that is exotic. What makes it worth writing down is why nothing caught
it: no test asserted that the code did what the catalog text promised. The tests
checked the code against itself. The documentation was the specification and
nothing read it.

A detection validated against the wrong signal doesn't fail. It passes, and you
file the rule as covered.

That's the part that transfers. If you generate test data, replay captures, or
maintain a detection lab, the question isn't whether your tests pass. It's
whether anything you own compares what your data says it is against what it
actually is.

Fixed in v0.7.0, with the tests that were missing. Apache-2.0, MITRE ATT&CK
grounded, 24 techniques across FortiGate, Palo Alto and Check Point.

[link]

---

## Draft B: shorter, for lower effort

952 passing tests did not catch three defects in my synthetic telemetry
generator. Here's why.

The tool emits fake firewall logs so detection engineers can exercise rules
without waiting for a real attack. Its whole claim is that the telemetry matches
what the catalog describes.

One technique exists specifically to defeat naive fixed-window timing
correlation. An integer divide floored its jitter to zero and a clamp made it a
constant one second, so it emitted exactly the fixed window it was built to
defeat. Another declared a 120 second window and finished in six. A third
shipped a benign look-alike that any duration threshold could separate at a
glance, which makes it decoration rather than a control.

Nothing caught it because no test compared the code to the catalog text. The
tests checked the code against itself.

A detection validated against the wrong signal doesn't fail. It passes.

v0.7.0 fixes all three and adds the tests that were missing.

[link]

---

## Notes before posting

- **Do not claim the lab test.** Every timing and delivery claim in this project
  is still loopback only. Neither draft asserts otherwise, and the temptation to
  add "validated against a live SIEM" should be resisted until it is true.
- Draft A is roughly 320 words, which is past the LinkedIn fold. The first two
  lines carry it.
- No em-dashes anywhere in this file, per house style. Both headings originally
  used one; caught on a check rather than by eye, which is the only way this
  rule ever gets enforced.
- The honest framing is that the review was external. Both drafts say so.
