# TypeSafe experiments for Replicant, 2026-09-16

Natural-language catalog discovery was the strongest result. TypeSafe selected
an acceptable technique for all 26 matchable requests across the pilot and tougher
follow-up, and rejected all six requests requiring capabilities the catalog lacks.
A simple untuned BM25 baseline ranked an acceptable technique first on 21/26 of
the same matchable requests. These results support a small authoring-tool prototype;
they do not establish production accuracy or justify model-controlled execution.

All changes in this experiment are development artifacts. The packaged runtime,
telemetry generation, collector configuration, UI, and code-derived advisory were
not changed.

## Measured results

| Experiment | Cases | Agreement with predefined labels | Relevant detail |
| --- | ---: | ---: | --- |
| Technique discovery pilot | 24 | 24/24 | 21 matchable requests, three unsupported capabilities |
| Discovery challenge follow-up | 8 | 8/8 | Negation, multiple constraints, missing enrichment, quoted instructions |
| Existing scenario selection | 12 | 12/12 | Eight matches; four absent, wrong-order, or hybrid chains rejected |
| Coverage-claim review | 16 | 16/16 | Six supported, six contradicted, four unsupported claims |

There were 60 unique cases, with expected answers hidden from the API. Twelve
decisions were repeated in three unchanged batches; all twelve selected the same
label on the repeat. This is limited repeat agreement, not a determinism guarantee.

For discovery, the initial BM25 top-one result was 16/21; the follow-up was 5/5.
Combined top-three recall was 23/26. BM25 received the same catalog fields as the
model but used a basic untuned tokenizer with no stemming or stopword removal.
It has no calibrated abstention mechanism, so unsupported requests are excluded
from that ranking comparison. This is not a comparison against optimized search.

The existing UI's whole-query substring search returned no entries for these
26 long-form matchable requests. That demonstrates a different user need from
its intended short keyword and identifier filtering, not a failure of that filter.

All measured responses reported `jev-1.13.0`. The 18 evaluation requests had a
median latency of **1.179 seconds**, with a range of 0.817 to 1.420 seconds. Each
request evaluated four cases, so these are batch request times, not a measured
single-query UI latency. Total time waiting for those requests was 21.034 seconds.

Including the one preliminary smoke request, the 19 successful live requests used
**221,204 input tokens and 15,323 output tokens**, as reported by the API.
Dollar cost was not calculated because account-specific billing was not verified.

## What the probabilities reveal

The prespecified suggestion gate required a non-`NO_MATCH` Choice, Choice
confidence at least 0.8, and a companion Noul of at least 0.8 for whether any entry
could satisfy the request. Across discovery, it suggested 25/26 matchable requests
and none of the six unsupported requests. The withheld case explicitly accepted
either ordinary or jittered callbacks; its correct Choice had confidence 0.68.

The second ambiguous case accepted either concentrated or distributed password
spray. The model chose an acceptable option with confidence 0.89. Thus high
confidence does not establish that the user's preference is uniquely specified.
The interface should preserve acceptable alternatives and let the operator choose.

For scenario selection, that gate surfaced 7/8 valid matches and no unsupported
chain. A valid DNS-exfiltration request containing a misleading password-spray
mention received a correct answer but confidence 0.74.

Claim review was accurate by label, but confidence was below 0.8 on five cases:
four supported claims and one contradicted claim. In particular, the shipped
NXDOMAIN foil claim was supported at 0.27, and the false assertion that REP-011
ships a negative-control foil was contradicted at 0.43. A high-confidence-only
claim filter would miss that latter issue. Keep all findings visible for review.

The Noul is about the existence of **any** matching entry, not the correctness of
the selected candidate. Confidence reflects the Choice distribution; neither
quantity is permission to execute a run or proof that a detection works. The
0.8 cutoffs were fixed before evaluation and are not calibrated production gates.

## Proposed changes, in priority order

1. **Add a separate catalog-finder tool for authors and detection engineers.**
   Accept a short description and return existing technique IDs, their objectives,
   relevant limitations, and `NO_MATCH` when required evidence is absent. Keep the
   tool outside the `replicant` package and require explicit invocation for API
   access. Show a suggestion or alternatives for operator selection; do not run
   commands, choose a collector, or send telemetry. Reuse validated catalog data
   rather than maintain a second catalog. [Inference] This has the clearest user
   benefit and the strongest measured advantage over the simple local baseline.

2. **Improve local UI search with reviewed aliases and objective text.**
   Add catalog `search_aliases` and include aliases plus the objective in local
   filtering. Candidate phrases can be reviewed with the authoring tool and
   committed as ordinary catalog data. This preserves collector-only runtime
   egress. For example, review phrases such as "one server many services" for
   REP-002 and "first seen by this workstation" for REP-008. [Inference] This
   should improve discovery without runtime API calls, but the experiment did
   not implement or measure alias-based search, so measure it before shipping.

3. **Add an optional documentation claim-review command.**
   Compare an author's draft claim with the relevant catalog entry and explicit
   limitations, returning supported, contradicted, or unsupported plus the source
   text for review. The pilot correctly caught all ten planted contradictions or
   unsupported assertions, including WHOIS and GeoIP claims, sub-second relay
   timing, and treating observed progression as proof of compromise. Treat it as
   a reviewer aid, not a required CI gate or a replacement for empirical testing.
   Deterministic checks should continue to enforce exact fields and known flags.

4. **Consider scenario suggestions after catalog discovery is useful.**
   Return an existing `SCEN-###` or no match. The experiment tested lookup among
   the three existing chains, not new scenario composition, offset selection,
   or entity consistency. Keep those checks in code and the advisory code-derived.
   [Inference] The perfect result on only three choices is less compelling than
   the broader discovery result, so this is a lower priority.

Before shipping a model-assisted authoring tool, collect independently labeled
operator requests covering every technique, short and vague requests, mismatched
requirements, and more adversarial quoted content. Reserve an untouched evaluation
set before changing prompts or thresholds. Measure cost and latency for actual
single-request usage, plus service failure behavior. This experiment is evidence
to prototype, not a production release gate.

## Method and limits

The main pilot used the current **26-technique** catalog and three curated
scenarios. Another agent authored discovery and claim labels from catalog evidence
before seeing model answers. The main agent authored scenario cases before API
evaluation. The challenge author knew the aggregate pilot score but did not inspect
individual predictions. Expected labels, rationales, tags, and source references
were excluded from every request. Two intentionally ambiguous discovery queries
accepted either of two IDs.

Choice questions selected IDs or coverage labels. Independent companion Noul
questions checked whether any technique/scenario matched. Questions sharing the
same state were batched four cases at a time. No questions were tuned after seeing
results. The follow-up used the same prompt and evidence construction.

The model received selected catalog metadata including objectives, distributions,
field lists, and transferability notes. Missing `emits_foil` was normalized to
false and missing `transferability` to `transfers`, matching the code defaults.
Claims were judged against that supplied evidence, not all repository documents or
external vendor facts. For example, the planted certification claim was labeled
unsupported because certification evidence was absent from the supplied catalog.
It is not an assessment of certification status and does not change the project's
standing prohibition on certification claims.

This is a small agent-authored diagnostic set. Several claims closely paraphrase
source notes, and the requests were constructed with knowledge of the catalog.
There are no real operator queries, customer logs, production SIEM measurements,
or live-vendor data. The quoted-instruction case demonstrates one handled example,
not general prompt-injection resistance. Perfect agreement here should not be
presented as 100 percent real-world accuracy.

The API key was read from the environment and used only in the authorization
header. No key, environment dump, real telemetry, or customer data was saved or
sent as model input. Both source catalogs were fetched anonymously from the public
GitHub repository and verified SHA-256 identical to the local files before the
batch ran. That verification resolved the initial automatic approval block on
exporting potentially sensitive project metadata.

## Artifacts and verification

- [Runner and usage](../experiments/typesafe/README.md)
- [Pilot results](../experiments/typesafe/results/2026-09-16/summary.json)
- [Challenge results](../experiments/typesafe/results/2026-09-16-challenge/summary.json)
- [Pilot manifest](../experiments/typesafe/results/2026-09-16/manifest.json)
- [Challenge manifest](../experiments/typesafe/results/2026-09-16-challenge/manifest.json)
- [Public-source verification](../experiments/typesafe/results/public-source-verification.json)

The result directories retain every request and response, full distributions,
latencies, usage, and hashes. The runner recreates the original requests exactly
and preserves saved manifest provenance on replay.

Black, Ruff, and mypy passed for the project and experiment runner. The initial
pytest run had 1,517 passes and three skips; 50 cases failed or errored because
the sandbox blocked sockets or the send-lock file. All 50 passed when rerun with
those permissions, including the loopback transport checks. Combined result:
**1,567 passed, three skipped**. The full run included the CEF golden tests.

Design references read live on 2026-09-16: [HTTP API](https://docs.typesafe.ai/api),
[Choice](https://docs.typesafe.ai/primitives/choice),
[Noul](https://docs.typesafe.ai/primitives/noul),
[confidence](https://docs.typesafe.ai/confidence),
[semantic search cookbook](https://docs.typesafe.ai/cookbooks/semantic_find), and
[claim-checking cookbook](https://docs.typesafe.ai/cookbooks/citation_check).

## Implementation addendum, 2026-09-27

The [authoring companion](typesafe-authoring.md) now implements `find` and
`review` as explicit source-checkout commands. Its default previews the request;
`--live` makes one API request and returns evidence and uncertainty for human
review. It is excluded from the wheel and refuses live use from the confined web
terminal. The original experiment results above remain historical evidence, not
a new accuracy measurement of these commands.

The packaged catalog now has 80 reviewed aliases across its 26 techniques. The
web filter includes aliases and objectives while retaining local phrase matching.
An execution of the actual TypeScript filter against all 80 alias phrases found
their intended techniques in 80/80 cases, compared with 0/80 using the previous
ID/name/use-case/ATT&CK fields. This is an authored-alias coverage check, not an
independent generalization test. The [query-level results](../experiments/typesafe/local-search-2026-09-27.json)
record all inputs and returned IDs.

Two live smoke checks of the new single-request CLI on 2026-09-27 returned the
expected choices: `one server many services` selected REP-002, and the claim that
REP-020 exercises WHOIS registration-age scoring was `contradicted`. Discovery
reported Choice confidence 0.99 but an existence Noul of 0.74, so the companion
surfaced its weak-match warning. Review reported confidence 0.95. Measured CLI
wall times were 2.531 and 7.197 seconds; combined usage was 14,213 input and 376
output tokens. These two checks verify the live interface, not accuracy or a
latency distribution. The [saved outputs](../experiments/typesafe/authoring-smoke-2026-09-27.json)
retain the distributions and catalog evidence. Before the calls, the exported
metadata was [verified identical](../experiments/typesafe/public-authoring-metadata-2026-09-27.json)
to the unauthenticated public catalog at `ae1976e`; newly added search aliases
are not part of the export.

To keep the supporting evidence compact in Git, each historical result directory
contains `api-records.json.gz` with the complete request/response records; summaries
and manifests remain plain JSON. The uncompressed local files are ignored by Git.
The archives preserve the original catalog context even though current `main`
has since changed.
