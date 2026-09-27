# Catalog discovery and claim review

The optional TypeSafe companion helps an author select an existing technique or
review a claim about what its telemetry can establish. It runs from a source
checkout, separately from the Replicant CLI, web service, and deterministic engine.
The live commands send catalog metadata and your supplied text to TypeSafe.

## Setup and preview

Use Python 3.11 or later from a checkout with `pip install -e '.[dev]'` completed.
No TypeSafe SDK or additional dependency is required. From the repository root:

```sh
python -m tools.typesafe_authoring find "one server many services"
python -m tools.typesafe_authoring review REP-020 \
  "This exercises WHOIS registration-age scoring."
```

Both commands preview the request without reading an API key or opening a socket.
Review that payload before using text containing sensitive information. The tool
loads `TECHNIQUE_CATALOG` through `replicant.resources` and validates it with the
same catalog models as the runtime. It does not load collector settings, logs,
manifests, arbitrary files, or repository instructions into model context.

## Live use

Export `TYPESAFE_API_KEY` in the shell, then add `--live` to make one request:

```sh
python -m tools.typesafe_authoring find "one server many services" --live
python -m tools.typesafe_authoring review REP-020 \
  "This exercises WHOIS registration-age scoring." --live --json
```

`--json` produces machine-readable output. The default model is the pilot's
versioned `jev-1.13.0`; `--model` selects a different model explicitly. The current
TypeSafe [model documentation](https://docs.typesafe.ai/models) lists supported
versions. The response records the actual model and token usage.

`find` asks a Choice over catalog IDs plus `NO_MATCH`, alongside an independent
Noul for whether any entry can satisfy the request. Candidate descriptions and
limitations come from the local validated catalog. A weak or conflicting result
is presented for review. `NO_MATCH` does not yield a technique to execute.
Alternatives contain only entries with positive reported probability, up to three.

`review` compares the whole claim with one technique's catalog evidence and
returns `supported`, `contradicted`, or `unsupported`. Low-confidence results
remain visible. The returned evidence is the source catalog metadata, not a
model-generated justification. "Supported" means supported by that supplied
evidence, not independently verified against a real appliance or production SIEM.
Objectives describe intended tests, not empirical detection performance.

Choice confidence summarizes its distribution. The Noul describes whether
**any** entry matches; it does not independently verify the selected entry.
The initial 0.8 thresholds are exploratory and have not been calibrated on real
operator queries. An ambiguous request can have several useful alternatives even
when one Choice has high confidence. A person decides what to test.

## Execution and network contract

- Without `--live`, no requests occur and no key is required.
- Live mode uses one HTTPS POST to `https://api.typesafe.ai/v1/systemone`.
  Environment proxies are disabled and redirects are refused.
- The key is read only from `TYPESAFE_API_KEY` and used in the authorization
  header. It is not a CLI flag, request-body field, or saved configuration value.
- HTTP, connection, decoding, and response-validation errors produce a concise
  stderr message and a nonzero exit. Response bodies and exception details are
  omitted from errors. There are no automatic retries or silent fallback choices.
- Requests have a 20-second socket timeout and responses are limited to 1 MiB.
  The timeout is a socket-operation bound, not a total wall-clock deadline.
- A response must have the requested question set, valid candidate IDs, matching
  types, and finite bounded probabilities before it can produce suggestions.
- `REPLICANT_WEB_CONFINED=1` refuses live mode. The companion is not invoked by
  the web UI, service, menu, or Orchestrator and is excluded from the wheel.
- It does not emit events, choose collector settings, execute commands, edit the
  catalog, or write detection rules. It writes only its output to stdout.

## Local UI search

The catalog's reviewed `search_aliases` and objective are included in the local
filter alongside ID, name, use-case ID, and ATT&CK technique ID. Matching remains
case-insensitive phrase/substring matching, with log-type toggles applied too.
For example, `one server many services` finds REP-002 and
`first seen by this workstation` finds REP-008. This is deterministic and needs
neither the companion nor an API key. It is not a natural-language classifier.

Aliases are reviewed data, not model output added automatically at runtime. They
default to an empty list for older/custom catalogs. Adding an alias does not alter
the event plan, seed behavior, manifest contract, or scenario advisory.

## Evidence and testing

The [2026-09-16 pilot](typesafe-experiments-2026-09-16.md) motivated this prototype.
Its small synthetic dataset is not a production-accuracy estimate. Historical
responses and dataset hashes remain in `experiments/typesafe/results/`.
Live API calls are optional; CI exercises the companion using mocked responses
and failure conditions and requires no credentials.

The design follows the TypeSafe skill and current [HTTP API](https://docs.typesafe.ai/api),
[semantic search](https://docs.typesafe.ai/cookbooks/semantic_find), and
[claim-checking](https://docs.typesafe.ai/cookbooks/citation_check) guidance, read
on 2026-09-27. These authoring judgments do not replace golden CEF tests, loopback
transport checks, deterministic validation, or human detection design.
