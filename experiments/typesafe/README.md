# TypeSafe development experiments

The measured results and proposed changes are in
[the experiment report](../../docs/typesafe-experiments-2026-09-16.md).

This directory is development tooling outside the packaged `replicant` runtime.
It sends synthetic evaluation inputs and public catalog metadata to the fixed
TypeSafe HTTPS endpoint only when invoked with `--live`. It does not invoke the
Orchestrator, generate traffic, contact a collector, or change application behavior.

The API key is read from `TYPESAFE_API_KEY` and used only in the authorization header.
The runner saves request bodies and responses, never headers or environment values.
The evaluation labels and rationales remain local. HTTP redirects are refused.

Use the project's existing development environment, which includes PyYAML:

```sh
# Prepare requests without network calls.
.venv/bin/python experiments/typesafe/run.py --output /tmp/typesafe-pilot

# Make billable requests using the exported key.
.venv/bin/python experiments/typesafe/run.py --live --output /tmp/typesafe-pilot

# Run the separately authored challenge set.
.venv/bin/python experiments/typesafe/run.py --live --challenge \
  --output /tmp/typesafe-challenge
```

The pilot makes 15 requests, including two repeated batches. The challenge set
makes three requests, including one repeated batch. Each invocation is limited to
16 requests and performs no automatic retries. Each request has a 45-second socket
timeout. Reusing an output directory replays saved responses for matching requests;
use a new directory for a fresh measurement. A changed dataset, prompt, catalog,
model, or threshold requires a fresh directory. Historical results are under
`results/`; the smoke test is separate from the measured evaluation sets.

The model is pinned to `jev-1.13.0`, resolved by the smoke test on 2026-09-16.
Exact prompts, probability distributions, latencies, token usage, dataset and
catalog hashes are retained. The `match_probability` result is the probability
that **some** catalog entry satisfies a request, not independent verification of
the selected entry. The 0.8 suggestion thresholds are exploratory heuristics.
The summary's `top3` contains at most three options with positive reported
probability, with alphabetical tie-breaking; zero-probability options are omitted.

The historical request/response records are committed as `api-records.json.gz`
in each result directory. The adjacent summaries and manifests remain plain JSON.
Inspect a complete record without making requests:

```sh
python -c 'import gzip,json; print(json.dumps(json.load(gzip.open("experiments/typesafe/results/2026-09-16/api-records.json.gz")), indent=2))'
```

These archives preserve the catalog snapshot used on 2026-09-16. The current
catalog has since changed, so running the experiment against today's catalog is
a new evaluation and requires a fresh output directory. The original uncompressed
files are kept locally but ignored by Git. Responses contain no authorization headers.

No SDK or new runtime dependency was installed. The original HTTP implementation
follows the API contract and design guidance linked in the report; no cookbook
source code was copied. The installed TypeSafe skill retains its MIT license.
