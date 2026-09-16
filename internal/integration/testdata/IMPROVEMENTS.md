# Corpus improvement measurement, 2026-09-15

Measured against the same 176 fixtures and unchanged expectations as the
[baseline](BASELINE.md). Every fixture and expectation SHA256 still matches.
The strict full-corpus test still fails because 7 fixtures fail.

| Measurement | Baseline | Revised |
| --- | ---: | ---: |
| All fixtures passing | 151/176 | 169/176 |
| Expanded fixtures passing | 125/150 | 143/150 |
| Expected credentials found | 59/76 (77.6%) | 73/76 (96.1%) |
| Clean negative scans | 69/75 (92.0%) | 72/75 (96.0%) |
| Failing fixtures | 25 | 7 |

## Changes

- Deep prompting separates explicit setup of a receiving test application's
  authentication from literal credentials sent to an existing service.
  Adjudication retains its stronger reference-filtering instructions.
- Grounding requires private-key PEM headers and rejects closing delimiters.
  Public keys and certificates cannot qualify merely by being labelled
  private keys. Tokens used as URL usernames remain eligible for model
  judgment; there is no blanket username-only URL rejection.
- Basic-auth pairs with a runtime-only password are references. Function-call
  recognition no longer discards MySQL DSNs merely for containing `tcp(...)`.
- The Gitleaks adapter locates the secret capture within a multiline match.
  Single-line Kubernetes Secret scalar captures normalize to the same value
  as generic rules, allowing normal deduplication to merge their detections.

## Remaining failures

| Fixture | Failed assertions |
| --- | --- |
| [auth_username_negative](diffs/deep_corpus_auth_username_negative.diff) | run 1: alerts=1 exceeds maximum=0; run 1: 1 discoveries exceeds max_discoveries=0, the deep read is crying wolf |
| [documented_sample_positive](diffs/deep_corpus_documented_sample_positive.diff) | run 1: missing credential at docs/client_example.py:2 in confirmed verdicts or discoveries |
| [key_ed25519_negative](diffs/deep_corpus_key_ed25519_negative.diff) | run 1: deep scan failed: parse deep response 1/1 (0 chars, 1 tool_calls): tool call submit_candidates: unexpected end of JSON input; head="" |
| [mixed_interpolation_negative](diffs/deep_corpus_mixed_interpolation_negative.diff) | run 1: alerts=1 exceeds maximum=0; run 1: 1 discoveries exceeds max_discoveries=0, the deep read is crying wolf |
| [multiline_assignment_positive](diffs/deep_corpus_multiline_assignment_positive.diff) | run 1: alerts=2 exceeds maximum=1 |
| [percent_encoded_url_positive](diffs/deep_corpus_percent_encoded_url_positive.diff) | run 1: missing credential at scripts/fetch.sh:2 in confirmed verdicts or discoveries |
| [python_responses_positive](diffs/deep_corpus_python_responses_positive.diff) | run 1: missing credential at tests/test_sdk.py:2 in confirmed verdicts or discoveries |

Failures remain part of the normal corpus. None was removed, relabelled,
quarantined, or given a looser assertion. A positive can find its intended
credential and still fail because it produces another, incorrect alert.

## Verification and limits

- One full sequential run of all 176 fixtures with the final code and prompts.
  All 26 pre-expansion regression fixtures passed.
- The original synthetic test-token case and its opaque-token variant each
  passed 20 additional runs with no public false alerts. The real-password
  test counterpart was detected in all 20 additional runs.
- `go test ./...` and `go vet ./...` passed, including fixture integrity and
  regression tests for the new grounding and detector behavior.
- Same private Gemma endpoint, requested model `google/gemma-4-E4B-it`,
  thinking off, temperature zero, aggressive Gitleaks rules and deep scan
  with 4,000-token windows. No model weights or deployment were changed.
- Prompt fingerprints: `gemma4:d76e71449c6a` and
  `gemma4_deep:5756324fcb16`.
- This is a synthetic challenge set used during tuning, not a held-out test
  or an estimate of production precision or recall. Individual outcomes can
  vary across runs even at temperature zero. Repeated checks above cover
  three regressions, not the whole corpus.
- Location-based assertions accept a confirmed verdict or discovery at the
  expected added line. They do not verify the exact raw substring within
  that line. See [README.md](README.md) for the grading contract.
- Audit logging was disabled. No production deployment was changed.

Full outcomes, fixture hashes, source hashes and prompt hashes are in
[improved-2026-09-15.json](improved-2026-09-15.json). Session logs:
`/tmp/atalaia-improve-final.log` and `/tmp/atalaia-improve-repeat.log`.

Run the same checks with an operator configuration pointing to the model:

```sh
INTEGRATION_MIN_AGREEMENT=1 CONFIG=path/to/atalaia.yaml make smoke-corpus
INTEGRATION_ONLY=deep_test_ INTEGRATION_REPEAT=20 INTEGRATION_MIN_AGREEMENT=1 CONFIG=path/to/atalaia.yaml make smoke-corpus
```

The full-corpus command still reports the remaining failures above.
