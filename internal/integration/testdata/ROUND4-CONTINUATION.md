# Round four: source selection and fresh comparison

The new configuration passes all 32 fresh cases in both runs. It improves recall
against both earlier configurations and matches the round-three candidate's
clean-negative result. It is packaged as the opt-in `gemma4_source` and
`gemma4_source_deep` profiles, with thinking and source selection enabled.
The implementation and profiles ship in v0.8.0. Defaults and deployment are unchanged.

## Fresh results

Sixteen contrast pairs were frozen before continuation tuning. Candidate and
runtime hashes were saved before any fresh inference. All profiles used the same
current runtime, model, budgets and thinking mode. Source selection was disabled
for the retained and round-three profiles. No tuning followed fresh results.

Each configuration processed 64 requests: two runs of 16 positive and 16 negative
cases. The credential and negative denominators below count both runs; the
complete-case column counts unique cases that passed every run.

| Configuration, thinking on | Cases passing both runs | Credentials found | Clean negative scans |
| --- | ---: | ---: | ---: |
| Retained prompts | 24/32 | 24/32 | 26/32 |
| Round-three candidate | 25/32 | 19/32 | 32/32 |
| Source-selection candidate | **32/32** | **32/32** | **32/32** |

All three runs had zero HTTP errors, deep errors and replacement attempts.
Primary requests matched exactly between repetitions within each configuration.
Baseline and reference prompt versions match their earlier frozen artifacts.
The candidate runtime, templates, config and holdout manifest still match the
pre-inference hashes.

The retained profile missed escaped JSON, token userinfo and some mock-lifetime
cases, and produced false alerts for mocked requests. The round-three candidate
kept all negatives clean but dismissed more live requests and still miscopied
escaped values. The source candidate passed all of these new contrast cases.

Evidence: [frozen selection](round4-2026-09-16/continuation-selection.json),
[retained results](round4-2026-09-16/retained-fresh-repeat.json),
[round-three results](round4-2026-09-16/reference-fresh-repeat.json),
[source results](round4-2026-09-16/source-fresh-repeat.json),
[final validation](round4-2026-09-16/continuation-validation.json),
[adoption decision](round4-2026-09-16/continuation-adoption.json).

## What changed

Longer copying instructions, explicit byte facts and an isolated copying-only
prompt still failed on doubled backslashes. A small source-selection probe showed
that the model could instead identify a catalog entry. The implementation adds
that option without accepting decoded guesses or guessed locations.

With `llm.deep_scan.source_literals: true`, Atalaia extracts closed quoted strings
containing backslashes from each source window. It assigns IDs to exact values
and supplies that catalog alongside the original source. The model still decides
whether a value is a credential, synthetic data or irrelevant. It can return a
`source_id` instead of reproducing the escaped string. Atalaia resolves the ID to
unchanged source bytes before the normal grounding and redaction pipeline.

Unknown IDs and conflicting ID/value pairs fail. Grounding still verifies added
source, applies reference and sentinel rules, drops test_data, respects detector
ownership and derives locations itself. No model-supplied location is accepted.
Plain value responses remain available for other credentials and older profiles.

Catalogs hold at most 32 unique values, 512 bytes per value and 4096 serialized
bytes in total. Invalid UTF-8 and unclosed or oversized strings are omitted.
Omitted strings remain in the original window. If the enhanced prompt and tool
schema exceed the configured input estimate, the catalog is omitted. The option
defaults off. Source IDs never appear in the public API, and catalogs are not
persisted or logged by the application.

If a reported credential's copied value is absent from a catalog-enabled window,
the existing bounded response-replacement mechanism may request a valid response.
It does not accept or reconstruct the invalid value. The original deadline,
per-attempt output limit and semaphore slot remain in force. No replacements
were needed in the final fresh comparison.

The source profile also clarifies mock lifetime, distinct clients, passthrough,
locally replaced network functions and tokens used as usernames. The copying
examples were replaced with a shorter user prompt; the runtime supplies the
source catalog and its selection instructions when enabled.

See the [design](../../../docs/superpowers/specs/2026-09-16-source-literal-selection.md),
[copying probes](round4-2026-09-16/copy-probe.json), and
[source-selection probe](round4-2026-09-16/source-probe.json).

## Development results and remaining failures

The complete development passes used all 304 previously revealed cases:

| Set | Complete cases | Credential expectations | Clean negative scans |
| --- | ---: | ---: | ---: |
| Original | 174/176 | 75/76 | 74/75 |
| Revealed round-two set | 79/80 | 40/40 | 39/40 |
| Revealed round-three set | 48/48 | 24/24 | 24/24 |
| Total | **301/304** | **139/140** | **137/139** |

Credential/negative counts cover expanded assertions; complete-case counts also
include legacy verdict assertions. A case can require more than one credential.

Three failures remain in those complete passes:

- `deep_corpus_nock_interceptor_positive`: the detector-channel adjudication
  misses a live credential. Deep scan cannot override detector ownership.
- `deep_corpus_aspnet_factory_negative`: an ASP.NET mock false alert.
- `holdout_webmock_ruby_negative`: a Ruby mock false alert.

An earlier 20-case repeat passed 19/20 cases in both runs, with one missed
`fresh_mock_scope_positive` occurrence. That case then passed in the complete
48-case development run. The new fresh set passed twice, but this earlier
instability remains evidence against a general determinism claim.

The round-three candidate's archived first complete development passes totaled
295/304, with 134/140 credential expectations and 136/139 clean negatives. This
continuation adds five recovered credential expectations and one clean negative
on those development passes. The fresh comparison above is the independent check
for this selection; the old sets were used during development.

Evidence: [original run](round4-2026-09-16/source-development176.json),
[80-case run](round4-2026-09-16/source-development80.json),
[48-case run](round4-2026-09-16/source-development48.json),
[targeted repeat](round4-2026-09-16/source-targeted-repeat.json).

## Validation and limits

The offline Go suite, vet, integration vet, fixture/manifest validation and
source-selection regressions pass. Tests cover source-byte preservation, catalog
bounds, unknown/conflicting IDs, default behavior, tool/content parity, input
fallback, per-window isolation and existing grounding exclusions.

The response audit checked source spellings and one JSON-decoded variant where
valid. It found no echoes across the 496 responses from complete development and
fresh comparison runs. This is targeted regression evidence, not proof against
every possible reformatted-secret representation. Raw synthetic records remain
in explicitly created mode-0600 files under `/tmp`.

These are hand-written synthetic contrast cases, not a production sample. The
live grader checks location and kind, not exact secret-substring equality. The
new JSON cases additionally had exact candidate bytes verified in both runs.
All 336 cases are now revealed and must be treated as development data in a
subsequent tuning round.

The source candidate's fresh median request latency was 3.915 s, p95 6.967 s,
maximum 7.536 s. Retained/reference medians were 3.145 s and 3.035 s. Latency did
not select the configuration. These handler-level experiments do not establish
production proxy, caller or server timeouts or behavior under concurrent load.

The backend remained vLLM 0.20.2 with Gemma 4 E4B, FP8 weights/KV cache and one
model slot. Inference used thinking on, temperature zero, 4096 output tokens,
24000 input tokens, 4000-token deep windows, at most 48 windows and a 120-second
per-call deadline. No server or model configuration was changed.

## Use and reproduction

The packaged source templates are byte-identical to the frozen candidate templates.
Their profile names differ for opt-in selection; the model-facing template bodies
do not. Existing default templates remain unchanged.

Use the [deployment configuration](../../../docs/deployment.md#opt-in-source-literal-selection)
to enable the paired profiles, thinking and source selection. This requires the
new binary and matching prompt files. Nothing was deployed during evaluation.

To reproduce the fresh candidate comparison from the repository root, choose a
trusted endpoint and fresh output filenames:

```sh
EVAL_ENDPOINT=http://127.0.0.1:8000/v1 EVAL_THINKING=on \
  EVAL_SET=holdout4 EVAL_OUTPUT=/tmp/round4-source-fresh.jsonl \
  EVAL_CONFIG=internal/integration/testdata/round4-2026-09-16/source-eval.yaml \
  INTEGRATION_REPEAT=2 INTEGRATION_MIN_AGREEMENT=1 \
  INTEGRATION_MIN_FIXTURE_AGREEMENT=1 \
  go test -tags=integration -count=1 -timeout 90m -v ./internal/integration \
  -run '^TestDiagnosticCorpus$' > /tmp/round4-source-fresh.log 2>&1
python3 scripts/summarize-eval.py /tmp/round4-source-fresh.jsonl \
  /tmp/round4-source-fresh.log /tmp/round4-source-fresh-summary.json
```

Use `retained-eval.yaml` and `reference-eval.yaml` for the two comparison profiles.
Run sequentially against a one-slot model. Live semantic failures exit nonzero
and remain in the report; labels and thresholds were not softened.
