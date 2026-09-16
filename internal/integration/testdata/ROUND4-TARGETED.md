# Round four: targeted recall and source copying

This report records the initial targeted phase. The later
[source-selection continuation](ROUND4-CONTINUATION.md) contains the completed
fresh comparison and the recommended opt-in configuration.

The recall and source-copying tasks are complete as targeted
implementation and investigation. The experimental prompts recover the three
requested credential patterns. Source copying remains unreliable. The candidate
is not adopted; production templates still match the round-three retained
baseline. No commit or deployment was made.

## Scope and outcome

Start point: round-three trial 4, with thinking on. All cases used here were
already revealed. No existing fixtures, labels, thresholds, runtime parsing or
grounding rules changed. Adjudication templates are unchanged from trial 4;
only the experimental deep templates changed. The final configuration retains
native tools. Plain JSON configurations were diagnostic trials only.

The final candidate checks mock lifetime before method/URL matching, distinguishes
an independently live client and explicit passthrough from fabricated responses,
and separates ordinary account usernames from authentication tokens. Explicit
indentation counting was needed to recover the request after a Python with block.

All three targeted contrast pairs pass in both runs:

- `fresh_mock_scope_{positive,negative}`
- `fresh_python_unrelated_mock_{positive,negative}`
- `fresh_token_username_{positive,negative}`

The separate-client pair, `fresh_mixed_clients_{positive,negative}`, also passes
in both runs. Controls include intercepted Python/JavaScript requests, Ruby
method replacement and ordinary URL userinfo. The final candidate uses the
same source bytes and fixture expectations as the reference.

| Measurement | Round-three reference, one pass | Targeted candidate, two passes |
| --- | ---: | ---: |
| Cases passing every evaluated run | 14/20 | 17/20 |
| Credential expectations found | 5/10 | 17/20 |
| Negative scans kept clean | 9/10 | 19/20 |
| HTTP / deep errors | 0 / 0 | 0 / 0 |

The candidate executed 40 requests. Its credential and negative denominators
count both passes. The reference is the exact subset of the preserved first
round-three fresh run; it was not rerun. This is a development comparison,
not an independent held-out improvement claim or a full-corpus selection.

The candidate's remaining failures are:

- `fresh_json_backslashes_positive`: fails both runs. Two source backslashes
  become one in the model's returned value.
- `fresh_json_source_bytes_positive`: passes once, fails once. The failed run
  replaces a literal Unicode escape with its decoded character.
- `fresh_javascript_fetch_negative`: a mocked request produces an alert in one
  run. Its paired live credential remains detected.

Primary model requests match exactly within each pair of repeated calls, with
thinking enabled and temperature zero. The different outcomes therefore remain
an observed stability problem. There were no recovery attempts. A source-value
check found no verbatim echoes of 20 expected values across the 40 API responses;
that check does not cover every reformatted-secret representation.

Evidence: [reference subset](round4-2026-09-16/reference-targets.json),
[final repeated evaluation](round4-2026-09-16/targeted-repeat.json),
[hashes, byte traces and repeat validation](round4-2026-09-16/validation.json).

## Where escaped bytes change

The original diagnostic records show the exact source spelling in the rendered
request. After decoding the API response's arguments JSON once, the candidate
already has one fewer backslash or a decoded Unicode character. The Go candidate
is identical to that decoded API argument. Exact grounding rejects it because
those returned bytes do not exist at the source location.

The installed vLLM native argument parser was inspected. Its parsing functions
preserve the contents of native string delimiters as literal text. Executing
those functions on synthetic strings, followed by JSON serialization and decoding,
preserved single backslashes, doubled backslashes and Unicode source escapes.
The checked parser source hash is recorded. This test isolates the parser;
raw generation tokens were not captured from the live runs. The evidence points
to model copying/serialization, not a demonstrated parser unescaping bug.

New Go regression coverage follows the HTTP response envelope through both
plain content and tool arguments into parsing and grounding. Correctly encoded
source escapes survive exactly. Decoded Unicode and collapsed backslashes
remain ungrounded. No fallback reconstructs or decodes a guessed credential.

Prompt experiments distinguished native tool-string contents from JSON escaping,
tried complete quoted source tokens, required explicit backslash counting and
provided a source/runtime spelling example. Plain JSON recovered Unicode in a
small diagnostic pass but still collapsed doubled backslashes. Native tools
also recovered Unicode with counting guidance, but the final repetition exposed
instability. Switching the production output mode is not supported by this evidence.

Evidence: [original stage trace](round4-2026-09-16/escape-stage-trace.json),
[installed backend parser check](round4-2026-09-16/backend-escape-check.json),
and [Go regression test](../../llm/deepparse_test.go).

## Experiment record

Each profile and configuration is preserved under `round4-2026-09-16/`.
No failed candidate replaced the production templates.

| Trial | Scope | Cases passing all runs |
| --- | --- | ---: |
| recall | 16 recall/control cases | 15/16 |
| recall2 | 16 recall/control cases, block example | 15/16 |
| bytes | 4 copying cases, native format guidance | 2/4 |
| lexeme | 6 scope/copying cases, source tokens and indentation count | 4/6 |
| lexeme repeated | 16 recall/control cases, twice | 15/16 |
| bytes JSON | 4 copying cases, plain JSON | 3/4 |
| lexeme JSON | 4 copying cases, plain JSON | 3/4 |
| copycheck | 4 copying cases, native tools and character counts | 3/4 |
| targeted repeated | 20 combined cases, twice | 17/20 |

The first recall trial recovered passthrough and token usernames but still
missed the request after mock scope. Explicit indentation counting recovered
that case. The first broad recall repeat then falsely reported an ordinary
username once. A direct ordinary-account example removed that failure in the
final repeat, which instead exposed the JavaScript mock false alert.

## Validation and next work

Passed: `go test ./...`, focused byte-preservation regressions,
`go vet ./internal/llm`, formatting and `git diff --check`. Original fixture
hashes match the reference; production prompt files match the retained baseline.

The TODO keeps reliable escaped-string generation, the incidental false alert,
a new frozen set and full comparison pending. The 304 existing cases can guide
development but cannot become fresh evidence again. The targeted gains are
insufficient for a production recommendation.

To reproduce the final experiment from the repository root, use a trusted
endpoint and a fresh output path:

```sh
EVAL_ENDPOINT=http://127.0.0.1:8000/v1 EVAL_THINKING=on \
  EVAL_SET=holdout3 EVAL_OUTPUT=/tmp/round4-targeted.jsonl \
  EVAL_CONFIG=internal/integration/testdata/round4-2026-09-16/targeted-eval.yaml \
  INTEGRATION_REPEAT=2 INTEGRATION_MIN_AGREEMENT=1 \
  INTEGRATION_MIN_FIXTURE_AGREEMENT=1 \
  go test -tags=integration -count=1 -timeout 90m -v ./internal/integration \
  -run '^TestDiagnosticCorpus$/^fresh_(mock_scope|python_unrelated_mock|mixed_clients|token_username|url_component|python_transport|javascript_fetch|ruby_local_method|json_backslashes|json_source_bytes)_(positive|negative)$' \
  > /tmp/round4-targeted.log 2>&1
python3 scripts/summarize-eval.py /tmp/round4-targeted.jsonl \
  /tmp/round4-targeted.log /tmp/round4-targeted-summary.json
```

The live test exits nonzero for the documented semantic failures. Raw synthetic
records stay in explicit mode-0600 files under `/tmp`.
