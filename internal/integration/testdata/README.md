# Secret-scanning evaluation corpus

176 fixtures: 26 existing regression cases plus 150 expanded cases in
75 positive/negative contrast pairs. All credentials and keys are
fabricated evaluation data. The fixtures are submitted as diff text;
the programs and commands inside them are never executed.

The [baseline](BASELINE.md) and [improvement measurement](IMPROVEMENTS.md)
record measured successes and remaining failures.

## Coverage

The paired cases change a value's role rather than relying on its name
or entropy. Most pairs reuse the same literal: a token installed into a
local test application is harmless, while that token used against an
existing service is a leak. References, non-credential data, public keys,
removed lines, and unchanged context are negative controls.

| Family | Pairs | Fixtures |
| --- | ---: | ---: |
| adversarial | 2 | 4 |
| connection | 11 | 22 |
| context | 4 | 8 |
| data-role | 4 | 8 |
| deployment | 5 | 10 |
| diff-boundary | 7 | 14 |
| encoding | 2 | 4 |
| key-material | 3 | 6 |
| mixed | 3 | 6 |
| reference | 16 | 32 |
| syntax | 2 | 4 |
| test-auth | 16 | 32 |

Languages and formats: csharp, go, hcl, java, javascript, kotlin, pem, php, python, ruby, rust, shell, toml, typescript, yaml.

Test-framework coverage includes Flask, FastAPI, Django, Express/
Supertest, Gin/httptest, Rails, Spring/MockMvc, ASP.NET, Laravel,
Axum, responses, nock, WireMock, Cypress, pytest and Kotlin mocking.
Deployment cases cover Compose, Kubernetes, Helm, Terraform, Ansible,
GitHub Actions and GitLab CI. Other cases cover database and broker
URLs, SMTP, command-line authentication, Unicode, percent encoding,
base64, PEM keys/certificates, misleading comments, prompt injection,
mixed real/fake values, multiple files, removals, renames and hunk offsets.

## Run

Offline integrity and grader tests run in normal CI with no LLM:

```sh
go test ./internal/integration
```

Run against a config that enables deep scan and points to a trusted LLM:

```sh
CONFIG=path/to/atalaia.yaml make smoke-corpus
INTEGRATION_TAG=expanded CONFIG=path/to/atalaia.yaml make smoke-corpus
INTEGRATION_TAG=test-auth INTEGRATION_REPEAT=20 CONFIG=path/to/atalaia.yaml make smoke-corpus
INTEGRATION_ONLY=deep_corpus_flask_config CONFIG=path/to/atalaia.yaml make smoke-corpus
```

`INTEGRATION_TAG` selects one exact tag. `INTEGRATION_ONLY` selects a
filename prefix. Both filters apply when supplied together. Useful tags
include `positive`, `negative`, the families above, and language names.
A filter selecting no fixtures fails rather than silently succeeding.

`INTEGRATION_TIMEOUT` controls the Go test process timeout (default
`60m`). Large repeated runs may need a larger value. Run a whole-corpus
single sample first, then repeat the families or cases under study.
Calls are sequential; do not parallelize runners against a one-slot LLM.
The script starts a local Atalaia instance and stops it on exit.

The expansion is a challenge set, not a claim that the current model
passes everything. Keep correct labels when a case fails. Record failures
and fix the detector, model integration, or prompts in a separate change.
Never whitelist a literal or lower a threshold just to make a fixture green.

## Expectation contract

Every `.diff` has an adjacent `.expect.json`. Expanded files use
`deep_corpus_<pair>_negative` / `_positive` names and carry tags and a
shared `pair` identifier. All expanded cases request deep scan and
reject unreviewed findings or incomplete detector/deep coverage.

```json
{
  "description": "A literal password is used against an existing service.",
  "tags": ["expanded", "connection", "python", "positive"],
  "pair": "postgres_url",
  "deep": true,
  "min_after_dedup": 0,
  "expectations": [],
  "expect_secrets": [
    {"file": "app/db.py", "line": 1, "kind": "credential", "value": "BirchHarbor62"}
  ],
  "max_alerts": 1,
  "max_unreviewed": 0
}
```

- `expect_secrets` requires each location in either a **confirmed**
  verdict or a grounded discovery. Dismissed and unreviewed findings do
  not count. This makes the expectation independent of which detector
  rules happen to recognize the value. Discovery kinds must match.
- `value` is evidence for offline validation: it must occur at the
  specified added line. Runtime matching uses file and line because
  responses redact values and may report a containing URL. One expected
  secret per source line avoids counting a single alert twice. A
  location assertion does not prove that the model selected precisely
  the intended substring; focused grounding unit tests cover that layer.
- `max_alerts` caps confirmed verdicts plus discoveries. Negative cases
  require zero, including unexpected credentials not listed explicitly.
  Positive/mixed cases cap alerts at their expected secret count so
  unrelated false positives and duplicate alerts are visible too.
- `max_unreviewed: 0` prevents model gaps from passing a negative case.
- Legacy `expectations`, `expect_discoveries`, `max_confirmed` and
  `max_discoveries` remain available for tests of a specific channel.

Missing expanded secrets and excess alerts are hard failures, even if
aggregate agreement stays above its floor. Reports show expanded secret
recall and clean-scan counts separately; successful capacity/coverage
checks must not be mistaken for recall. Per-tag assertion totals help
locate failing families. Positive cases can contain more than one secret,
so the recall denominator can exceed the positive fixture count.

## Adding cases

1. Specify the expected behavior before looking at the model's response.
2. Add both sides of a contrast when possible. Put the reason for the
   label in metadata, not an artificial hint inside the positive diff.
3. Use plausible code and fabricated values. Include mock setup when it
   is the evidence making a token synthetic.
4. Use valid unified-diff hunk counts and post-image line numbers.
5. Run the offline tests, then the selected pair against a real LLM.
6. Keep the fixture if it exposes a real gap; document that gap.

The offline validator checks JSON fields, paired files, contrast-pair
completeness, polarity, alert limits, hunk counts, distinct expected
locations, and the actual added bytes at every expanded expectation.
It does not execute or type-check embedded language snippets. Older
fixtures retain their historical formatting and are not subjected to
the new strict hunk-count check.

## Stage diagnostics and frozen holdout

The 40 new contrast pairs in `holdout/` are separate from the original 176
fixtures. Their manifest is checked by offline tests. Do not edit their labels
or use their model outcomes to tune the same round.

The diagnostic runner uses the actual HTTP handler and the same grader. It
writes raw synthetic inputs/model outputs to an explicitly selected, new file
with mode 0600. Use only a trusted model endpoint. No production recording is
added. Run from the repository root:

```sh
EVAL_ENDPOINT=http://127.0.0.1:8000/v1 EVAL_OUTPUT=/tmp/eval.jsonl \
  INTEGRATION_MIN_AGREEMENT=1 go test -tags=integration -count=1 -timeout 60m \
  -v ./internal/integration -run '^TestDiagnosticCorpus$' > /tmp/eval.log 2>&1
python3 scripts/summarize-eval.py /tmp/eval.jsonl /tmp/eval.log /tmp/eval-summary.json
```

`EVAL_THINKING=off|on|default` controls the per-request override; default for
this evaluator is `off`. `EVAL_SET=holdout` selects the frozen new pairs.
`EVAL_CONFIG` selects the configuration (default: checked-in [eval.yaml](eval.yaml)). `INTEGRATION_REPEAT`, `INTEGRATION_ONLY` and `INTEGRATION_TAG` work as
in the ordinary corpus. Go subtest expressions can select multiple families.
Use a distinct output path for every run; existing files are never overwritten.

The ordinary HTTP runner also accepts `INTEGRATION_FIXTURES` to select a fixture
directory. For recorded evaluation, `EVAL_SET` restricts input to the four known
synthetic sets. Summaries report failures even when the Go process exits nonzero.

The summary treats every assertion disagreement as a failed case, including
legacy verdict mismatches that use a soft aggregate gate in single Go runs.
Run `python3 scripts/test-summarize-eval.py` for its offline scoring checks.

For controlled mode comparisons, verify the rendered requests as well as the
prompt-template hashes. This check excludes only `enable_thinking` and counts
replacement attempts separately:

```sh
python3 scripts/compare-eval-requests.py /tmp/off.jsonl /tmp/on.jsonl /tmp/request-comparison.json
```

A mismatch exits nonzero and names the fixture/call without exposing model
input text. Deterministic detector provenance order is part of this contract.

## Quality-first round

`holdout3/` adds 24 contrast pairs (48 fixtures), frozen before round-three
prompt changes. Its manifest is checked by `TestFrozenHoldout`. The diagnostic
runner selects it with `EVAL_SET=holdout3`; the ordinary corpus runner can use
`INTEGRATION_FIXTURES=internal/integration/testdata/holdout3` from the repository
root. Diagnostic runs continue to use the existing location-based grader.

The round-two `holdout/` results are now known and may be used for development.
They no longer provide an independent held-out score for later prompt changes.
Keep the new set's labels fixed and do not tune after inspecting its results.


## Round-four continuation

`holdout4/` adds 16 new contrast pairs (32 fixtures), frozen before continuation
tuning. Use `EVAL_SET=holdout4` in the diagnostic runner. `TestFrozenHoldout`
checks its immutable manifest. Earlier sets are development data. The ordinary
corpus still defaults to `diffs/`; fixture programs are never executed.
