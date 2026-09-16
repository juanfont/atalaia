# Second improvement round, 2026-09-15

For the subsequent quality-first thinking comparison, see [ROUND3.md](ROUND3.md).
The mode recommendation below records the round-two selection.

## What changed

The model now sees source context before the exact scanner matches. The
adjudication prompt explicitly distinguishes a matched variable from its assigned
literal and a filename from evidence of synthetic authentication. Deep prompts
clarify ordinary URL usernames, runtime passwords and verbatim percent escapes.
The model still decides whether authentication data is synthetic. Deduplication
now sorts both findings and their detector provenance, so scanner completion
order cannot change the prompt or which findings reach a configured cap.

Malformed or truncated completions get at most one replacement attempt within
the original deadline and semaphore slot, with the same per-attempt output
limit. Two attempts can consume twice the generation budget. Valid decisions are
never retried. Partial candidates are discarded on failure. Attempt counts and
failed-scan timing remain visible without exposing raw model text in errors.

`llm.enable_thinking` can explicitly select the backend template's thinking
mode. Unset preserves the backend default. The evaluation verifies actual
reasoning text as well as the requested flag. No deployment was changed.

The original 176 fixtures and labels remain fixed. A further 80 fixtures,
40 contrast pairs, were frozen before prompt selection. They remain a separate
holdout rather than being folded into the tuning score.

## Diagnosis of the previous seven failures

| Family | Diagnosis |
| --- | --- |
| Ordinary URL username | Deep scan labels a nonsecret service username as a credential. |
| Operational documentation | Adjudication dismisses a real-service token because of the example filename. Deep finds it, but correctly cannot override detector ownership. |
| Public Ed25519 key | The historical malformed completion did not reproduce in the first diagnostic sample. A public-key candidate did reproduce, but grounding correctly rejected it. |
| Mixed interpolation | Deep reports the literal username as a password. The runtime password reference itself is not the reported value. |
| Multiline assignment | Adjudication confirms a matched variable argument using a different literal nearby, producing an extra alert. |
| Percent-encoded password | Deep copies only a short prefix of the password. Grounding correctly rejects that candidate. |
| Python SDK test | Adjudication mistakes the test filename for evidence of a mocked service. Detector ownership prevents deep from replacing that decision. |

These observations come from synthetic stage records. They do not justify
filename shortcuts, blanket username suppression or weaker grounding.

## Selected configuration

Keep thinking **off** for these prompts and this backend. On the original
176-case corpus, both modes pass the same number of complete cases, but thinking
off finds every expected credential and has lower latency. Set `llm.enable_thinking: false` to make that choice
explicit. The option remains unset by default; no deployment was changed.

| Measurement, one full run | Previous round | Thinking off | Thinking on |
| --- | ---: | ---: | ---: |
| Complete cases passing | 169/176 | 175/176 | 175/176 |
| Expected credentials found | 73/76 | 76/76 | 75/76 |
| Clean negative scans | 72/75 | 75/75 | 75/75 |
| Median request latency | Not recorded here | 1.306 s | 9.804 s |
| p95 request latency | Not recorded here | 3.884 s | 23.243 s |
| Maximum request latency | Not recorded here | 68.825 s | 104.380 s |
| Generated tokens | Not recorded here | 27,204 | 146,128 |
| Model calls, including recovery | Not recorded here | 273 | 272 |
| Calls with reasoning text | Not recorded here | 0 | 272 |
| Recovery attempts | Not available | 1 | 0 |
| Deep scan errors | 1 | 0 | 0 |

All 272 primary model requests match exactly apart from `enable_thinking`.
See [request-comparison.json](round2-2026-09-15/request-comparison.json).
The extra thinking-off request recovered a real truncation on the RSA public-key
negative: the first completion hit 4,096 tokens; the replacement returned a
complete response and the case passed. Total cost above includes both attempts.
Thinking used 5.4 times as many generated tokens and increased median request
latency 7.5-fold, even including that recovery in thinking-off costs.

The remaining thinking-off failure is `multiline_assignment_positive`: the
intended credential is found, but adjudication also confirms the variable
argument nearby. Thinking on fixes that case but misses `weak_password_positive`.
There, adjudication calls the weak literal a placeholder and grounding also
rejects deep's candidate as a placeholder. No fixture was removed or given a
looser assertion.

### Why the comparison was rerun

An initial comparison favored thinking off 175/176 versus 174/176. Checking the
actual rendered requests exposed 15/272 calls whose detector provenance appeared
in different orders. The deterministic ordering fix removes that confound. The
Django override negative, previously a thinking-on false alert, passes with the
canonical order. The full table above uses fresh runs after the fix.

An initial repeat run was stopped after 141 requests and is excluded from final
validation. It had not reached the holdout. Earlier targeted development scores
were 16/17 with thinking off and 17/17 with thinking on; full-corpus evaluation
was needed to choose the mode.

## Repeated validation and holdout

The selected configuration passed **175/176 cases in all three full-corpus
passes**. Across 528 requests it found 228/228 expected credentials and kept
225/225 negative scans clean. The only failing case in each pass was the extra
alert on `multiline_assignment_positive`. There were no HTTP or deep-scan errors.
Two truncated RSA-public-key completions recovered successfully, one in the
initial clean run and one in the two additional passes. All 1,044 primary calls
in the additional full and targeted repeats matched their fixtures' initial
requests; see [repeat-request-consistency.json](round2-2026-09-15/repeat-request-consistency.json).

See [the first full run](round2-2026-09-15/full-off-1.json) and
[the two additional passes](round2-2026-09-15/full-off-repeat2.json).

In the [20-repeat targeted run](round2-2026-09-15/target-off-repeat20.json),
16/17 cases passed every repeat. Six of the seven previously failing families
and all their counterparts passed. The multiline positive found its credential
but produced the same extra alert in all 20 repeats. The family subset found
140/140 expected credentials and kept 140/140 negative scans clean. All three
original screenshot-related regressions passed 20/20 each, 60/60 requests total.

### Frozen holdout: 65/80

The [new 80-case holdout](round2-2026-09-15/holdout-off-1.json) passed **65/80
cases (81.25%)**, found **37/40 expected credentials (92.5%)**, and kept **29/40
negative scans clean (72.5%)**. There were no HTTP errors, deep errors or retries.
Median request latency was 1.252 seconds and p95 was 2.561 seconds.

The improvement on familiar cases does not establish comparable generalization.
The holdout exposes 11 false alerts on negative fixtures, three missed
credentials and one extra alert on a positive fixture. Its labels and prompts
remain unchanged. Selection and source hashes were saved in
[selection.json](round2-2026-09-15/selection.json) before holdout inference.

| Holdout failure group | Count | Observed stage |
| --- | ---: | --- |
| Unfamiliar mock transports/test clients | 9 | Deep emits a literal credential despite mocked use; grounding locates its bytes correctly. |
| Mocked fixture-directory case and explicit sample runbook | 2 | Deep emits credentials; grounding correctly locates the proposed values. |
| Digest-shaped HMAC key | 1 | Deep returns no candidate. |
| JSON-escaped credential | 1 | Deep's candidate is not present verbatim; grounding rejects it. |
| MySQL password containing parentheses | 1 | Deep proposes the password fragment; the reference guard rejects its function-like shape. |
| Python multiline assignment | 1 | Adjudication confirms the variable argument in addition to deep finding the intended literal. |

Exact failing fixture names and value-free stage outcomes are in
[holdout-failures.json](round2-2026-09-15/holdout-failures.json).
The [preserved historical prompts](round2-2026-09-15/historical-prompts/)
were also evaluated on the same holdout with the current runtime and thinking
off. Their hashes match the preceding round's report. This is a fixed prompt
baseline, not a rerun of the historical binary or another tuning candidate.

| Holdout measurement | Historical prompts | Revised prompts |
| --- | ---: | ---: |
| Complete cases passing | 63/80 | 65/80 |
| Expected credentials found | 37/40 | 37/40 |
| Clean negative scans | 27/40 | 29/40 |

The revised prompts fix the JavaScript-template and Python-fstring negatives.
All other case outcomes match in these runs. The held-out gain is two cases,
not the six-case gain seen on the familiar corpus. The remaining false alerts
and missed credentials prevent a claim of broadly reliable near-100% accuracy.
See [the baseline summary](round2-2026-09-15/holdout-historical-prompts.json).
The selected implementation was not changed after viewing holdout results.

## Method and limits

- Same private Gemma endpoint and model `google/gemma-4-E4B-it`. Temperature
  zero, aggressive Gitleaks rules, deep scan enabled, 4,000-token windows,
  4,096 output tokens and a 120-second model-stage request timeout.
- [eval.yaml](eval.yaml) records the configuration. The initial exploratory run used
  an equivalent local smoke configuration; the harness overrides endpoint
  and disables audit recording in both configurations.
- Both thinking modes use the same selected prompts. Earlier prompt trials
  are development measurements and are separate from final validation.
- The real HTTP handler and corpus grader run in an in-process test server.
  This measures handler latency without an external proxy, production HTTP
  write deadline, concurrent traffic or queue pressure.
- A case passes only if all its assertions pass. Summaries also count legacy
  verdict disagreements that the single-run Go subtest can leave to its
  aggregate gate. Recall, clean scans and complete-case scores are separate.
- Location-based assertions accept a confirmed verdict or discovery at the
  expected added line. They do not verify the exact raw substring on that
  line. See [README.md](README.md) for the grading contract.
- Repetition measures observed stability at temperature zero. It does not
  establish a zero failure probability. Synthetic holdout performance is
  not an estimate of production precision or recall.
- Raw synthetic records remain in explicitly selected mode-0600 files under
  `/tmp`. Checked-in summaries contain counts, timings and hashes, with no
  credential values or reasoning text.

## Reproducing the final measurements

Run from the repository root against a trusted compatible model endpoint.
Use a new output prefix for each run. The Go process exits nonzero for the
remaining model failures; generate the summary afterward even when it fails.

```sh
EVAL_ENDPOINT=http://127.0.0.1:8000/v1 EVAL_THINKING=off \
  EVAL_OUTPUT=/tmp/final-full.jsonl INTEGRATION_REPEAT=3 \
  INTEGRATION_MIN_AGREEMENT=1 INTEGRATION_MIN_FIXTURE_AGREEMENT=1 \
  go test -tags=integration -count=1 -timeout 90m -v ./internal/integration \
  -run '^TestDiagnosticCorpus$' > /tmp/final-full.log 2>&1
python3 scripts/summarize-eval.py /tmp/final-full.jsonl /tmp/final-full.log /tmp/final-full-summary.json
```

Use `EVAL_SET=holdout` and `INTEGRATION_REPEAT=1` for the new cases. For the
historical-prompt control, also set
`EVAL_CONFIG=internal/integration/testdata/round2-2026-09-15/historical-eval.yaml`.
The [corpus README](README.md) documents targeted selection and request comparison.

Offline validation passed: `go test ./...`, `go vet ./...`,
`go vet -tags=integration ./internal/integration`, fixture/manifest integrity,
and `python3 scripts/test-summarize-eval.py`. All 176 original fixture and
expectation hashes match the preceding round. No production deployment changed.
