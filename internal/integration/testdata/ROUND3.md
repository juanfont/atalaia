# Quality-first round, 2026-09-16

The development-selected candidate reduced false alerts but lost credential
recall on the fresh holdout. Its templates remain in the experiment directory;
`prompts/` retains the round-two baseline. Grounding and redaction fixes remain.
Thinking on is recommended for the evaluated Gemma deployment. The backend
configuration default remains unchanged. Nothing was deployed.

Validation is complete. The fresh baseline and candidate outcomes repeated
exactly. No HTTP errors, deep errors or recovery attempts occurred in the final
comparison and repeated runs.

## Thinking comparison and candidate selection

Latency did not select the configuration. The order was credential recall,
then false alerts. Original labels, thresholds and cases were preserved.

| Configuration | Original complete cases | Revealed complete cases | Credential locations found | Clean negatives |
| --- | ---: | ---: | ---: | ---: |
| Baseline, thinking off | 175/176 | 65/80 | 113/116 | 104/115 |
| Baseline, thinking on | 175/176 | 72/80 | 113/116 | 109/115 |
| Candidate, thinking off | 175/176 | 66/80 | 114/116 | 103/115 |
| Candidate, thinking on | 174/176 | 79/80 | 115/116 | 113/115 |

The original corpus has 76 expanded credential expectations and 75 expanded
negative cases. Its other legacy assertions contribute to complete-case scores,
not those two denominators. The revealed corpus has 40 of each.

All 272 original-corpus and 108 revealed-corpus primary candidate requests match
between modes after excluding only `enable_thinking`. Reasoning was returned
with thinking on. The candidate's original-corpus failures were a synthetic
multi-file credential false alert and a missed live PaymentClient token in a
JavaScript test. Deep scan found that token but correctly could not override
the detector channel's dismissal. The revealed failure was an Axios mock false
alert. These regressions were retained in the selection record.

Evidence: [selection and hashes](round3-2026-09-16/selection.json),
[original on](round3-2026-09-16/trial4-on-full.json),
[original off](round3-2026-09-16/trial4-off-full.json),
[revealed on](round3-2026-09-16/trial4-on-holdout.json),
[revealed off](round3-2026-09-16/trial4-off-holdout.json),
[original request comparison](round3-2026-09-16/trial4-full-mode-comparison.json),
[revealed request comparison](round3-2026-09-16/trial4-holdout-mode-comparison.json).
The earlier [baseline mode comparison](round3-2026-09-16/baseline-mode-comparison.json)
matched all 108 primary calls on the revealed corpus.

## Fresh holdout and adoption decision

The 24 contrast pairs in `holdout3/` were frozen before prompt tuning. The
selected candidate and runtime hashes were saved before any fresh inference.
The baseline uses archived prompts, grounding and redaction through a Go
overlay. No prompts or labels were retuned after observing fresh results.

| First pass | Complete cases | Credential locations found | Clean negatives |
| --- | ---: | ---: | ---: |
| Baseline, thinking on | 39/48 | 21/24 | 18/24 |
| Candidate, thinking on | 42/48 | 19/24 | 23/24 |

The complete-case increase conceals a recall regression. Under the stated
recall-first criterion, this is insufficient evidence to adopt the candidate.
The shipped templates were restored to the baseline. Candidate experiments
remain reviewable, including the development selection and subsequent
[adoption review](round3-2026-09-16/adoption-review.json).

All six candidate failures on this first fresh pass were in deep scan:

- Escaped JSON and backslashes: returned bytes did not exist in the source;
  grounding correctly rejected them.
- A call after mock scope ended, and a call through a separate live client:
  the model classified the credential as synthetic test data.
- A token used in a username position: no candidate returned.
- A Ruby local method replacing HTTP: synthetic authentication was reported.

Evidence: [baseline fresh](round3-2026-09-16/baseline-on-fresh.json),
[candidate fresh](round3-2026-09-16/selected-on-fresh-1.json),
[failure stages](round3-2026-09-16/fresh-failure-stages.json).

## Repeated validation

| Configuration and set | First pass | Second pass | Passed both |
| --- | ---: | ---: | ---: |
| Candidate, original | 174/176 | 174/176 | 174/176 |
| Candidate, revealed | 79/80 | 80/80 | 79/80 |
| Candidate, fresh | 42/48 | 42/48 | 42/48 |
| Baseline, fresh | 39/48 | 39/48 | 39/48 |

Both fresh passes found 19/24 candidate credentials versus 21/24 baseline
credentials. Negative results also repeated: 23/24 candidate versus 18/24
baseline. The recall-first rejection therefore stands after repetition.

All primary requests matched within each repeated comparison: 272 original,
108 revealed and 59 fresh calls per candidate pass, plus 59 fresh baseline
calls per pass. Only the Axios negative changed pass/fail outcome between the
two complete candidate passes. All other named failures repeated.

The candidate's second original pass had median request latency 4.936 s,
p95 12.321 s and maximum 60.564 s. Its fresh repeat had median 3.730 s and
p95 6.095 s. These measurements do not select the winner or establish safe
production timeouts.

The source-value audit checked 280 expected values across 608 candidate API
responses and found no verbatim echoes. It checks fixture source spellings,
not every possible reformatted-secret representation. Runtime and candidate
prompt hashes still match the pre-holdout selection. Production prompt files
match the archived baseline; original fixture and expectation hashes remain
unchanged.

Evidence: [final validation](round3-2026-09-16/final-validation.json),
[response audit](round3-2026-09-16/public-value-audit-final.json),
[original repeat requests](round3-2026-09-16/repeat-full-requests.json),
[revealed repeat requests](round3-2026-09-16/repeat-holdout-requests.json),
[fresh repeat requests](round3-2026-09-16/repeat-fresh-requests.json),
[baseline repeat requests](round3-2026-09-16/repeat-baseline-fresh-requests.json).

## Changes retained

Grounding permits a function-shaped password only when its first added-source
occurrence proves it is a complete closed quoted literal, or the password
component of a quoted connection string. Unquoted calls, interpolation,
unterminated strings and arbitrary containing expressions still fail this
exception. No decoding or fuzzy matching was added.

A development response returned a whole connection URL while quoting only
its password in the explanation. Whole-match scrubbing missed that fragment.
The redactor now scrubs URL userinfo components in source and decoded forms,
and MySQL tcp/unix DSN components. MySQL previews mask userinfo rather than
exposing a short password through generic head/tail masking. Grounding and
raw audit bytes remain unchanged.

The corpus now contains 304 fixtures across the original 176, revealed 80 and
fresh 48 cases. Ordinary corpus runs still default to the original 176.
Offline manifest validation covers both frozen sets and rejects unmanifested
fixture files. The diagnostic runner selects the new set with
`EVAL_SET=holdout3` and records synthetic data only, in new mode-0600 files.

See the [design](../../../docs/superpowers/specs/2026-09-16-quality-first-evaluation-design.md).

## Development experiments

Trial 1 broadly rewrote the deep prompt. Thinking off passed 172/176 original
cases and 75/80 revealed cases. Thinking on passed 79/80 revealed cases, but
its original-corpus run was stopped after 98 requests when Kotlin and Laravel
live-test credentials were missed. No complete score is assigned to that
partial run. The broad rewrite was rejected.

Trial 2 retained more of the original deep prompt and made targeted changes
to mock scope, role and byte copying. Thinking on passed 79/80 revealed cases
and 10/11 focused controls. Trial 3 clarified registered interception but
regressed an operational-documentation case; it also scored 79/80 and 10/11.
Trial 4 clarified that detector matches are captured values, not invented
source columns. A key sharing the value's spelling must not disqualify the
literal. It passed 11/11 controls and was selected for complete evaluation.

Identical deep requests at temperature zero produced different Axios mock
outcomes between trials 3 and 4. The deep prompt did not change between those
trials. This is observed instability, not evidence that an adjudication-only
prompt edit caused the difference. The backend cause was not established.
See the [identical-request record](round3-2026-09-16/identical-request-variation.json).

## Backend interruption

An early trial-1 run stopped after 39 completed requests, with two deep
timeouts. vLLM stopped generating while systemd still reported it active.
The user approved a service restart. Reload then stalled with NVIDIA vGPU
scrub timeouts. The user approved rebooting the guest VM; generation recovered.
Model files, quantization, caching and server configuration were unchanged.
The interrupted run is excluded from quality scores. See the
[incident record](round3-2026-09-16/interrupted-trial1-on-holdout.json).

## Limits and next evidence needed

These are hand-written, stratified synthetic challenges, not a representative
production sample. The original and revealed corpora were development data.
The fresh set independently tests this selection once; it is now revealed and
must not be presented as independent evidence for subsequent tuning.

The live tables compare the archived baseline runtime and prompts with the
experimental candidate runtime and prompts. The retained combination of runtime
fixes and baseline templates has offline regression coverage; it has not been
assigned a separate full live-corpus score.

The grader matches location and kind, not exact secret substrings. The model
still confuses credential role and mock lifetime and sometimes changes source
escapes. Grounding proves that reported bytes exist; it cannot prove a
credential is real. Detector ownership prevents a deep guess from silently
reversing an adjudicated result. These explain why complete-case accuracy is
below 100% even when transport and parsing succeed.

A subsequent prompt experiment should address mock lifetime and client identity
without blanket suppression, and source-byte copying without relaxed grounding.
It needs another frozen set before tuning. Repeats remain necessary because
temperature zero did not guarantee identical semantic output.

## Validation and reproduction

Passed: `go test ./...`, `go vet ./...`,
`go vet -tags=integration ./internal/integration`, the five Python summarizer
tests, fixture/manifest integrity, formatting and `git diff --check`.
Live tests exit nonzero for documented semantic failures; those are not offline
test-suite failures. Raw synthetic records remain under `/tmp` with mode 0600.

The evaluated backend is vLLM 0.20.2, `google/gemma-4-E4B-it`, FP8 weights and
KV cache, with one model slot. Evaluation uses temperature zero, 4096 output
tokens, 24000 input tokens, 4000-token deep windows, up to 48 windows and a
120-second per-call deadline. Caller/proxy deadlines and concurrent queue
pressure were not exercised. Latencies describe these fixtures only.

Run from the repository root with a fresh output filename and a trusted model:

```sh
EVAL_ENDPOINT=http://127.0.0.1:8000/v1 EVAL_THINKING=on \
  EVAL_SET=holdout3 EVAL_OUTPUT=/tmp/round3-candidate.jsonl \
  EVAL_CONFIG=internal/integration/testdata/round3-2026-09-16/trial4-eval.yaml \
  INTEGRATION_MIN_AGREEMENT=1 INTEGRATION_MIN_FIXTURE_AGREEMENT=1 \
  go test -tags=integration -count=1 -timeout 90m -v ./internal/integration \
  -run '^TestDiagnosticCorpus$' > /tmp/round3-candidate.log 2>&1
python3 scripts/summarize-eval.py /tmp/round3-candidate.jsonl \
  /tmp/round3-candidate.log /tmp/round3-candidate-summary.json
```

For the archived baseline use `baseline-eval.yaml` and a Go overlay mapping
`internal/llm/ground.go` and `internal/redact/redact.go` (absolute keys) to their
`baseline-*.go.txt` archives (absolute values) under the experiment directory.
Pass that overlay with `go test -overlay /tmp/baseline-overlay.json`.
