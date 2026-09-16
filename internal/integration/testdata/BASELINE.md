# Expanded-corpus baseline, 2026-09-15

The expanded corpus deliberately exposes failures in the current pipeline.
The strict model evaluation **fails**. All offline fixture-integrity and
grader tests pass. No fixture was removed, quarantined or relabelled to
make the model score higher. Prompts and scanning behavior were unchanged
during this expansion.

The subsequent [improvement measurement](IMPROVEMENTS.md) uses identical
fixtures and expectations. This file preserves the original baseline.

## Results

| Measurement | Result |
| --- | ---: |
| All fixtures passing | 151/176 |
| Expanded fixtures passing | 125/150 |
| Expected credentials found | 59/76 (77.6%) |
| Clean negative scans | 69/75 (92.0%) |
| Failing fixtures | 25 |

There are 75 expanded positive fixtures and 75 negative fixtures. One
positive contains two expected secrets, making 76 recall expectations.
Two positive cases find the expected secret but return excess alerts;
case pass rate is therefore different from recall. The existing 26
regression fixtures pass in this run.

| Expanded family | Fixtures passing |
| --- | ---: |
| adversarial | 4/4 |
| connection | 22/22 |
| context | 6/8 |
| data-role | 6/8 |
| deployment | 10/10 |
| diff-boundary | 14/14 |
| encoding | 3/4 |
| key-material | 3/6 |
| mixed | 6/6 |
| reference | 30/32 |
| syntax | 3/4 |
| test-auth | 18/32 |

## Failures to investigate

Several test-file cases call existing services with literal credentials,
but the pipeline does not report them. Other gaps include public key and
certificate false positives, username/reference false positives,
percent-encoded credentials, and duplicate alerts. These are observable
pipeline failures; this baseline does not attribute every failure to a
specific detector, parser, grounding rule or model decision.

| Fixture | Failure |
| --- | --- |
| [aspnet_factory_positive](diffs/deep_corpus_aspnet_factory_positive.diff) | Missed expected credential |
| [auth_username_negative](diffs/deep_corpus_auth_username_negative.diff) | Unexpected or duplicate alert |
| [axum_oneshot_positive](diffs/deep_corpus_axum_oneshot_positive.diff) | Missed expected credential |
| [base64_role_positive](diffs/deep_corpus_base64_role_positive.diff) | Unexpected or duplicate alert |
| [certificate_vs_key_negative](diffs/deep_corpus_certificate_vs_key_negative.diff) | Unexpected or duplicate alert |
| [django_override_positive](diffs/deep_corpus_django_override_positive.diff) | Missed expected credential |
| [documented_sample_positive](diffs/deep_corpus_documented_sample_positive.diff) | Missed expected credential |
| [express_supertest_positive](diffs/deep_corpus_express_supertest_positive.diff) | Missed expected credential |
| [fastapi_override_positive](diffs/deep_corpus_fastapi_override_positive.diff) | Missed expected credential |
| [flask_config_positive](diffs/deep_corpus_flask_config_positive.diff) | Missed expected credential |
| [gin_httptest_positive](diffs/deep_corpus_gin_httptest_positive.diff) | Missed expected credential |
| [gitlab_variables_negative](diffs/deep_corpus_gitlab_variables_negative.diff) | Unexpected or duplicate alert |
| [junit_mock_secret_positive](diffs/deep_corpus_junit_mock_secret_positive.diff) | Missed expected credential |
| [key_ed25519_negative](diffs/deep_corpus_key_ed25519_negative.diff) | Unexpected or duplicate alert |
| [key_rsa_negative](diffs/deep_corpus_key_rsa_negative.diff) | Unexpected or duplicate alert |
| [laravel_config_positive](diffs/deep_corpus_laravel_config_positive.diff) | Missed expected credential |
| [localhost_not_mock_positive](diffs/deep_corpus_localhost_not_mock_positive.diff) | Missed expected credential |
| [mixed_interpolation_negative](diffs/deep_corpus_mixed_interpolation_negative.diff) | Unexpected or duplicate alert |
| [multiline_assignment_positive](diffs/deep_corpus_multiline_assignment_positive.diff) | Unexpected or duplicate alert |
| [nock_interceptor_positive](diffs/deep_corpus_nock_interceptor_positive.diff) | Missed expected credential |
| [percent_encoded_url_positive](diffs/deep_corpus_percent_encoded_url_positive.diff) | Missed expected credential |
| [pytest_env_positive](diffs/deep_corpus_pytest_env_positive.diff) | Missed expected credential |
| [python_responses_positive](diffs/deep_corpus_python_responses_positive.diff) | Missed expected credential |
| [spring_mockmvc_positive](diffs/deep_corpus_spring_mockmvc_positive.diff) | Missed expected credential |
| [wiremock_positive](diffs/deep_corpus_wiremock_positive.diff) | Missed expected credential |

The adjacent `.expect.json` explains each label. Complete case outcomes,
assertion failures, fixture hashes and model/prompt fingerprints are in
[baseline-2026-09-15.json](baseline-2026-09-15.json).

## Method and limits

- One sequential run per fixture through a locally built Atalaia and the
  configured private vLLM endpoint. Requested model: `google/gemma-4-E4B-it`.
- Thinking off, explicit temperature zero. Gitleaks with the repository's
  aggressive rules; deep scan enabled, 4,000-token windows, 48-window cap.
- Adjudication prompt fingerprint: `gemma4:db769fbf49cd`.
- Deep prompt fingerprint: `gemma4_deep:3f57ab299d58`.
- The working tree includes the preceding `test_data` classification fix.
  The model was not retuned while evaluating this expansion.
- All values are fabricated; embedded programs are never executed. Audit
  logging was disabled. No production deployment was changed.
- The set is synthetic and balanced, not a sample of production traffic.
  These percentages are challenge-set scores, not production precision
  or recall estimates. One sample does not establish stability.
- Location assertions accept a confirmed verdict or a discovery at the
  expected added line. They do not prove the exact raw substring selected
  within that line. See [README.md](README.md) for grading details.

Reproduce with an operator config pointing to the same trusted model:

```sh
INTEGRATION_MIN_AGREEMENT=1 CONFIG=path/to/atalaia.yaml make smoke-corpus
INTEGRATION_TAG=test-auth INTEGRATION_REPEAT=20 CONFIG=path/to/atalaia.yaml make smoke-corpus
```

The first command should fail until the recorded model/pipeline gaps are
fixed. Offline validation remains independent of the model:

```sh
go test ./internal/integration
```

Raw run log for this session: `/tmp/atalaia-expanded-corpus.log`.
