# Ciphertext classification regression

A reported alert correctly identified an encrypted credential and nevertheless
confirmed it as a leak. The correction is a general distinction between encrypted
credential storage and exposure of a credential. No product name or encrypted
format is hardcoded into the prompt rule or runtime.

## Change

The default and source-selection system prompts now dismiss recognized credential
ciphertext. Evidence must come from the format or decrypting code, not a secret
field name, random-looking bytes or a comment claiming encryption. Base64 and
hex encoding alone do not establish encryption. Opaque values used directly for
authentication remain credentials. Plaintext credentials and literal decryption
passwords/keys are judged independently, even beside ciphertext in the same file.

Private-key reporting is unchanged, including encrypted private-key blocks.
Detectors, schemas, grounding, budgets and configuration defaults are unchanged.

## Targeted results

Twelve synthetic cases form six contrast pairs. The source pair was run twice
per case. The default baseline and initial candidate were run once, followed
by two runs per case of the revised default candidate. Case counts require every
repeat to pass; credential and clean-negative denominators count individual requests.

The initial candidate received the same general rule in all four system templates.
The source pair was not changed after its results. The first default candidate
still flagged one ciphertext case and missed a decryption key, so it received a
further general clarification: decryption precedes authentication, and decoding
a literal key does not make its embedded bytes a runtime reference. The revised
default candidate was run twice per case. Initial failures remain in the table.

| Profile | Runs per case | Complete cases | Credentials found | Clean negative scans |
| --- | ---: | ---: | ---: | ---: |
| source-baseline | 2 | 7/12 | 11/12 | 5/12 |
| source-candidate | 2 | 12/12 | 12/12 | 12/12 |
| default-baseline | 1 | 9/12 | 6/6 | 4/6 |
| default-candidate | 1 | 10/12 | 5/6 | 5/6 |
| default-revised | 2 | 12/12 | 12/12 | 12/12 |

The released source profile confirmed one Vault case in one of its two runs,
explaining that the finding held an encrypted API token intended for deployment.
Its standalone encrypted-Vault case passed. The report's exact production input
was not replayed. The cases use freshly generated ciphertext and fabricated
credentials, including valid Ansible Vault and AES-GCM payloads whose round trips
were checked during fixture creation.

The generic AES-GCM cases also reproduced the reported reasoning error: the
baseline described a value as encrypted but still confirmed it. The counterpart
uses identical base64/hex bytes directly as a bearer token and must be reported.
Other pairs check a neighboring plaintext token, a Vault password and a literal
decryption key. Strict alert limits reject extra ciphertext alerts even when the
real credential is also found.

## Existing regression controls

- `source-holdout4`: 32/32 complete cases in one run.
- `source-controls`: 8/8 complete cases in one run.

These cover the 32 round-four cases and eight existing base64/private-key/public-key
controls. The historical frozen fixture manifests are unchanged. This is targeted
regression evidence, not a new independent holdout score or a full-corpus rerun.
The new cases increase the corpus to 348 fixtures.

## Reproduce

Run from the repository root with a trusted Gemma endpoint. Substitute `source`
with `default` and `candidate` with `revised` for the final default profile.
Select the corresponding `*-baseline.yaml` for released templates. The initial
default candidate can be replayed with `default-initial-replay.yaml`.
Use a distinct output path each time; raw records contain synthetic values.

```sh
EVAL_ENDPOINT=http://127.0.0.1:8000/v1 \
EVAL_OUTPUT=/tmp/ciphertext-source-candidate.jsonl \
EVAL_CONFIG=internal/integration/testdata/ciphertext-2026-09-17/source-candidate.yaml \
EVAL_THINKING=on EVAL_SET=diffs INTEGRATION_REPEAT=2 \
INTEGRATION_MIN_AGREEMENT=1 INTEGRATION_MIN_FIXTURE_AGREEMENT=1 \
go test -tags=integration -count=1 -timeout 30m -v ./internal/integration \
  -run '^TestDiagnosticCorpus$/^deep_ciphertext_' > /tmp/ciphertext-source-candidate.log 2>&1
python3 scripts/summarize-eval.py /tmp/ciphertext-source-candidate.jsonl \
  /tmp/ciphertext-source-candidate.log /tmp/ciphertext-source-candidate-summary.json
```

The baseline templates are copied from v0.8.0. Both configurations use the same
current runtime and Gemma 4 E4B backend, thinking enabled, temperature zero,
24,000 input tokens, 4,096 output tokens and a 120-second per-call deadline.
Source selection is enabled only for the source profile pair.

[Initial input hashes](ciphertext-2026-09-17/inputs.json) pin the fixtures, templates
and configs used in the first comparison. The initial default templates are
preserved in `initial-candidate-prompts/`. [Revised input hashes](ciphertext-2026-09-17/revised-inputs.json)
pin the final default revision; source templates are unchanged. Summaries beside
those inputs preserve per-case outcomes and completion errors. [Validation](ciphertext-2026-09-17/validation.json) checks those
hashes and expected literal echoes in the synthetic API responses. Its limits
are recorded there. Offline validation: `go test ./...` and `git diff --check`.

The change is uncommitted and has not been released or deployed.
