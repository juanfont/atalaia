# Evaluation diagnostics and bounded completion recovery

## Problem

The expanded corpus exposes both semantic misclassification and malformed model
output. Previously the client discarded `finish_reason` and token usage, and
parse errors could include an excerpt of model output. That made truncation
hard to diagnose and risked echoing credential bytes into error responses/logs.

## Runtime changes

The client retains completion status, token usage and reasoning fields returned
by the backend. These are internal transport data, not additions to the public
`/check` response. No raw model content is added to production logging.

Both adjudication and deep scan use one completion/recovery routine:

1. Make the normal request with its existing deadline and output-token budget.
2. If the completion ends with `length`, discard it even if its JSON parses.
   If the response is malformed, discard it as well.
3. Make at most one replacement request with a concise formatting reminder.
   It shares the original deadline and semaphore slot, keeping the same
   per-attempt output-token limit. Total generation can reach twice that limit.
4. Parse only the successful replacement. Never merge partial output into it.
5. If recovery fails, return a safe error with the failure category, attempt
   count, completion status and token count. Never echo the response body,
   reasoning, tool arguments or parser excerpts.

Valid semantic decisions are not retried. Backend `content_filter` refusals and
transport/deadline errors are not retried. The routine does not raise token limits automatically.
`llm_calls`/deep `calls` count actual attempts, rather than planned batches.
Failed deep scans retain attempt/window/latency accounting and report `failed`;
they do not publish their partial candidates as completed discoveries. Existing
adjudication verdicts survive a deep failure, as before.

Verified/sentinel short-circuits, finding-ID correlation and ownership of
existing detector findings are unchanged. Deep scan cannot override an
adjudication verdict. No filename, username or token-value blacklist is added.

## Thinking configuration

`llm.enable_thinking` is an optional boolean. When explicitly set, requests to
both stages include `chat_template_kwargs.enable_thinking`. Unset means the
extension is omitted and the backend keeps its default. This is a backend
extension, not a capability guaranteed by every compatible API. Operators must
use it only with a backend/template that supports it. It does not enable a
reasoning parser on the server.

The environment override is `ATALAIA_LLM_ENABLE_THINKING=true` or `false`.
Reasoning and generated-token counts remain internal; the evaluation recorder
captures them for synthetic cases. Backend token-detail fields are not assumed
to account for reasoning accurately, so evaluation also checks whether actual
reasoning text is present.

## Deterministic scanner input

Deduplication sorts findings by `(file, line, match)` and each detection trail
by detector type, detector name, rule and verification state. IDs, grouping,
provenance and verified short-circuits are unchanged. A test covers all 720
permutations of a representative scanner result set. This removes prompt and
request-cap differences caused by concurrent scanner/rule completion order.

## Evaluation isolation

`TestDiagnosticCorpus` is build-tagged `integration` and requires an endpoint
and explicit output path. It creates the real HTTP handler with recorded LLM,
adjudication and deep-reader seams, and runs the existing corpus assertions.
Only byte-identical fixtures from `testdata/diffs` or `testdata/holdout` are
accepted. Record files are created exclusively with mode 0600. They contain
raw **synthetic** credentials and are never enabled in production.

Grounding exposes an optional value-free decision trace for each candidate:
synthetic test data, invalid/reference candidate, placeholder, sentinel,
missing source bytes, duplicate, detector overlap or discovery. The evaluator
replays this pure decision path to obtain traces; its process-local Prometheus
counters are therefore not production performance measurements. API stats and
recorded transport timings are the evaluation measurements.

The original 176 fixtures and expectations remain fixed. A separate set of 40
contrast pairs is frozen with SHA256 hashes before tuning and is evaluated only
after selecting changes. Offline tests validate both sets. Ordinary corpus runs
still default to the original set; holdout runs must be selected explicitly.

The summary script derives correctness from the existing Go grader log and
reports case counts, recall, clean scans, latency, token use, reasoning presence,
completion status and failed cases separately. A high aggregate assertion count
must not mask a missed credential, incomplete scan or excess alert.
