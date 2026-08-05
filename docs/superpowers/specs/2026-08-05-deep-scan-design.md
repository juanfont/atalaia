# Deep scan: LLM-discovered secrets the detectors missed

Date: 2026-08-05
Status: approved, not implemented

## Problem

A diff can contain a detector finding that is a genuine false positive
and, elsewhere in the same diff, a real credential that no detector
flagged. Atalaia today reports the first as `dismissed` and never
mentions the second. The caller reads an all-dismissed response with
clean stats as "no secrets in this diff". A false clean is a worse
failure than the false positive the pipeline exists to remove.

This is structural, not a bug in any one function:

- In whole-diff mode the model does receive the full diff
  (`adjudicate.go`, `PromptData.Diff`), so the unflagged secret is in
  its context window.
- The output contract has no way to report it. `VerdictSchema` requires
  a `finding_id` per verdict, and `mergeAndFill` iterates the bound
  finding set, so a verdict for an unknown id is silently discarded.
- The adjudication prompt actively steers away from noticing: "Lean
  toward dismissing" and "Judge the matched value itself, not the code
  around it".
- In per-finding mode (diff over `context_budget.input_tokens`) the
  model never sees the diff at all, only `finding_context_lines` around
  each match. The exposure is inverted: the largest commits, where an
  unflagged secret is most likely to hide, are the ones where the model
  is structurally blind to it.

## Decisions

Settled during design, with the reasoning that fixed each:

1. **Async, non-gating callers only.** Atalaia ships no webhook
   receiver; the watcher is external and already owns the queue,
   concurrency cap, retries, and notification (`docs/deployment.md`).
   A non-gating caller can simply afford a slower synchronous call, so
   this needs no job ids, no result storage, no callbacks, and no
   departure from statelessness.
2. **Second pass in a separate channel.** Detectors and adjudication
   are untouched. The deep read is additive and lands in its own field,
   never mixed into `verdicts[]`. "Detectors detect, the LLM decides"
   still holds for the load-bearing channel.
3. **Per-request opt-in on `/check`.** One endpoint, one auth path,
   one response shape. Default off, so every existing caller is
   unaffected.
4. **Added lines first, then window.** Secrets are added, not removed.
   The added-line set is a fraction of a typical diff; if it still
   overflows the budget, sweep it in windows.
5. **Scope: live credentials and private key material.** Same bar as a
   `confirmed` verdict, plus PEM/SSH key material as a hedge against a
   wrapped or mangled key defeating the regex.
6. **Grounding by verbatim value, never by model-supplied location.**
   The model returns the credential value; atalaia finds it in the diff
   and derives the position itself.

Rejected: LLM as sole detector on this path (loses trufflehog's
`verified: true` short-circuit, the one signal more trustworthy than
the model, and regex's reliable recall on structured keys); merging
discoveries into `verdicts[]` (existing consumers would page on
un-triaged model output); model-supplied file and line (line arithmetic
is what small models are worst at, and with no exact value there is no
stable id and no reliable dedupe).

## Request flow

`POST /check` gains `deep: true` in the JSON body, or `?deep=1` for the
`text/x-diff` content types. Bearer auth is unchanged.

When set, two stages run against the same parsed diff:

- **Adjudication** — detectors, dedup, short-circuits, LLM. Exactly as
  today. Produces `verdicts[]`.
- **Deep read** — the added-line set handed to the LLM cold, with no
  detector hits in the prompt. Produces candidates, which grounding
  turns into `discoveries[]`.

They run as concurrent goroutines, each acquiring the LLM semaphore
independently. At the default `max_inflight: 1` this degrades to
sequential execution at the GPU, which is correct: the stages take
turns. Operational consequence to document: a deep request occupies up
to two queue waiters, halving effective `queue_max` capacity for deep
callers.

The deep read runs **even when detectors found nothing**. A
clean-looking diff that isn't clean is the general case of this bug,
and today it never reaches the model at all.

## API surface

`discoveries[]` is a new `omitempty` field on `CheckResponse`, absent
for non-deep requests.

```go
// Discovery is a credential the LLM found in the diff that no detector
// flagged. Lower trust than a Verdict: nothing corroborates it but the
// model's judgement, so it must not gate a merge unreviewed.
type Discovery struct {
    ID           string  `json:"id"`
    File         string  `json:"file"`
    Line         int     `json:"line"`
    MatchPreview string  `json:"match_preview"`
    Kind         string  `json:"kind"`       // "credential" | "private_key"
    Confidence   float64 `json:"confidence"`
    Reason       string  `json:"reason"`
}
```

No `verdict` field: membership in the array is the claim. No
`detections[]`: nothing detected it. The `id` uses the existing
`sha256(file + ":" + line + ":" + match)[:12]` scheme, so a discovery
and a detector finding covering the same bytes collide by construction;
on collision the discovery is dropped, because `verdicts[]` is
authoritative. The two arrays are always disjoint.

`Stats` gains:

```go
type DeepScanStats struct {
    Ran         bool   `json:"ran"`
    Calls       int    `json:"calls"`
    Windows     int    `json:"windows"`
    Candidates  int    `json:"candidates"`
    Discovered  int    `json:"discovered"`
    Ungrounded  int    `json:"ungrounded"`
    Truncated   bool   `json:"truncated"`
    LatencyMs   int64  `json:"latency_ms"`
    Error       string `json:"error,omitempty"`
}
```

Carried on `Stats` as:

```go
DeepScan *DeepScanStats `json:"deep_scan,omitempty"`
```

## Deep-read stage

`internal/llm/deep.go` holds a `DeepReader`; `internal/llm/ground.go`
holds grounding. The split matters because grounding is a pure function
— diff bytes and candidates in, discoveries out, no LLM, no clock — so
the risky half of the feature is testable without a model.

### Input construction

`detector.WalkDiff` already returns one `AddedBlock` per contiguous run
of `+` lines, carrying a path and a post-image start line. Blocks render
as a `path:startline` header followed by content, packed into windows
sized against `context_budget.input_tokens` via the existing
`estimateTokens` in `internal/llm/context.go`. A block larger than one
window splits by lines. Window count is capped by
`deep_scan.max_windows`; past the cap, coverage stops and
`stats.deep_scan.truncated` is true. Windows are scanned sequentially
under a single semaphore acquisition, mirroring how `Adjudicate`
handles batches.

Dropping context and removed lines is what makes this affordable. A
secret appearing only in a removed line was committed in an earlier
push and belongs to a history scan, not this one.

### Prompt

New profile pair, `prompts/gemma4_deep_{system,user}.tmpl`, selected by
`deep_scan.profile`.

This prompt must not inherit the adjudication prompt's posture. That
one is deliberately default-dismiss because it is a precision filter
handed a candidate. The deep prompt is the opposite job: recall across
a haystack with nothing handed to it. The bar stays a genuine, usable
credential or private key material. The instruction that carries the
whole design: reproduce each value **verbatim, exactly as it appears in
the line**.

### Schema

Separate from `VerdictSchema`:

```json
{"candidates":[{"value":"…","kind":"credential|private_key",
                "confidence":0.0,"reason":"…"}]}
```

Tool name `submit_candidates`, reusing the existing `use_tools`
machinery and parser conventions. The model supplies no file, no line,
and no id — it has no way to express a location, so it has no way to
hallucinate one.

## Grounding

Per candidate, in order:

1. Cheap rejects: empty, shorter than 6 characters, or reference-shaped
   (`$VAR`, `${VAR}`).
2. `detector.LocateInDiff(diff, value)` → `(path, line)`. On a miss,
   normalize once (trim whitespace, strip matching surrounding quotes
   or backticks, drop a trailing comma or semicolon) and retry. Still a
   miss: drop the candidate and bump `atalaia_deep_ungrounded_total`.
   This gate is absolute — a fabricated secret cannot survive it,
   because it is not in the diff.
3. Build `detector.Finding{File, Line, Match: value}` and take its
   `detector.FindingID`.
4. Run the existing sentinel short-circuit from
   `internal/llm/shortcircuit.go`. `AKIAIOSFODNN7EXAMPLE` discovered
   cold is dropped by the same table that dismisses it in the other
   channel.
5. Drop on id collision with any `verdicts[]` entry; dedupe discoveries
   against each other by id, so the same secret found in two windows
   collapses to one.
6. `MatchPreview = redact.Preview(value)`,
   `Reason = redact.Scrub(reason, value)`.

`LocateInDiff` exists because `trufflehog stdin` reports matches without
source positions. Grounding a tool's output against the diff is an
established pattern in this codebase, not a new invention.

### Private key carve-out

A PEM block spans dozens of lines, `LocateInDiff` searches line by line,
and no 4B model reproduces a 40-line key body verbatim. For
`kind: private_key`, grounding uses the first non-empty line of the
returned value — in practice the `-----BEGIN … PRIVATE KEY-----` header
— and the preview derives from that header rather than the key bytes.
Recall on what matters, with no dependence on the model transcribing key
material.

## Failure isolation

A deep-read failure (timeout, backend 5xx, unparseable output) never
fails the request. `verdicts[]` is the primary product and stands on its
own. The failure surfaces as `stats.deep_scan.error` with `discoveries`
absent, following the precedent `DetectorErrors` set: a caller must
never read a missing result as a clean one.

Adjudication failure still fails the whole request, as today. The
asymmetry is deliberate: one channel is load-bearing, the other is
additive.

## Configuration

Under `llm`:

```yaml
deep_scan:
  enabled: true       # operator kill switch
  max_windows: 8      # coverage cap; beyond it, truncated: true
  max_candidates: 50  # per LLM call; extras are discarded before grounding
  profile: gemma4_deep
```

With `enabled: false`, a `deep=true` request succeeds normally and
reports `stats.deep_scan.ran: false`. Explicitly false, never silently
absent.

## Metrics

- `atalaia_deep_scan_total{result="ok|error|disabled"}`
- `atalaia_deep_candidates_total`
- `atalaia_deep_ungrounded_total`
- `atalaia_deep_discoveries_total`
- `atalaia_deep_latency_seconds` (histogram)
- `atalaia_deep_windows` (histogram)

The ratio to alert on is ungrounded ÷ candidates: the model's
hallucination rate, measured directly. A climb means the channel is
drifting. A panel goes in the existing `docs/grafana` dashboard.

## Testing

Unit, grounding (no GPU needed):

- a fabricated value is dropped
- each normalization variant grounds (quoted, trailing comma, padded)
- a sentinel discovered cold is dropped
- an id colliding with `verdicts[]` is dropped
- the same secret in two windows collapses to one
- a PEM block grounds on its header line
- previews are redacted, reasons are scrubbed of the raw value

Unit, windowing and wiring:

- an oversized block splits across windows
- `max_windows` sets `truncated`
- a secret present only in a removed line is never scanned
- a deep-read error leaves `verdicts[]` intact and sets
  `stats.deep_scan.error`
- `deep=false` makes no deep LLM call and emits no `discoveries` field

Corpus (integration, `internal/integration/testdata`), extending the
existing diff + `.expect.json` pairs with `expect_discoveries` and a
`max_discoveries` ceiling:

- **quirk fixture** — a decoy that fires a detector and is a genuine
  false positive, plus a real credential no detector sees. Passes only
  when the decoy is still `dismissed` in `verdicts[]` *and* the real
  secret appears in `discoveries[]`. The reported bug, encoded as a
  gate.
- **quiet fixture** — a substantial, entirely clean diff, asserting
  `discoveries` is empty. This decides whether the channel is worth
  reading: a deep scan that cries wolf on ordinary code is worse than
  no deep scan, and it is the expected failure mode of a 4B model asked
  for recall.

## Documentation

- `docs/api.md` — the `deep` flag, `discoveries[]`, the `deep_scan`
  stats block, and an explicit statement that discoveries are a
  lower-trust channel that must not gate a merge unreviewed.
- `README.md` — architecture diagram gains the second path.
- `AGENTS.md` — "Detectors detect, the LLM decides" needs an explicit
  exception clause, or the next reader will file this feature as a bug.
- `CHANGELOG.md`.
- `config.example.yaml` — the `deep_scan` block.

## Out of scope

- Any change to the default (non-deep) `/check` behaviour.
- A webhook receiver, job queue, or result storage inside atalaia.
- Deep scanning of removed lines or repository history.
- Widening scope beyond credentials and private key material (no PII,
  no internal hostnames).
- Promoting a discovery into `verdicts[]`, now or automatically later.
