# Opt-in source-literal selection

## Problem and contract

Repeated evaluation shows Gemma evaluating escaped source strings while copying
credentials. The API tool arguments already contain changed bytes. Native backend
parsing and Go decoding preserve correctly encoded strings; relaxing grounding
would hide the actual failure.

Add `llm.deep_scan.source_literals`, false by default. When enabled, a window may
include a bounded catalog of closed single/double-quoted source literals containing
backslashes. This is lexical source extraction, not secret classification. The
model still decides whether each value is a credential, test data, or irrelevant.

A candidate may return `source_id` instead of `value`. IDs identify exact source
values in the current window's catalog, not file positions. Resolution returns
those original bytes unchanged, then the existing grounding, ownership, reference,
sentinel, test-data and redaction checks still run. Unknown IDs and conflicting
ID/value pairs are invalid. A response cannot invent source bytes or locations.
Plain `value` responses remain supported for all other credentials and for older
profiles. The default schema and model requests remain unchanged when disabled.

This extends the deep-scan design's values-only model contract for an opt-in
profile: the internal candidate passed to grounding remains a value, with no
model-supplied location. The HTTP response contract is unchanged.

## Bounds and failures

Catalogs contain at most 32 unique values and at most 4096 bytes of serialized
catalog data. Each value is at most 512 bytes. Invalid UTF-8, malformed or unclosed strings are
omitted; omitted strings remain visible in the original window. Catalog omission
is not scan truncation. If the enhanced prompt exceeds the configured input budget,
render the original prompt without a catalog. No original source window is removed.

With a catalog present, a non-private-key candidate value absent from the source
window is an invalid source copy. The existing single bounded response-replacement
attempt may ask the model to return a source ID. This does not decode, normalize or
accept the invalid value. Errors after replacement remain deep errors. Calls share
the original per-window deadline, output limit and semaphore slot.

The source catalog lives only for a window's request. It is never included in
API responses or application logs. Synthetic diagnostic recording stays opt-in.

## Selection

The new 32-case set was frozen before this change. Tune only on existing cases,
freeze the resulting configuration before fresh comparison, then compare retained
baseline, round-three candidate and the new candidate. Do not tune after fresh
results. The completed repeated comparison supports shipping the paired profiles as an
opt-in configuration. Defaults remain unchanged. See
[the final report](../../../internal/integration/testdata/ROUND4-CONTINUATION.md).
