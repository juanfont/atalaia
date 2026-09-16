# Quality-first evaluation round

## Objective

Reduce missed credentials and false alerts. Latency is measured but does not
select the winner. Keep the production default and deployment unchanged until
there is evidence for a configuration recommendation.

## Experiment order

1. Run thinking on against the unchanged 80-case round-two holdout. Compare
   primary requests with the prior thinking-off run, excluding only the mode.
2. Freeze 24 fresh contrast pairs before modifying prompts. These 48 cases
   test related failure categories with new literals, code and combinations.
   They are a stratified synthetic check, not a production sample.
3. Use the original 176 cases and now-revealed 80 cases for development. Make
   mock interception semantics consistent, preserve exact source bytes and
   separate credential role from shape. Keep detector ownership, grounding,
   redaction and semantic decisions in their existing layers.
4. Compare candidate modes. Select first for credential recall, then false
   alerts; report any tradeoff rather than hiding it in a composite score.
5. Freeze the selection and hashes before running the fresh cases. Evaluate
   both baseline and candidate on the fresh cases without further tuning.
   Repeat selected configuration on both familiar and fresh cases.

## Constraints

Do not edit existing fixture labels, relax assertions, decode guessed values
into source bytes, allow deep discoveries to override detector verdicts, or
add framework-name suppression rules. Every discovery still requires actual
added source bytes. All captured raw records are synthetic and stay in explicit
mode-0600 files. Durable reports include only counts, case names and hashes.

## Validation

Run fixture/manifest checks, the offline Go suite, vet, the Python summarizer
checks and live diagnostic evaluations. Report complete-case results, expected
credential locations, clean negatives, failed stages and repeated stability.
The current grader checks location and kind, not exact substring equality;
state that limitation in conclusions. A failed experimental candidate stays
in the experiment record and must not silently become the selected prompt.

## Function-shaped password grounding

The existing call-shape guard discards a valid password such as `ForestPass(27)`
even inside a quoted DSN. Allow that candidate only when its first added-source
occurrence is the complete content of a closed single/double-quoted literal,
or the exact `:value@` password component of a quoted connection string.
Reject interpolation, escape-containing strings, unterminated strings and
unquoted calls. This is source syntax evidence, not a credential classifier;
the model still supplies the credential role and existing ownership, sentinel,
length and redaction checks still apply. No decoding or fuzzy matching is added.
The baseline grounding source is preserved with a verified hash and can be
compiled through a Go overlay for baseline comparisons without changing files.

## Connection-string redaction

Review of a development response found that the model returned a whole URL
while its explanation quoted only the password. Exact-whole-match scrubbing
missed the password fragment. Scrub recognized URL userinfo components in both
source-encoded and decoded forms, and MySQL tcp/unix DSN components. Redact
MySQL userinfo in previews too: generic head/tail masking can expose an entire
short password. Keep raw source bytes unchanged for audit and grounding.
This is a redaction change only; it does not accept decoded model candidates.
The baseline redactor is archived and included in the baseline Go overlay.
