# OF-360 Extraction Eval Harness

OF-360 is the HaluMem-adopted extraction-quality metric tier used by downstream
Dreamer/autoreason work. The implementation lives in `oneiron::extraction_eval`
and is intentionally offline/deterministic: extraction systems provide parsed
matches and flags, and the harness computes metrics without a runtime judge.

## Stable Inputs

Use `Of360ExtractionRun` as the AR-3-facing input shape:

- `dataset_id` and `dataset_revision` must match the selected gold dataset.
- Each `Of360ExtractedClaim` may carry zero or more `matched_gold` entries.
- A match score is the HaluMem rubric: `omitted` = 0, `partial` = 0.5,
  `full` = 1.
- `overreach` marks unsupported specificity or role attribution.
- `temporal_correct` is evaluated only when the positive gold match requires a
  temporal anchor.
- `dedup_key` controls redundancy; when absent, normalized claim text is used.

The primary entry point for AR-3-style consumption is
`of360_ar3_metric_tier(dataset, run)`, or `of360_builtin_ar3_metric_tier(run)`
for the bundled seed subset.

## Metric Definitions

Metric definitions are pinned as data in
`crates/oneiron/src/data/of360_metric_definitions.v1.json`. The top-level
`derivation_envelope` uses the same keys accepted by the repo-provenance
DerivationEnvelope-compatible shape:

- `content_hash`
- `model_id`
- `version`
- `params_hash`

The primary OF-360 parsed metrics are:

- `faithfulness_rate`
- `hallucination_rate`
- `overreach_rate`
- `temporal_correctness`
- `redundancy_rate`
- `updating_accuracy` (matched gold points whose stored `is_update` flag is true)
- `qa_accuracy` (answers matched against each QA item's accepted answers)
- `omission_rate`

The report also carries HaluMem scaffold metrics: recall, weighted recall,
target precision, and F1.

QA outputs use `Of360QaAnswer { question_id, answer }`. Unknown or duplicate
question IDs refuse the run. Missing answers remain in the denominator.

## Gold Dataset Status

`crates/oneiron/src/data/of360_gold_subset.v1.json` is a versioned smoke subset.
It is not the 500-point owner-authored gold corpus requested by ONE-198 and
ONE-1524. The fixture metadata keeps `owner_corpus_missing = true` and
`target_full_memory_points = 500`; reports over this subset include a warning.

`generate_of360_seeded_gold_subset` performs deterministic subset selection from
the bundled seed rows. It does not synthesize replacement gold labels.

`crates/oneiron/src/data/of360_gold.v1.json` supplies the full v1 fixture through
`of360_gold_corpus()`: 500 memory points across 50 scenarios, plus grounded QA
items. It was authored for this ticket and is explicitly synthetic, not private
owner data. The full loader reports `owner_corpus_missing = false` and no seed
warning. The original subset and its warning remain available for smoke tests.

The 500-point integration fixture supplies exact extraction matches and QA
answers to test the scorer. Its perfect score validates accounting, not a model's
extraction quality. Live systems must provide their own predictions.
