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

The report also carries HaluMem scaffold metrics: recall, weighted recall,
target precision, and F1.

## Gold Dataset Status

`crates/oneiron/src/data/of360_gold_subset.v1.json` is a versioned smoke subset.
It is not the 500-point owner-authored gold corpus requested by ONE-198 and
ONE-1524. The fixture metadata keeps `owner_corpus_missing = true` and
`target_full_memory_points = 500`; reports over this subset include a warning.

`generate_of360_seeded_gold_subset` performs deterministic subset selection from
the bundled seed rows. It does not synthesize replacement gold labels.
