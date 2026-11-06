# Dreamer harness-maintenance v1 policy (ONE-2027 / OF-191)

The engine reads immutable `DreamerTuningConfig` blob-artifact versions and scheduled
`HarnessEvaluation` scores. The first valid observation is a baseline, not a finding.
A later backbone change flags **prompts, weights, and manifest thresholds** together.
Otherwise the observed aggregate score drop from the last accepted baseline
flags targets whose configured cutoffs it exceeds. If config surfaces changed,
only those changed surfaces are flagged; with no typed config change, crossed
cutoffs remain score-only diagnostic flags:

| Target | Default absolute drop (score range 0–1) | Review question |
|---|---:|---|
| Prompts | > 0.05 | Did the instruction or task framing change the judged outcome? |
| Weights | > 0.08 | Did ranking or evidence emphasis favor the wrong memory? |
| Manifest thresholds | > 0.10 | Did a configured admission or selection threshold suppress needed evidence or admit noise? |

These are **review flags**, not causal attribution. An aggregate score cannot tell
which setting caused the regression. A backbone swap triggers review even if the
score improved. The default cutoffs live in `retune_defaults.json`; a vault owner
can set different cutoffs using `set_retune_thresholds`. All findings use the
existing Generated/Proposed gate and never apply a config edit automatically.
The score has to be finite and in `[0, 1]`; cutoffs have the same range.
Equality at a cutoff does not flag a target. Every accepted version updates the
baseline, including a recovery. The evaluator does not run a grading model by
itself: the caller supplies an eval score for the pinned artifact version.

## Consolidation-grading question set

For a human or host-supplied judge reviewing Dreamer consolidation output:

1. Is the generated claim backed by the cited first-party evidence and its scope?
2. Does it preserve uncertainty and contradiction instead of merging competing
   claims into an unsupported certainty?
3. Is it still current, or has later evidence superseded its time or source?
4. Does its retrieval pull improve the answer, or does it repeatedly steer
   answers away from better evidence?
5. Can the issue be fixed by lowering retrieval pull alone, without editing or
   deleting the claim? Which evidence would justify a stronger rung?

The current curator is a deterministic candidate selector and proposal writer;
it does **not** answer these questions or claim to be an LLM grader. These are
questions for the judge behind the external score/review step, not hidden
hardcoded prompt text in the engine. They are not automatically executed by
`schedule_curator`.

## Demotion rubric

Recommend the minimum-force change supported by evidence: reduce the
`claim_of` edge weight first, then weaken claim confidence if the edge lever
is insufficient, then mark stale if newer evidence defeats it, then retract
only when the claim is demonstrably wrong. Never hard-delete for quality
grading, never use VAD as a demotion lever, and never promote a proposed
change without the normal gated approval path. The existing curator proposes
this sequence; `curator_defaults.json` supplies its minimum age, cadence,
edge-weight factor, and confidence factor. A proposal is a request for review,
not a factual verdict from those five questions.

Canon: ARCH-0026, “Curate own output” and “Observe and attribute”.

## Owner-set curator rubric

`GET /v1/owner/dreamer/maintenance/curator-rubric` reads the actual stored
`CuratorRubric`, or the validated shipped defaults when no owner row exists.
The real owner proof and active-person check are revalidated in that same
read snapshot. It is a policy read, not a grading verdict.

`POST` to the same path replaces the complete rubric through the unchanged
native `set_curator_rubric` owner act. Its normal grouped writer revalidates
the owner and active person before storing anything. The response echoes the
rubric that committed, not a second read or a promise that no later writer
changed it. No pass is queued by setting the rubric. Subsequent native
scheduling/passes consume it as before; existing slot/dedupe behavior stays.

The full JSON object has `minimum_age_secs`, `edge_weight_factor`,
`confidence_factor`, `cadence_secs` and `questions`. The questions object has
`authorship`, `freshness` and `least_force`. Unknown fields are invalid.
Native validation is unchanged: cadence is nonzero; both factors are finite,
at least zero and less than one; each question is non-blank. No new defaults,
limits or automatic judge are added. The question wording remains policy
data; the deterministic curator does not answer it with a grading model.

Curator maintenance and OF-216 strength maintenance remain distinct. The
curator's owner-configured weight/confidence/stale/retract ladder and its
nightly/idle scheduling are unchanged. Strength orders selection and archives
quiet weak claims; its separate operator policy is not exposed as owner
policy by these routes. Archive behavior and maintenance of retained history
are unchanged. This control surface does not complete curator quality grading
or reconcile every policy question in FIX393.

## Owner-supplied evaluation input

`POST /v1/owner/dreamer/maintenance/harness-evaluation` accepts
`{"artifact":"<32 hex>","version":1,"score":0.8}` through the existing owner
credential door. The engine revalidates the actual owner and credential in the
same writer that validates the artifact, immutable version and finite `[0, 1]`
score and queues the maintenance attempt. The response's `attempt` is the actual
new or existing attempt, not a finding or proof that evaluation has completed.
The ordinary native host scheduling API remains available.

This is an owner-supplied observation, not an engine-verified evaluator result.
It does not select, run or attest an extraction-gold or BEAM evaluator. Those
external score producers still need their own integration. The scheduled run
uses the existing baseline, regression and retune-finding rules above.

## Owner-selected native OF360 metric

`POST /v1/owner/dreamer/maintenance/harness-evaluation/of360` takes:

- `artifact`: the tuning-config artifact as 32 hex;
- `version`: its immutable version, explicitly associated with the run by the owner;
- `metric`: one native metric name from the table below;
- `dataset`: the complete native `Of360GoldDataset` JSON;
- `run`: the complete native `Of360ExtractionRun` JSON, including its graded matches.

The input schemas and native scoring rules are described in
[`docs/of360-extraction-eval.md`](../of360-extraction-eval.md). The caller supplies
both inputs. No corpus, run or metric is silently selected. This door neither
runs a model nor supplies the missing independent 500-point owner gold corpus.
It does not prove that the named tuning version produced the supplied run.

The engine calls the existing pure `of360_ar3_metric_tier` over those typed
inputs. Native dataset/run id and revision checks still apply. It selects one
real rate, not a mean across metrics. The native definition supplies its direction:

| Native metric | Harness quality score |
|---|---|
| `halumem_recall`, `halumem_weighted_recall`, `target_precision`, `halumem_f1`, `faithfulness_rate`, `temporal_correctness`, `updating_accuracy`, `qa_accuracy` | Native value |
| `hallucination_rate`, `overreach_rate`, `redundancy_rate`, `omission_rate` | `1 - native value` |

The reply contains `observation` with the raw rate (value, numerator and denominator),
direction, quality score, selected metric, dataset/run identity, canonical typed-input
BLAKE3 digests, metric-definition digest and native evaluator warnings. Typed-input
digests identify the parsed inputs, not the original HTTP bytes or independent truth.
Gold matches, partial/full grades, temporal correctness and overreach labels still
come from the supplied run. Native arithmetic is not independent PASS or proof of
execution. Seed-subset warnings remain visible.

A zero-denominator metric has no observation score. The response then has
`attempt: null` and `observation.score: null`; it invents neither zero nor a pass
and changes no baseline. Otherwise `attempt` names the actual new or existing
maintenance attempt, not a completed maintenance run. The existing owner-float
endpoint remains available and unchanged.

Pure scoring runs outside the write transaction. Before any enqueue, the existing
owner proof is revalidated first in the same writer that validates the real config
artifact and immutable version. The queued payload stores the exact typed gold,
run and metric. The maintenance consumer recomputes the observation rather than
trusting a supplied report or scalar. Full canonical payload bytes supply the native
dedupe key, so a repeated identical request reuses the current attempt.

OF360 baselines are separate from the existing owner-acceptance/owner-float baseline.
Their key binds the actual config artifact, canonical gold digest, metric and native
metric-definition digest. A changed gold payload or metric starts a separate baseline,
even if its labels are reused. Config version and run output may vary within a baseline;
that permits comparison across runs/config changes over the same gold and objective.
The owner selects the associated system and runs; this is not a controlled experiment.
The actual finding still names the real config artifact, not the internal baseline key,
and records the current OF360 observation's provenance. The normal thresholds,
stale-version/time rule and atomic finding/receipt/baseline write are unchanged.

The nightly owner-acceptance audit and the original three-field scheduling APIs keep
their existing keys and meaning. BEAM aggregation, authenticated execution provenance,
independent gold and automatic evaluator selection remain open. Nothing applies or
deploys a tuning change.
