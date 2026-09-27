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
