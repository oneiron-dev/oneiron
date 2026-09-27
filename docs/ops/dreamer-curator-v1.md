# Dreamer curator v1 grading policy (ONE-2026 / OF-191)

This is the v1 question set authored for the curator attempt. Its runtime text and numeric
knobs live in `crates/oneiron/src/dreamer_runner/maintenance/curator_defaults.json`.
A vault owner can replace the row through `set_curator_rubric`; the engine checks
all three question texts and the numeric bounds before scheduling or running.
The answer is a Generated/Proposed claim, not an applied demotion. A reviewer
must re-read the target and its source hash before accepting any action.

| Question | Answer from stored facts | Effect |
| --- | --- | --- |
| Authorship | Active, approved/auto, Generated claim with one matching Dreamer actor and Dreamer surface in its write provenance | Refuse other writers or ambiguous provenance. |
| Freshness | Age since the claim's `learned_at` meets `minimum_age_secs` (v1: 86,400). | Hold young claims. Age is a review trigger, **not** evidence that a claim is false. |
| Least force | Read the recorded demotion rung, rejecting malformed or duplicate stamps. | Suggest only the next permitted rung, never a jump. |

The v1 demotion rubric is: no rung → `claim_of_weight` (factor 0.8),
`decayed` → confidence weakening (factor 0.8), `weakened` → stale-mark,
`stale` → retract. The proposal contains the target body hash, question set,
observed grade, and suggested action. Freshness reports the stable `learned_at`
stamp and policy threshold, not the elapsed age at each wake: an unchanged
source and policy must produce one proposal across nightly/idle retries.
These are **proposals**, not proof of a semantic contradiction. The reviewer
checks present-day corroboration and rejects the proposal if the evidence still
supports the belief. A semantic
verdict cannot be inferred from elapsed time. Never use VAD, a hard delete,
or an automatic acceptance of this review cue.

## Re-tune flag rubric

Harness maintenance compares immutable config artifact versions. Score drops
must exceed each target's [0, 1] cutoff: prompts 0.05, weights 0.08, and
manifest thresholds 0.10. A backbone change flags all three review surfaces,
even without score loss. Otherwise a changed config flags only the changed
surfaces whose cutoff was crossed: prompt references, weight map, or
manifest-threshold map. If the typed config is unchanged, the crossed cutoffs
still flag their respective surfaces for diagnosis. A non-regressing change
alone does not emit a re-tune flag. The flag is a proposal to review settings,
not an automatic retune.
