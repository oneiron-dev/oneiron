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
observed grade, and suggested action. These are **proposals**, not proof of a
semantic contradiction. The reviewer checks present-day corroboration and
rejects the proposal if the evidence still supports the belief. A semantic
verdict cannot be inferred from elapsed time. Never use VAD, a hard delete,
or an automatic acceptance of this review cue.

## Re-tune flag rubric

Harness maintenance compares immutable config artifact versions. The default
score-regression threshold is strictly greater than 0.05 on the [0, 1] score.
A backbone change flags all three review surfaces, even without score loss.
On score loss without a backbone change, flag only surfaces that changed since
the prior evaluated version: prompt references, weight map, or manifest-threshold
map. If the config is byte-equivalent at the typed-value level, flag all three
for diagnosis rather than hiding a genuine score loss. A non-regressing change
in prompts, weights, or manifest values is not enough to emit a re-tune flag.
The flag is a proposal to review settings, not an automatic retune.
