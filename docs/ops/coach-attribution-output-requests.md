# Explicit output placement for Coach skill discovery

A native host can queue a skill-discovery pass with
`DreamerRunnerStore::enqueue_coach_skill_discovery`. The request is stored in
that job's input. The existing Coach host dispatcher reads it after the normal
Coach-attempt check and forwards it through the task sweep to the attribution
projector.

`skill_attribution::AttributionOutputReadRequests` has two independent maps:

- `judgments`: persisted attribution evidence sequence to
  `AttributionJudgmentReadPosition`.
- `proposals`: persisted attribution evidence sequence to
  `SkillEditProposalReadPosition`.

Each key addresses evidence in the same vault. Each position explicitly declares
all its placement axes. These declarations are output data, not read grants.
Judgment placement does not supply proposal placement. Receipt, executor,
funding and source-read metadata do not supply either map.

The pass looks up only the evidence it actually routes. A missing key leaves the
new output's placement unknown. Extra keys create no output and do not move a
cursor. Stored judgments keep their original placement, including unknown;
replays do not restamp them. Stored proposals keep their position only while
their contents remain unchanged, as in the ordinary projector.

The enqueue method accepts the caller's parent attempt, optional advisory dedupe
key, run ID and time. It uses the Coach host queue, not the generic Dreamer queue.
The existing queue's dedupe rules apply. A key shared with another queued job can
return that existing job, so callers should not use the nightly facet key when
they intend a separate request. There is no new coalescing rule.

Ordinary nightly jobs still carry Nil input and request no placement. An
unrecognized optional input leaves placement unknown and does not refuse the
pass. Existing direct projector batch-placement APIs remain available.

This API does not declare a complete input read set, grant source access, enable
FACT or authorize model release. Readers still need the original full read key
and the actual canonical/native row checks. Model release remains separate.

## Type-tree upkeep outcomes

`DreamerRunnerStore::enqueue_coach_type_tree_upkeep_with_requests` accepts
`dreamer_runner::maintenance::coach::TypeTreeOutcomeReadRequests`. Its `outcomes`
map addresses each output by the exact pair of skill head and leader pack receipt
passed to the native contributing-win or settled-loss door. The receipt fixes
that outcome's executor. A team reference or a later-selected head does not
supply a position.

The original Coach-attempt check runs before the optional request is read. The
ordinary settled-team, run-binding, terminal-pack and exact manifest checks all
run before any lookup. Missing entries stay unknown; extra entries create no
outcome. The other fork-promote callers still request no placement. Nil nightly
jobs, unknown optional input, retained birth and no-restamp behavior are unchanged.
