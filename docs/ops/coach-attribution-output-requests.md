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
outcome. Nil nightly jobs, unknown optional input, retained birth and no-restamp
behavior are unchanged.

## Project fork and leaf-promotion outcomes

`DreamerRunnerStore::enqueue_coach_fork_promote_with_requests` accepts the same
`TypeTreeOutcomeReadRequests` and queues the existing `coach.fork_promote` pass.
The original Coach-attempt check runs before decoding the durable job input. The
request then reaches all three settled-team outcome writers: the project's fork
trigger, upkeep of a project's own tree, and the vault head's leaf-promotion
reserve.

Every lookup still uses the exact skill head and leader pack receipt selected by
that writer after its existing checks. Upkeep uses the project's incumbent head;
leaf promotion uses the current vault head, including a new head selected after a
successful merge. A request for an earlier head is never transferred to a later
one. Missing keys remain unknown, and extra keys do not create outcomes. Stored
rows retain their original physical placement, including unknown.

The caller supplies all placement axes explicitly. Team membership, project,
receipt, executor, funding and current read scope do not supply placement. The
existing held-out reservation, fork scoring, upkeep settlement, promotion order,
refusal counts and ordinary nightly behavior are unchanged. The same advisory
queue dedupe rules apply as for the other request-bearing Coach jobs.

This request does not grant source access, declare a complete input read set,
enable FACT or authorize model release.

## Callable defects and actual invokers

`DreamerRunnerStore::enqueue_coach_skill_discovery_with_requests` accepts
`dreamer_runner::maintenance::coach::SkillDiscoveryOutputReadRequests`. Its
`attribution` field keeps the two independent judgment/proposal maps above.
Its separate `callable_outcomes` map addresses an output by the exact pair of
persisted judgment sequence and actual invoker executor. One judgment can charge
several executors. A request for one invoker never supplies another's placement.
The ordinary `enqueue_coach_skill_discovery` method still accepts attribution
requests and queues an empty callable map. There is one current job-input format,
not an old-format reader.

After the original Coach-attempt check, the durable input reaches the original
task sweep. That sweep resumes callable defects from its persisted judgment
range before advancing its applied cursor. The callable projector rechecks the
exact stored judgment, its undisplaced state, current callable skill revision,
terminal receipt manifest and actual invocation witnesses in the same writer as
the outcome. As with the ordinary reliability projector, only the judgment's
first evidence receipt supplies its one outcome per invoker; additional citations
do not multiply losses. A pack load without an invocation supplies no executor.
A routed defect charges every executor that ran the callable, not only those
whose invocation passed its return contract. The existing callable win path is
unchanged.

Only the explicit entry for that sequence and invoker supplies placement at a
new physical outcome's birth. Missing requests remain unknown. Extra requests
create no row. Replays do not restamp held outcomes, and changed contents retain
the ordinary placement-clearing behavior. The judgment's own position, receipt,
funding, read grants and advertised executor supply no output placement. No entry
grants source access, declares a complete read set, enables FACT or authorizes
model release.

Displacing a defect's judge also marks every stored native executor arm for that
exact skill and first receipt. The receipt's advertised model is not assumed to
be a callable's invoker, and a later skill revision does not hide retained arms.
These arms re-project after the same displacement commit, including on retries.
The existing receipt-model marker request remains on its original arm only.
Additional arms have unknown marker placement; one judgment request is never
broadcast to several physical markers. Native marker birth and no-restamp rules
remain unchanged.
