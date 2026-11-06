# Case-backed Coach prompt drafts

An embedded host may implement `CoachHealAuthor::draft_prompt`. The method
receives the engine's recorded `HealerCase` and the failure's untrusted cause
context. It returns `Some(CoachPromptDraft { prompt, rationale })` to propose
exact prompt bytes, or `None` to leave the heal route-only. The host supplies
its own configured author; the built-in server author does not opt in.

Only a case's `prompt_inject` route calls this method. Other routes, skill
repair and blocked-report Issues keep their existing behavior. An author error,
a decline or an empty prompt leaves the heal route-only with a reason. Prompt
bytes are not trimmed or rewritten. No new text cap or policy setting is added.

The heal's writer revalidates the exact durable case and its Failed attempt,
TASK binding and dispatched agent through the existing case check. A case
that moved while the author worked leaves the heal route-only. Storage errors
still abort the writer.

A usable draft lands a Generated, Proposed CLAIM with predicate
`coach.prompt_repair`. Its value contains `case`, `failing_attempt`, `agent`,
`checkpoint`, `diagnosis`, `prompt` and `rationale`. It uses the heal's existing
Coach run-tray envelope and evidence. The heal's `repair.route` is a
`PromptInjectAndForkResume` whose `prompt_ref` names that artifact and whose
other references come from the recorded case. Both claims and the existing
oversight and settlement writes commit together, or none do. Replaying an
already settled heal creates no artifact.

This artifact is reviewable data, not permission to inject a prompt or resume
a run. It does not create a MESSAGE or a new Q&A entry. Its checkpoint is the
case's recorded reference, not proof that a continuation can execute now.
The existing continuation/apply doors retain their own owner approval and
checkpoint checks. There is no automatic bridge to an agent-health card ask.
Default served authors, environment/person artifact producers and a case-to-
continuation application remain separate work.
