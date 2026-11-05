# Per-agent model lists on reader calls

An agent's `models` list names engine model ids, not provider wire names.
A reader, summary or scoped child inherits the frozen list of the run that
spawned it. An empty list keeps the existing house-routed behavior.
`compaction_model` is separate and need not appear in that list.

With the served code-mode backend, the inherited list now follows the
reader's own metered backend. The backend checks the model selected by role
admission, not only the configured model checked before that admission. An
off-list selected model follows the existing admission-denied path; the
server log records the list check's reason.

A permitted call keeps every listed rung and every eligible owner fallback
that is also listed. Filtering is call-local: it does not change shared
routes, cooldowns, meters or owner fallback settings. Rung order and the
original receipt positions are retained. An off-list fallback cannot be
sent; another eligible listed fallback can still answer. No exact-model-only
shortcut replaces the normal walk.

This is the served reader-backend slice. Ordinary resident and planned-run
backends that do not yet carry their agent's list retain their existing
routing. Injected or custom providers are not covered by a claim that they
cannot substitute models. The live compaction admission remains separate;
this reader-call check does not constrain its explicitly independent model.
