# Decision question-pack advisories

`DecisionBandPolicy::questions_per_call()` controls how a logical pack is grouped
into provider reads. A larger pack is served as several requests under the same
clock. It is not truncated, held or refused for its question count.

Vault-holding producers call `Vault::measure_decision_pack(&policy, count)` once
for the logical primary-question pack before invoking the ladder. The helper uses
that same policy's current value as the bound and reports a crossing through the
vault's installed `LimitAsk` port. With no port installed, no question is queued.
The server's existing port records a `WireLimitQuestion` for its health-check path.
It does not await an answer before serving the pack.

The advisory identity is `EngineLimit::DecisionQuestionsPerCall`, with catalog key
`limits.decision_questions_per_call`. Its per-work bound is supplied from the
actual decision policy, not substituted from the catalog default. It is not a
second batch-size governor. The policy's existing setter still controls grouping;
its nonzero validation is unchanged.

The existing default remains 16. Its single definition is now
`oneiron_contracts::limit_ask::DEFAULT_DECISION_QUESTIONS_PER_CALL`; the policy's
`DEFAULT_QUESTIONS_PER_CALL` path re-exports that same value.

The connected producer families are:

- Description-routing fitness: the actual filtered candidate rows, once per pack.
- Owner and hosted policy classification: the actual prepared rubric questions,
  once inside the classifier shared by its three vault entrypoints.
- Scoped consolidation decisions: the actual generated-read pack, its existing
  step vault and the same band policy.

The vault-free ladder and raw generated provider remain vault-free. They do not
invent a vault, principal, owner stamp or callback. Other producer families,
including attribution amendments, critic review and campaign taste, still need
their own exact vault-bound observation wiring. Their completion is not implied
by this helper.

Only the prepared primary-question count is measured. Provider chunks, retries,
paired/person questions and token counts do not become extra logical packs. Model
selection, authority, funding, receipts and deadline behavior are unchanged.
