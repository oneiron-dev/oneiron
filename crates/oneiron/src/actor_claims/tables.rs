//! The side tables `actor_claims` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Durable SessionEnd distill job for one ended sitting, queued in the same transaction that
    /// closes it and cleared once distilled. Key: id16.
    ACTOR_CLAIMS_DISTILL_PENDING_JOB: VaultMeta b"actor_claims:distill_pending:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Rotation cursor (last session id served) for the bounded session-end distill drain pump, so
    /// one budget-limited pass cannot starve later jobs. Key: ().
    ACTOR_CLAIMS_DISTILL_RUNNER_CURSOR: VaultMeta b"actor_claims:distill_runner_cursor:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
}
