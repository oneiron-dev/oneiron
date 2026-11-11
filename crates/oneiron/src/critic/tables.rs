//! The side tables `critic` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Stored-review keys already reported unreadable (FIX 5251): each
    /// unreadable review is named once. Presence-only, empty value. Key: bytes.
    CRITIC_UNREADABLE_REPORTED: SyncState b"critic:unreadable_reported:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Private run-tree-scoped critique artifact for one branch attempt, keyed by attempt id and
    /// artifact id; written independently by both the generic critic reviewer and the Dreamer
    /// tournament with the identical prefix and key layout (see WHERE) - worth a second look for
    /// accidental collision if the same (attempt, artifact_id) pair is ever used from both callers.
    /// Key: id16 + u16be + string.
    CRITIC_ARTIFACT: VaultMeta b"dreamer:critic:v1:" Named Authored [accepts: crate::critic::critique_artifact_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::learning::erase_review_scope_in_txn;
    /// Blake3 stamp of a written claim body, used to detect a review verdict claim edited outside its
    /// producer. Key: id16.
    CRITIC_REVIEW_CLAIM_TRUST: VaultMeta b"review:claim:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Cached review verdict/triage/artifacts for a review request, keyed by a hash of the request's
    /// identity tuple. Key: hash32.
    CRITIC_REVIEW_RESULT: VaultMeta b"review:result:v2:" Named Authored [accepts: crate::critic::review::critic_review_result_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::learning::erase_review_scope_in_txn;
}
