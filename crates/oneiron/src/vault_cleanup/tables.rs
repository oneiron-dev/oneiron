//! The side tables `vault_cleanup` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Explicit archived-attempt deletion: actual actor, time and optional originating run tag.
    /// Key: id16 (AttemptId), not an entity id; contains no attempt payload.
    VAULT_CLEANUP_ATTEMPT_DELETE: VaultMeta b"vault_cleanup.attempt_delete.v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::vault_cleanup::erase_attempt_delete_actor_in_txn;
    /// One recorded vault-cleanup decision (accepted/auto), listing archived and skipped candidates.
    /// Key: id16.
    VAULT_CLEANUP_DIGEST: VaultMeta b"vault_cleanup.digest.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Which cleanup proposal, digest and run rows name an id, so an erase reads only those
    /// (FIX 7616). Key: the named id16, the listing's tag byte (`p`, `d` or `r`), then the
    /// listing row's id16. Value: empty.
    VAULT_CLEANUP_ENTITY_ROW: VaultMeta b"vault_cleanup.entity_row.v1:" Raw
        // Payload family: Id-only membership indexes, restored with the rows they index.
        [restore: content] [family: structure] [tier: canonical];
    /// Mint-time evidence pinning a PERSON as extraction-produced and eligible for the claimless-
    /// person cleanup arm. Key: id16 (PERSON id).
    VAULT_CLEANUP_EXTRACTION_PERSON: VaultMeta b"vault_cleanup.extraction_person.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owner-set cleanup posture: auto-with-digest when absent, or propose-first. Key: ().
    VAULT_CLEANUP_POSTURE: VaultMeta b"vault_cleanup.posture.v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Open vault-cleanup archive proposal awaiting owner accept/reject. Key: id16.
    VAULT_CLEANUP_PROPOSAL: VaultMeta b"vault_cleanup.proposal.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable cleanup-scan result for one attempt, closing the job-commit-to-queue-settlement crash
    /// gap. Key: id16 (AttemptId).
    VAULT_CLEANUP_RUN: VaultMeta b"vault_cleanup.run.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Index of archived attempts under one TASK, used to restore them together when the task is
    /// touched. Key: BLAKE3 derive_key of the task reference (32) then id16 (AttemptId).
    VAULT_CLEANUP_TASK_ATTEMPT_ARCHIVE: VaultMeta b"vault_cleanup.task_attempt_archive.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owner-adjustable retention period for completed TASK queue records before archival
    /// eligibility. Key: ().
    VAULT_CLEANUP_TASK_RETENTION_DAYS: VaultMeta b"vault_cleanup.task_retention_days.v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
