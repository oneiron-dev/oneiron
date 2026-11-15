//! The side tables `task_authority` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Presence marker: an authority fact of this task was refused at admission because its id
    /// was deleted here first, so the task's facts read as a refusal. Key: id16 (task).
    TASK_FACT_SUPPRESSED: VaultMeta b"tasks.fact_suppressed.v1/" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// An authority fact this install's own door wrote: the content hash of the exact body it
    /// wrote (32 bytes). Local truth that never replicates, so no peer can make its own row read
    /// as one this install wrote; another machine's fact proves itself by its carrier's
    /// signature (pass 28 R5). No image keeps it; a restore carries it from the live vault.
    /// Key: hex32 (fact).
    TASK_FACT_WRITTEN_HERE: SyncState b"tasks.fact_written_here.v1/" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
}
