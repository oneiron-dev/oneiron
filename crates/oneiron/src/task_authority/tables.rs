//! The side tables `task_authority` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Presence marker: an authority fact of this task was refused at admission because its id
    /// was deleted here first, so the task's facts read as a refusal. Key: id16 (task).
    TASK_FACT_SUPPRESSED: VaultMeta b"tasks.fact_suppressed.v1/" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
