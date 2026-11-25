//! The side tables `machine_records` keeps: each row declares one, and the crate's build script
//! places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A key a vault machine holds that this issuer never dispatched or no longer knows (pass 33,
    /// 5.1 and 8.5): found by the reconcile before the first dispatch to that machine, stopped
    /// while it lives, and kept with its terminal receipt and its unattributed seconds. Key:
    /// `<machine hex>#<node key>` (UTF-8).
    JOB_ORPHAN: VaultMeta b"job_orphan:v1:" Named
        // Restore class: An orphan is live: a restore never forgets a key a machine still runs
        // for nobody, or seconds that already shrank a generation's room.
        [restore: live] [family: unclassified] [tier: canonical];
    /// The issuer's half of the drain guard for one vault machine (pass 33, 5.1 and 7.9): the
    /// machine's own failures in a row as the issuer observed them, and the drain that stops
    /// every dispatch there until door 12 clears it. Key: the machine's id, lower hex (UTF-8).
    MACHINE_JOB_GUARD: VaultMeta b"machine_job_guard:v1:" Named
        // Restore class: A guard is live: a restore never reopens a machine the live vault
        // drained.
        [restore: live] [family: unclassified] [tier: canonical];
}
