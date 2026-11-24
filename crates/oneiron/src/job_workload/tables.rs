//! The side table `job_workload` keeps: its row declares it, and the crate's build script places
//! it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One pinned workload (pass 33, 5.1): the exact pin, who pinned it, and the owner's
    /// approval or revoke. Key: the pin's sha256 digest (32 bytes).
    JOB_WORKLOAD: VaultMeta b"job_workload:v1:" Named
        // Restore class: An owner's approval and revoke are live: a restore never approves
        // again a workload the owner revoked, or widens an approval the owner narrowed.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::job_workload::erase_workload_actor_in_txn;
}
