//! The side table `gpu_job` keeps: each row declares one, and the crate's build script places it
//! in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One customer GPU job (CROSS-ARCH-0023 lifecycle): its offer, quote, maximum, chunks and
    /// state, so a restarted host takes up the same job. Key: id16 (job).
    GPU_JOB: VaultMeta b"gpu_job:v1:" Named
        // Restore class: A job's state and its reservations are live: a restore never starts a
        // stopped job again or forgets one that runs at its provider.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::gpu_job::erase_job_starter_in_txn;
    /// The per-job maximum the owner set beside one agent Grant for starting GPU jobs (RULING
    /// L10-31-STARTER = B): the Grant, its agent, the maximum and who set it when. Key: id16
    /// (Grant).
    GPU_JOB_ALLOWANCE: VaultMeta b"gpu_job_allow:v1:" Named
        // Restore class: An owner's setting is live: a restore never widens what an agent may
        // start again after the owner narrowed or removed it.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::gpu_job::erase_allowance_actor_in_txn;
}
