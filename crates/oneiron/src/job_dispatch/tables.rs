//! The side tables `job_dispatch` keeps: each row declares one, and the crate's build script
//! places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// What the issuer sent a vault machine for one GPU job chunk (pass 33, 5.1): the exact
    /// signed submit, its window, the phase and the node's `Held` receipt. Written before the
    /// first network call. Key: the chunk's idempotency key (UTF-8).
    JOB_DISPATCH: VaultMeta b"job_dispatch:v1:" Named
        // Restore class: A dispatch is live: a restore never forgets a submit a machine may hold,
        // or sends one again that the live vault closed.
        [restore: live] [family: unclassified] [tier: canonical];
    /// The newest forward receipt the issuer holds for one dispatched key (pass 33, 5.1), when it
    /// arrived, when the terminal one arrived on the issuer's boot clock, and the meter verdict.
    /// Key: the chunk's idempotency key (UTF-8).
    JOB_OBSERVATION: VaultMeta b"job_observation:v1:" Named
        // Restore class: An observation is live: a restore never takes back a receipt the live
        // vault holds, so the sequence of a key never goes back on the issuer.
        [restore: live] [family: unclassified] [tier: canonical];
}
