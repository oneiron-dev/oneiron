//! The side tables `training_pack` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The trained question head the owner bound to one typed question version (FIX 3864):
    /// its run, checkpoint, temperature, checks and paired trial. Key: question id hex, `@`,
    /// version.
    TRAINING_PACK_QUESTION_HEAD: VaultMeta b"training_pack:question_head:v1:" Named
        // Restore class: A restore never replays a GPU dispatch or rolls back an owner's model
        // swap.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::training_pack::erase_question_head_in_txn;
    /// A question run's paired held-out trial against a typed question's current answerer
    /// (FIX 3864): its counted serving, then quality, cost and latency of both. Key: id16
    /// (run).
    TRAINING_PACK_QUESTION_TRIAL: VaultMeta b"training_pack:question_trial:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::training_pack::erase_question_trial_in_txn;
    /// Current owner-approved training checkpoint per model role. Key: serialized role string.
    TRAINING_PACK_ROLE: VaultMeta b"training_pack:role:v1:" Named
        // Restore class: A restore never replays a GPU dispatch or rolls back an owner's model
        // swap.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::training_pack::erase_role_actor_in_txn;
    /// Pinned corpus, compute, dispatch and evaluation of one training job. Key: id16 (run).
    TRAINING_PACK_RUN: VaultMeta b"training_pack:run:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::training_pack::erase_run_id_in_txn;
    /// Immutable owner-approved role-swap receipt. Key: id16 (receipt).
    TRAINING_PACK_SWAP: VaultMeta b"training_pack:swap:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::training_pack::erase_swap_actor_in_txn;
}
