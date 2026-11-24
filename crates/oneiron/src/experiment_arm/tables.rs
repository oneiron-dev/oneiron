//! The side table `experiment_arm` keeps: each row declares one, and the crate's build script
//! places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One experiment arm of the lane economy (design pass 32 section 3.3): its line, family,
    /// track, frozen contract, runner, first-allowance hold and rungs. Key: id16 (arm).
    EXPERIMENT_ARM: VaultMeta b"experiment_arm:v1:" Named
        // Restore class: An arm's hold and rungs are live: a restore never gives an arm back the
        // room its hold took or reopens a rung its verdict closed.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::experiment_arm::erase_arm_actor_in_txn;
}
