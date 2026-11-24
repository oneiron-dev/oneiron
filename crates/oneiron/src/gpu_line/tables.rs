//! The side tables `gpu_line` keeps: each row declares one, and the crate's build script places it
//! in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The owner's policy for one lane's GPU time (design pass 32, section 3.1): its wallet,
    /// periods, pinned share, floors, rung caps, allowance rules and seated families. Key: id16
    /// (lane project).
    GPU_LINE: VaultMeta b"gpu_line:v1:" Named
        // Restore class: An owner's setting is live: a restore never widens a line the owner
        // narrowed or seats a family again.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::gpu_line::erase_line_actor_in_txn;
    /// The mint's record of one period of one GPU line, written once at the period's first
    /// write (design pass 32, section 3.2): its buckets and each rule's market ceilings. Key:
    /// id16 (lane project) + u32be (period index).
    GPU_LINE_PERIOD: VaultMeta b"gpu_line_period:v1:" Named
        // Restore class: A period's record is what units drew against: a restore never mints
        // it again from other inputs.
        [restore: live] [family: unclassified] [tier: canonical];
}
