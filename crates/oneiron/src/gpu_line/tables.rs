//! The side tables `gpu_line` keeps: each row declares one, and the crate's build script places it
//! in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One kept write of a lane-economy door under its asker's intent key (design pass 32
    /// section 5): the asker, the verb, the ask's digest and the key of the row the write made,
    /// never the answer. Key: blake3 (32) of the framed asker, verb and intent key.
    LANE_ECONOMY_INTENT: VaultMeta b"lane_economy_intent:v1:" Named
        // Restore class: An intent is live: a restore never lets a key replay a write the
        // restored rows no longer hold.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::gpu_line::erase_intent_asker_in_txn;
}
