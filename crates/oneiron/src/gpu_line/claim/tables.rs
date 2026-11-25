//! The side table the unit claims keep: each row declares one, and the crate's build script places
//! it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One unit claim of the lane economy (design pass 32 section 3.4): the line's ledger entry
    /// for one logical attempt of one unit, and the durable record of its wallet hold. Key: id16
    /// (arm) + u8 (rung) + 16-byte BLAKE3 digest of the unit key + u16be (attempt).
    EXPERIMENT_ARM_UNIT: VaultMeta b"experiment_arm_unit:v1:" Named
        // Restore class: A claim is live: a restore never gives back the room a claim held or
        // reopens a claim that ended; the line reconciles its claims with the machines first.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::gpu_line::claim::erase_claim_actor_in_txn;
}
