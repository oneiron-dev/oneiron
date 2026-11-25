//! The side table the unit claims keep: each row declares one, and the crate's build script places
//! it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One unit claim of the lane economy (design pass 32 section 3.4): the line's ledger entry
    /// for one logical attempt of one unit, and the durable record of its wallet hold. Key: id16
    /// (arm) + u8 (rung) + the unit key's 16-byte fingerprint (purpose `gpu_line::UNIT_KEY`) +
    /// u16be (attempt).
    EXPERIMENT_ARM_UNIT: VaultMeta b"experiment_arm_unit:v1:" Named
        // Restore class: A claim is live: a restore never gives back the room a claim held or
        // reopens a claim that ended; the line reconciles its claims with the machines first.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::gpu_line::claim::erase_claim_actor_in_txn;
    /// One machine's newest answer for one GPU allocation generation (row M2-I2, Engine
    /// EM-15): the vault writer acquisition it came in and the occupied seconds of the jobs it
    /// ran against that generation that no row of this vault names. Key: u64be (generation) +
    /// id16 (machine) + the allocation id.
    GPU_ALLOCATION_NODE: VaultMeta b"gpu_allocation_node:v1:" Named
        // Restore class: An answer is live: a restore never forgets the seconds a machine ran
        // that the restored rows lack. An answer from an earlier start never admits; the line
        // asks every machine again after each start.
        [restore: live] [family: unclassified] [tier: canonical];
}
