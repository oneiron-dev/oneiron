//! Purposes of the lane economy's GPU lines (`crates/oneiron/src/gpu_line`).

purposes! {
    /// The unit key's digest in a unit claim's row key (`gpu_line/claim`, `ClaimKey::of`):
    /// the first 16 bytes of the fingerprint of one part, the unit key's UTF-8 bytes. The
    /// claim table's key is id16 (arm) + u8 (rung) + this digest + u16be (attempt), so one
    /// logical attempt has one row whatever the unit key's length.
    UNIT_KEY = "oneiron.gpu_line.unit_key.v1";
    /// The arrangement of one block of a two-rule period's comparison
    /// (`gpu_line/cohort.rs`, `cohort_rule`). Parts: the period's 32-byte cohort seed,
    /// the track's name (`demand` or `interest`) and the block number as u32
    /// little-endian. The first 8 bytes, as a little-endian u64, modulo 6 pick one of
    /// the six arrangements of two arms of each rule. Never stored: the arms store the
    /// cohort it gave them.
    COHORT_BLOCK = "oneiron.gpu_line.cohort_block.v1";
}

legacy_purposes! {}
