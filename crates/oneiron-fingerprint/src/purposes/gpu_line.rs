//! Purposes of the lane economy's GPU lines (`crates/oneiron/src/gpu_line`).

purposes! {
    /// The unit key's digest in a unit claim's row key (`gpu_line/claim`, `ClaimKey::of`):
    /// the first 16 bytes of the fingerprint of one part, the unit key's UTF-8 bytes. The
    /// claim table's key is id16 (arm) + u8 (rung) + this digest + u16be (attempt), so one
    /// logical attempt has one row whatever the unit key's length.
    UNIT_KEY = "oneiron.gpu_line.unit_key.v1";
}

legacy_purposes! {}
