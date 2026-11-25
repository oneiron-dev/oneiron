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

// HASH-ROUTE-GPU-LINE-STORED = A (Engine, 25 Nov 14:56) keeps these bytes.
// Stack #10416 stored them after this crate existed, an exception to the `legacy.rs`
// rule for bytes main wrote before this crate. PLAN-UC-04 stage 9 moves them to v1 at launch reset.
legacy_purposes! {
    /// The key of every `LANE_ECONOMY_INTENT` row (`gpu_line/intent.rs`, `intent_row_key`).
    /// Writes the asker's ID bytes, the verb's length as a u64 big-endian and its bytes,
    /// then the intent key's length as a u64 big-endian and its bytes.
    INTENT_KEY = (Blake3, DeriveKeyContext, "oneiron lane economy intent key v1");

    /// The ask digest in every intent row (`gpu_line/intent.rs`, `IntentAsk::new`), stored
    /// in lower hex. Writes the ask's canonical JSON with no length before it.
    /// `oneiron_records::receipt::call::write_canonical` sorts object keys at every depth.
    INTENT_ASK = (Blake3, DeriveKeyContext, "oneiron lane economy intent ask v2");

    /// The economic digest in every period record (`gpu_line/mint/period.rs`,
    /// `economic_digest`), stored in lower hex. Writes the tag's bytes, including its final
    /// newline, then `serde_json::to_vec` of `EconomicFields` in that struct's field order.
    /// There is no length before the JSON.
    PERIOD_ECONOMIC = (Sha256, HashedFirst, "oneiron.gpu_line.period.economic:v1\n");
}
