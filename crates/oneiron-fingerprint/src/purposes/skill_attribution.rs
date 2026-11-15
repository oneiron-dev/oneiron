//! Purposes of skill attribution (`crates/oneiron/src/skill_attribution`).

purposes! {}

legacy_purposes! {
    /// A late-credit receipt's key (`skill_attribution::late_credit::receipt_id`). BLAKE3
    /// derive-key with the tag as its context; the attempt receipt, the outcome receipt and
    /// the axis, each a u64 big-endian length and its bytes. `credit:` and the lowercase hex
    /// is the stored late-credit receipt's key.
    LATE_CREDIT_RECEIPT = (Blake3, DeriveKeyContext, "oneiron pack outcome credit v1");
}
