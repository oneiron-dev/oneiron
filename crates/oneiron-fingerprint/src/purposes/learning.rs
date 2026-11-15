//! Purposes of the learning loop (`crates/oneiron/src/edit_distance`, `skill_attribution`).

purposes! {}

legacy_purposes! {
    /// The key a skill attribution receipt's causes are kept under
    /// (`skill_attribution::causes::receipt_key`): plain BLAKE3 of the receipt's bytes, with
    /// no tag.
    SKILL_CAUSE_RECEIPT_KEY = (Blake3, NotHashed, "oneiron.learning.skill_cause_receipt_key.v1");

    /// The key an amendment receipt's causes are kept under
    /// (`edit_distance::attribution::causes::receipt_key`): plain BLAKE3 of the receipt's
    /// bytes, with no tag. Today the same bytes as [`SKILL_CAUSE_RECEIPT_KEY`] for one string.
    AMENDMENT_CAUSE_RECEIPT_KEY =
        (Blake3, NotHashed, "oneiron.learning.amendment_cause_receipt_key.v1");

    /// The 16-byte key a graduation threshold row is kept under
    /// (`edit_distance::graduation::threshold_policy::pattern_key`): plain BLAKE3, the tag's
    /// bytes, then the scope pattern's bytes; the key is the digest's first 16 bytes.
    GRADUATION_PATTERN_KEY = (Blake3, HashedFirst, "oneiron.edit_distance.graduation.pattern.v1");
}
