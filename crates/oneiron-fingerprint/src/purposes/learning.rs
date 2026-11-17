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
}
