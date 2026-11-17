//! Purposes of the learning loop (`crates/oneiron/src/edit_distance`, `skill_attribution`).

purposes! {
    /// A cause's source, one per receipt and judge-revision slot
    /// (`edit_distance::attribution::causes`). Parts: receipt, slot.
    AMENDMENT_CAUSE = "oneiron:amendment-cause:v1";

    /// An issue signature, spelled from its own stored bytes so the same signature lands on
    /// the same row (`edit_distance::publisher::signature_store`). Parts: the encoded
    /// signature.
    ISSUE_SIGNATURE = "oneiron:issue-signature:v1";

    /// A cause's source, one per terminal receipt and evidence sequence
    /// (`skill_attribution::causes`). Parts: receipt, sequence (big-endian).
    SKILL_ATTRIBUTION_CAUSE = "oneiron:skill-attribution-cause:v1";
}

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
