//! Purposes of the managed restore contract (`oneiron-vault-contract` `restore`).
//!
//! A verified cold restore names its receipt by an id: the `verified` frame on the result
//! pipe and every `restore_status` page carry it to the supervising host, which reads it
//! and checks its shape (64 lowercase hex). So it keeps its bytes (K, PLAN-UC-04 6.3).

purposes! {}

legacy_purposes! {
    /// A verified restore's receipt id (`restore::framing::receipt_id`). BLAKE3 of the
    /// receipt's exact JSON bytes, with no tag and no length; written as 64 lowercase hex
    /// digits.
    RECEIPT_ID = (Blake3, NotHashed, "oneiron.restore.receipt_id.v1");
}
