//! Door for `tests/fingerprint_keep_import_digests.rs` (PLAN-UC-04 stage 6.2b): a claim
//! import batch's and a note import batch's content hash, a history message's hash, and a
//! blob version's content hash, which the engine computes in private code.

/// The content hash of a claim import batch.
///
/// # Errors
/// When the batch does not encode.
pub fn claim_import_content_hash(
    batch: &crate::ingest::ImportedClaimBatch,
) -> crate::Result<[u8; 32]> {
    crate::ingest::claim_import_content_hash_for_test(batch)
}

/// The content hash of a note import batch.
///
/// # Errors
/// When the batch does not encode.
pub fn note_import_content_hash(batch: &crate::note::ImportedNoteBatch) -> crate::Result<[u8; 32]> {
    crate::note::note_import_content_hash_for_test(batch)
}

/// A history message's hashes, as the ingest ledger stores them, as each speaker said it: by
/// role, as a Slack member, unknown.
#[must_use]
pub fn history_message_hashes(message: &crate::ingest::history::HistoryMessage) -> [String; 3] {
    crate::ingest::history::history_message_hashes_for_test(message)
}

/// The content hash of a blob version whose body is held in memory.
#[must_use]
pub fn blob_version_content_hash(bytes: &[u8]) -> [u8; 32] {
    crate::blob_artifact::version_content_hash_for_test(bytes)
}
