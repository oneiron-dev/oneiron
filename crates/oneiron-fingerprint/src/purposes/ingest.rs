//! Purposes of imports into the vault: claims from a registered source, and chat history.
//!
//! A claim import batch's content hash is bound into the owner's approval of the batch and
//! into the batch's one decision slot, which the vault stores and compares; a history
//! message's hash is stored in the ingest ledger, and a re-import compares it to skip what
//! landed. So each keeps its bytes (K, PLAN-UC-04 6.2). Neither writes a tag: the names
//! below are registry names only.

purposes! {}

legacy_purposes! {
    /// A claim import batch's content hash (`ingest::bulk_review::content_hash`). BLAKE3 of
    /// the JSON array of each entry's claim id (hex), subject (hex), source record id,
    /// predicate, value, occurred start and end, and learned-at, in batch order.
    CLAIM_IMPORT_CONTENT = (Blake3, NotHashed, "oneiron.ingest.claim_import_content.v1");

    /// A history message's hash (`ingest::history::ledger::hash`), stored in
    /// `LedgerRow.hashes`. BLAKE3: `unknown\0` when the source left the speaker unknown,
    /// then `user\0` or `asst\0`, then the words, with no lengths; written as lowercase hex.
    HISTORY_MESSAGE = (Blake3, NotHashed, "oneiron.ingest.history_message.v1");
}
