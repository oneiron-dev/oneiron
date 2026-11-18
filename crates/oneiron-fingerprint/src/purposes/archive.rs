//! Purposes of the whole-vault archive (`oneiron` `batch::export`).
//!
//! An archive carries each retained side-table row under a key made from the row's source
//! table, source key and source value. A vault stores its retained rows under that key and
//! deduplicates on it; reading a stored row back and importing an archive both recompute it
//! and refuse a row filed under another. So it keeps its bytes (K).

purposes! {}

legacy_purposes! {
    /// A retained side row's physical key
    /// (`archive_retained_side_rows::retained_side_row_key`). BLAKE3: the tag with no length
    /// before it; then the source table's name, the source key and the 32-byte content hash of
    /// the source value, each as a u64-LE length and its bytes.
    RETAINED_SIDE_ROW_KEY = (Blake3, HashedFirst, "oneiron.archive.retained_side_row.v1");
}
