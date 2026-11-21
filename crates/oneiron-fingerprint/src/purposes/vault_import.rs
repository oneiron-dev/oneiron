//! Purposes of a staged foreign vault import (`oneiron-store`
//! `batch::export::foreign_stage`, sync builds).
//!
//! A staged import is named by its receipt id. The stage keeps its receipt and content rows
//! under it and returns the stored receipt when the same id comes again; encoding a receipt
//! and the engine's decode both recompute it and refuse a row whose id differs; and the
//! peer's confirmation carries it back, so a confirmation under another id is refused. So
//! it keeps its bytes (K, PLAN-UC-04 6.3).

purposes! {}

legacy_purposes! {
    /// A staged foreign vault import's receipt id
    /// (`export_foreign_receipt::receipt_id`). BLAKE3: the tag, NUL-terminated and with no
    /// length before it; the manifest digest's 32 bytes; the source (`1` and the peer's 16
    /// id bytes, or `2` and the platform's UTF-8 with no length); the window's UTF-8 with
    /// no length; the remote update digest's 32 bytes.
    RECEIPT_ID = (Blake3, HashedFirst, "oneiron/vault-import-receipt/v1\0");
}
