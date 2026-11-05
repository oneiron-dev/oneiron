//! The identity marker carried after receipt attribution is erased.

/// What an erased actor's call receipts state in place of who called: the
/// actor, its class and the credential it presented (FIX 812). Engine call
/// 10-18, behind this one constant.
pub const ERASED_CALL_IDENTITY: &str = "erased";

// Invalid UTF-8 and a non-container MessagePack first byte prevent opaque
// carriers from falling through a text serializer. Whole export uses the
// credential-safe source facet, never these bytes as another escape channel.
pub const MAGIC: &[u8] = b"\xf5oneiron.receipt-archive.v1\0";

pub fn is_receipt_archive_source(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}
