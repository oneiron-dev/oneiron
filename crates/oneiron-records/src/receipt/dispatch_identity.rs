//! Moved from `crates/oneiron/src/receipt/dispatch_identity.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// FIX 6424 (Engine 10-20 20:4x): the receipt field a held send's
/// approve-once digest rides, beside its gate outcome.
pub const APPROVAL_DIGEST_FIELD: &str = "approval_digest";
