//! Moved from `crates/oneiron/src/sync/transport.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::sync::transport::codec::TagBytesRow;
use loro::LoroValue;
pub use oneiron_store::window_protocol::MAX_DECODED_PAYLOAD_BYTES;
use serde::Deserialize;
use serde::Serialize;

/// Decoded Loro `EphemeralStore` wire record.
///
/// This mirrors the postcard-encoded shape used by Loro 1.10.x. It is shared
/// so callers can validate untrusted ephemeral bytes before applying them to a
/// store while still relaying the native bytes on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EphemeralWireState {
    pub key: String,
    pub value: Option<LoroValue>,
    pub timestamp: i64,
}
pub mod codec;
