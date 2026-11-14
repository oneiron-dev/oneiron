//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/compaction_check/conversation.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;

/// The payload key a conversation's declaration rides under.
pub const CONVERSATION_DECLARATION_KEY: &str = "conversation_declaration";

/// A 64-character lowercase hex digest's bytes.
pub fn hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
