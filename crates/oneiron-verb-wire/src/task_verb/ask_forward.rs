//! Moved from `crates/oneiron/src/task_verb/ask_forward.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A holder signature's bytes: exactly 128 lowercase hex characters.
pub fn holder_signature_bytes(signature: &str) -> Option<[u8; 64]> {
    let text = signature.as_bytes();
    if text.len() != 128 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut bytes = [0_u8; 64];
    for (byte, pair) in bytes.iter_mut().zip(text.chunks_exact(2)) {
        let [high, low] = pair else {
            return None;
        };
        *byte = (digit(*high)? << 4) | digit(*low)?;
    }
    Some(bytes)
}
