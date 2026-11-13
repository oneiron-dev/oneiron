//! Moved from `crates/oneiron/src/memory/result_attachment.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// The metadata key a MESSAGE's result attachment sits under. Only the
/// executor door writes it.
pub const MESSAGE_RESULT_METADATA_KEY: &str = "result";

/// Where a MESSAGE's result came from: the run that produced its body, that
/// run's occurrence of it, and its path in the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageResultSource {
    pub run_id: EntityId,
    /// The producer's occurrence: where the body's authority and taint came
    /// from. Never the MESSAGE's own hold on it.
    pub occurrence: EntityId,
    pub path: String,
}

/// The digest a body's handle names.
pub fn handle_digest(handle: &str) -> Option<[u8; 32]> {
    let hex = handle.strip_prefix("code-run-output:blake3:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut digest = [0; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}
