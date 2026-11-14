//! Moved from `crates/oneiron/src/runtime_hooks/verb/plain_resume.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// Context of one Grant row's revision digest.
pub const PLAIN_GRANT_REVISION: &str = "oneiron verb hook plain grant revision v1";

/// Context of the ceiling digest a delegated call is asked under.
pub const PLAIN_CEILING: &str = "oneiron verb hook plain ceiling v1";

/// One Grant row's revision: a digest of its type, id and stored body.
pub fn revision(kind: u8, id: &EntityId, body: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PLAIN_GRANT_REVISION);
    hasher.update(&[kind]);
    hasher.update(id.as_bytes());
    hasher.update(body);
    *hasher.finalize().as_bytes()
}
