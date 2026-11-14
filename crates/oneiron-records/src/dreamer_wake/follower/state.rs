//! Moved from `crates/oneiron/src/dreamer_wake/follower/state.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// A session's identity: the Dreamer authority and the read scope it reads
/// under, hashed.
pub type SessionKey = [u8; 32];

/// A result row's key: the attempt that wrote it and the session's sequence.
pub type ResultKey = (AttemptId, u64);

/// What a backend may say of its cache's hold on a prefix. Nothing at this
/// head attests residency, so every record reads Unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheResidency {
    Unknown,
}
