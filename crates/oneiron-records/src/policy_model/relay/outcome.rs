//! Moved from `crates/oneiron/src/policy_model/relay/outcome.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;
use std::collections::HashMap;

/// What a hosted pass examined: the policy's version AND hash, the pair an
/// attestation is matched on, and the request's identity-free verification
/// content hash, the one a CloudVault carrier is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct HostedPassEvidence {
    pub version: String,
    pub policy_hash: String,
    pub verify_content_hash: [u8; 32],
}
