//! Moved from `crates/oneiron/src/snapshot_read/source_version.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::claim_history_handoff::ScopedRead;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_TURN;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::consolidation_evidence::swarm_evidence_content_hash;
use serde::Deserialize;
use serde::Serialize;

/// What a recheck of a [`SourceVersion`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceVersionCheck {
    /// The row still reads for the caller, at the same revision.
    Current,
    /// The row still reads for the caller, at another revision.
    Moved,
    /// The caller no longer reads the row, or it is gone. Nothing more is
    /// said, as a scoped read says nothing of a withheld row.
    Withheld,
}

/// `blake3:<hex>` for a 32-byte BLAKE3 digest.
pub fn blake3_ref(digest: &[u8; 32]) -> String {
    format!("blake3:{}", blake3::Hash::from(*digest).to_hex())
}
