//! Moved from `crates/oneiron/src/snapshot_read/strength_observations.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::claim_history_handoff::ClaimReadStatus;
use oneiron_authority::claim_history_handoff::ScopedRead;
use oneiron_authority::claim_history_handoff::ScopedReadResult;
use oneiron_authority::federation::Scope;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::ops::Bound;

/// The next observation page, bounded by the effective snapshot page settings.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StrengthObservationsPageRequest {
    /// The preceding page's opaque cursor; absent on the first page.
    pub cursor: Option<String>,
    /// The most claims served, capped at the effective page row bound.
    pub limit: Option<u32>,
}
