//! Moved from `crates/oneiron/src/memory/reads.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::recall::*;
use crate::memory::structural::*;
use crate::memory::*;
use oneiron_base::edge::EdgeKind;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Filter for [`Memory::claim_list`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimListFilter {
    /// Restrict to claims on this subject (short-id ref or hex).
    pub subject_ref: Option<String>,
    /// Restrict to this predicate.
    pub predicate: Option<String>,
    /// Restrict to this lifecycle (`active`/`superseded`/`retracted`).
    pub lifecycle: Option<String>,
    /// Maximum results (required; no unbounded scans).
    pub limit: usize,
    /// The caller's retrieval filter (FIX 3977): it narrows the claims the
    /// list reads, never the subject it names.
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
}

/// Options for [`Memory::neighbors`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NeighborOpts {
    /// Restrict to this snake_case `EdgeKind` name.
    pub edge_kind: Option<String>,
    /// Drop edges below this weight (engine-side filter).
    pub min_weight: Option<f32>,
    /// Maximum hits (required; no unbounded scans).
    pub limit: usize,
}
