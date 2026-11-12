//! Moved from `crates/oneiron/src/snapshot_read/evidence_spans.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::snapshot_read::source_version::SourceVersionCheck;
use crate::snapshot_read::source_version::blake3_ref;
use oneiron_authority::claim_history_handoff::ClaimReadStatus;
use oneiron_authority::claim_history_handoff::PointRead;
use oneiron_authority::claim_history_handoff::ScopedReadResult;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;
use std::fmt::Write as _;

/// One byte range over a TURN's projected text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRange {
    /// The first byte, inclusive.
    pub start: u64,
    /// The end, exclusive.
    pub end: u64,
}

/// Whether the source reads for the caller, and at the version asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceStatus {
    /// The source reads, at the version asked when one was named.
    Current,
    /// The source reads, but at another version than the one asked: no bytes
    /// are served.
    Moved,
    /// The caller does not read the source, or it is absent.
    Withheld,
}

/// The exact bytes of one range of a TURN's projected text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceSpan {
    /// The first byte, inclusive.
    pub start: u64,
    /// The end, exclusive.
    pub end: u64,
    /// The range's exact text.
    pub text: String,
    /// `blake3:<hex>` of the range's exact bytes.
    pub content_hash: String,
    /// The MESSAGE-local slices the range covers, for a TURN whose words are
    /// its MESSAGE rows; empty for a TURN that carries its own words.
    pub messages: Vec<EvidenceMessageSlice>,
}

/// One MESSAGE-local slice behind a range of a TURN's text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceMessageSlice {
    /// The MESSAGE row.
    pub message: EntityId,
    /// The first byte within the MESSAGE's own content, inclusive.
    pub start: u64,
    /// The end within the MESSAGE's own content, exclusive.
    pub end: u64,
    /// `blake3:<hex>`: the evidence hash of the MESSAGE revision read.
    pub revision: String,
    /// The MESSAGE's document frontier, in hex, when it has a document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}
