//! Moved from `crates/oneiron/src/dreamer_wake/sieve/audit_windows.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_wake::sieve::SpanKind;
use crate::model_step_effect::StepEffectBinding;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A byte range of one source of a turn, read at the version
/// `source_digest`, where the turn's current reading flagged nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SieveAuditWindow {
    pub turn: EntityId,
    /// The MESSAGE whose text the offsets index, or the TURN for body text.
    pub source: EntityId,
    /// BLAKE3 of the source text the offsets index.
    pub source_digest: [u8; 32],
    /// UTF-8 byte offsets into that text, on character boundaries.
    pub start: u64,
    pub end: u64,
}

impl SieveAuditWindow {
    /// BLAKE3 identity of the window: its ref and the text version it
    /// indexes.
    pub fn id(&self) -> [u8; 32] {
        *blake3::Hasher::new()
            .update(b"oneiron:dreamer-sieve:audit-window:v1")
            .update(self.turn.as_bytes())
            .update(self.source.as_bytes())
            .update(&self.source_digest)
            .update(&self.start.to_be_bytes())
            .update(&self.end.to_be_bytes())
            .finalize()
            .as_bytes()
    }
}

/// What the rules expected of an audited range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SieveAuditExpectation {
    /// A rule or a saved tag flagged a span there ([`super::recipes::SieveAudit`]).
    Flagged,
    /// Nothing was flagged in the range.
    Unflagged,
}

/// One span the expensive path found in a window, by its exact bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SieveAuditDiscovery {
    /// UTF-8 byte offsets into the window's source text, inside the window.
    pub start: u64,
    pub end: u64,
    pub kind: SpanKind,
    /// Percent.
    pub confidence: u8,
}

/// Why a span the expensive path named has no offsets (FIX 7901).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SieveUnlocatedCause {
    /// The window's words hold its quote nowhere.
    QuoteNotFound,
    /// The window's words hold its quote more than once.
    QuoteAmbiguous,
}

/// One span the expensive path named in a window whose quote binds no one
/// place there (FIX 7901): kept as it was named, with no offsets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SieveUnlocatedDiscovery {
    pub kind: SpanKind,
    /// Percent.
    pub confidence: u8,
    pub cause: SieveUnlocatedCause,
    /// The words the reply quoted, as it wrote them.
    pub quote: String,
}

/// What the expensive path found in an audited range: the rules'
/// expectation, and every span it found there, zero or more, located or
/// not. None found is a negative label: the rules missed nothing in the
/// range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SieveAuditFinding {
    pub expectation: SieveAuditExpectation,
    pub window: SieveAuditWindow,
    pub discovered: Vec<SieveAuditDiscovery>,
    /// What it found whose quote locates no one place (FIX 7901); a
    /// finding whose every quote bound holds none and keeps its bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlocated: Vec<SieveUnlocatedDiscovery>,
}

impl SieveAuditFinding {
    /// Whether the expensive path agrees with the rules: it found nothing,
    /// located or not, in the range.
    pub fn agrees(&self) -> bool {
        self.discovered.is_empty() && self.unlocated.is_empty()
    }
}

/// An unflagged window's audit receipt: its finding and what it spent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SieveWindowAudit {
    pub finding: SieveAuditFinding,
    pub at: u64,
    pub completed_units: u64,
    pub step_bindings: Vec<StepEffectBinding>,
}
pub mod finding_identity;
