//! Moved from `crates/oneiron/src/dreamer_wake/sieve/recipes.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_consolidation::provenance::KeptDecision;
use crate::dreamer_wake::recipes::WakeRecipePolicy;
use crate::dreamer_wake::sieve::SieveSpan;
use crate::model_step_effect::StepEffectBinding;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::Scope;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::model_decision::EvidenceVersion;
use serde::Deserialize;
use serde::Serialize;

/// One span the nightly spending consumed: its ref, the child attempt that
/// carries its TURN's work (FIX 7498) and when. The original reading stays
/// in the retained history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SieveConsumeReceipt {
    pub span: [u8; 32],
    pub turn: EntityId,
    pub source: EntityId,
    pub start: u64,
    pub end: u64,
    pub kind: super::SpanKind,
    pub score: u32,
    pub attempt: AttemptId,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RungInput {
    pub span: SieveSpan,
    pub audit: bool,
    pub policy: WakeRecipePolicy,
}

/// A sampled rule reading and the expensive path's label, kept by receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SieveAudit {
    pub sampled: bool,
    pub span: [u8; 32],
    pub turn: EntityId,
    pub source: EntityId,
    pub source_digest: [u8; 32],
    pub expected_kind: super::SpanKind,
    pub actual_kind: super::SpanKind,
    pub expected_entity: Option<EntityId>,
    pub actual_entity: Option<EntityId>,
    pub novel: bool,
    pub confidence: u8,
    pub agrees: bool,
    pub at: u64,
    pub completed_units: u64,
    pub step_bindings: Vec<StepEffectBinding>,
    /// Every owed rung's typed decisions, rung by rung in pack order
    /// (OF-498a): what the reading was read from.
    pub decisions: Vec<KeptDecision>,
}

/// One audit receipt as kept: a flagged span's reading, sampled or owed,
/// exactly as before, or an unflagged window's finding (OF-498f). The enum
/// adds no tag, so a flagged receipt keeps its own bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SieveAuditRecord {
    Flagged(SieveAudit),
    Window(super::audit_windows::SieveWindowAudit),
}

impl SieveAuditRecord {
    /// Whether the receipt is a sampled audit, not an owed rung's reading.
    pub fn sampled(&self) -> bool {
        match self {
            Self::Flagged(audit) => audit.sampled,
            Self::Window(_) => true,
        }
    }

    pub fn turn(&self) -> EntityId {
        match self {
            Self::Flagged(audit) => audit.turn,
            Self::Window(audit) => audit.finding.window.turn,
        }
    }

    pub fn source(&self) -> EntityId {
        match self {
            Self::Flagged(audit) => audit.source,
            Self::Window(audit) => audit.finding.window.source,
        }
    }

    /// Whether the expensive path agrees with the rules: a flagged span's
    /// kind and entity, or nothing found in a window the rules left
    /// unflagged.
    pub fn agrees(&self) -> bool {
        match self {
            Self::Flagged(audit) => audit.agrees,
            Self::Window(audit) => audit.finding.agrees(),
        }
    }

    pub fn completed_units(&self) -> u64 {
        match self {
            Self::Flagged(audit) => audit.completed_units,
            Self::Window(audit) => audit.completed_units,
        }
    }

    pub fn step_bindings(&self) -> &[StepEffectBinding] {
        match self {
            Self::Flagged(audit) => &audit.step_bindings,
            Self::Window(audit) => &audit.step_bindings,
        }
    }
}

/// Text and exact source grants for a rung. A changed reading never labels
/// a new source version with the old span's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RungEvidence {
    pub text: String,
    pub entities: Vec<EntityId>,
    pub scope: Scope,
    /// The body version of each source the scope grants: the TURN, its
    /// source and each candidate, as a rung's decisions pin them.
    pub versions: Vec<EvidenceVersion>,
}
pub mod audit_erase;
