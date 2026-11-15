//! Moved from `crates/oneiron/src/self_heal/repair/mod.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Healer-supplied attribution for review display, not an authority credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairActor {
    /// Claimed actor class, to be rendered as untrusted disclosure text.
    pub actor_class: String,
    /// Actor the proposal claims to represent.
    #[serde(with = "oneiron_verb_wire::self_heal::receipt_serde::id")]
    pub actor_ref: EntityId,
}

/// A closed vocabulary of repair intents. References are opaque, never opened here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RepairOperation {
    /// Request an index rebuild within a named scope.
    Reindex { scope_ref: String },
    /// Request a fresh score for an entity.
    Rescore {
        #[serde(with = "oneiron_verb_wire::self_heal::receipt_serde::id")]
        target_ref: EntityId,
    },
    /// Request review of a retry, not execution of the referenced run.
    Retry { run_ref: String },
    /// Suggest a policy restriction. The name is not proof of narrowing.
    NarrowPolicy {
        predicate: String,
        #[serde(with = "crate::self_heal::receipt_serde::value")]
        value: rmpv::Value,
    },
    /// Suggest a claim value without writing a claim.
    ProposeClaim {
        predicate: String,
        #[serde(with = "crate::self_heal::receipt_serde::value")]
        value: rmpv::Value,
    },
    /// Suggest a skill patch. Always human-reviewed because skills can carry code.
    SkillEdit {
        #[serde(with = "oneiron_verb_wire::self_heal::receipt_serde::id")]
        skill_ref: EntityId,
        patch_ref: String,
    },
    /// Case-bound, agent-targeted healer diagnosis. It is never an effect;
    /// each route is a review-only proposal, including fork-resume.
    FixAgent {
        case_ref: String,
        route: crate::failure_ladder::lineage::HealerRepairRoute,
    },
    /// Dev-time code review only; no repository or patch access is provided.
    DevPatch { repo_ref: String, patch_ref: String },
    /// Dev-time schema review only; no migration capability is provided.
    SchemaPatch {
        schema_ref: String,
        patch_ref: String,
    },
}

impl RepairOperation {
    /// Stable wire spelling of the operation tag, not an executable command.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Reindex { .. } => "reindex",
            Self::Rescore { .. } => "rescore",
            Self::Retry { .. } => "retry",
            Self::NarrowPolicy { .. } => "narrow_policy",
            Self::ProposeClaim { .. } => "propose_claim",
            Self::SkillEdit { .. } => "skill_edit",
            Self::FixAgent { .. } => "fix_agent",
            Self::DevPatch { .. } => "dev_patch",
            Self::SchemaPatch { .. } => "schema_patch",
        }
    }
}

/// Untrusted healer output. Actor and source are disclosure, not Gate inputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairProposal {
    /// Identity of this proposed intent within the bundle.
    #[serde(with = "oneiron_verb_wire::self_heal::receipt_serde::id")]
    pub proposal_id: EntityId,
    /// Diagnostic records the healer cites; not evidence of permission.
    #[serde(with = "crate::self_heal::receipt_serde::ids")]
    pub diagnostic_refs: Vec<EntityId>,
    /// Claimed actor, retained even when it differs from the engine stamp.
    pub actor: RepairActor,
    /// Claimed source, retained even when it differs from the engine stamp.
    #[serde(with = "crate::self_heal::receipt_serde::source")]
    pub source: ClaimSource,
    /// Predicate whose CURRENT manifest criticality governs this repair.
    pub target_predicate: String,
    /// Typed intent with its own target or operation-specific references.
    pub operation: RepairOperation,
    /// Replaced by the runner's session tag before review.
    pub session_tag: String,
}
