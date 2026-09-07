//! Propose-only repair contracts. These values carry intent, never execution authority.

use crate::claim::ClaimSource;
use crate::entity_id::EntityId;

mod invocation;
mod validation;

pub use invocation::HealerInvocationStamp;
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use invocation::{RegisteredHealer, run_healer_proposals};
pub(crate) use validation::validate_repair_proposal;

use super::{DiagnosticEvent, DiagnosticWorkingSet};

/// Healer-supplied attribution for review display, not an authority credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairActor {
    /// Claimed actor class, to be rendered as untrusted disclosure text.
    pub actor_class: String,
    /// Actor the proposal claims to represent.
    pub actor_ref: EntityId,
}

/// A closed vocabulary of repair intents. References are opaque, never opened here.
#[derive(Debug, Clone, PartialEq)]
pub enum RepairOperation {
    /// Request an index rebuild within a named scope.
    Reindex { scope_ref: String },
    /// Request a fresh score for an entity.
    Rescore { target_ref: EntityId },
    /// Request review of a retry, not execution of the referenced run.
    Retry { run_ref: String },
    /// Suggest a policy restriction. The name is not proof of narrowing.
    NarrowPolicy {
        predicate: String,
        value: rmpv::Value,
    },
    /// Suggest a claim value without writing a claim.
    ProposeClaim {
        predicate: String,
        value: rmpv::Value,
    },
    /// Suggest a skill patch. Always human-reviewed because skills can carry code.
    SkillEdit {
        skill_ref: EntityId,
        patch_ref: String,
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
            Self::DevPatch { .. } => "dev_patch",
            Self::SchemaPatch { .. } => "schema_patch",
        }
    }
}

/// Untrusted healer output. Actor and source are disclosure, not Gate inputs.
#[derive(Debug, Clone, PartialEq)]
pub struct RepairProposal {
    /// Identity of this proposed intent within the bundle.
    pub proposal_id: EntityId,
    /// Diagnostic records the healer cites; not evidence of permission.
    pub diagnostic_refs: Vec<EntityId>,
    /// Claimed actor, retained even when it differs from the engine stamp.
    pub actor: RepairActor,
    /// Claimed source, retained even when it differs from the engine stamp.
    pub source: ClaimSource,
    /// Predicate whose CURRENT manifest criticality governs this repair.
    pub target_predicate: String,
    /// Typed intent with its own target or operation-specific references.
    pub operation: RepairOperation,
    /// Replaced by the runner's session tag before review.
    pub session_tag: String,
}

/// A healer receives only the caller's bounded read set and diagnostic slice.
///
/// Implementations must propose without side effects. No vault, transaction,
/// filesystem handle, or executor is supplied. Rust trait implementations are
/// trusted engine code, not an in-process sandbox for arbitrary native code.
pub trait Healer: Send + Sync {
    /// Return drafts only. The runner owns session tagging and consent recomputation.
    fn propose(
        &self,
        working_set: &DiagnosticWorkingSet<'_>,
        diagnostics: &[DiagnosticEvent],
    ) -> Vec<RepairProposal>;
}

/// Recomputed repair criticality, never copied from a diagnostic or healer label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairCriticality {
    /// Normal under the supplied current manifest.
    Normal,
    /// Critical under the manifest or the operation's review-only floor.
    Critical,
}

/// Routing advice only. No variant is an authorization to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairConsentRoute {
    /// The ordinary Gate allows the intent; it remains an unexecuted proposal.
    AutoEligible,
    /// A human must review the intent.
    HumanReview,
    /// The Gate denied the intent.
    Denied,
}

/// One proposal paired with its engine-computed disclosure. No summary approval exists.
///
/// Fields are read-only so a reviewed target cannot be replaced while retaining
/// another target's route. This is still a snapshot, not a reusable capability.
#[derive(Debug, Clone, PartialEq)]
pub struct ReviewedRepair {
    proposal: RepairProposal,
    invocation: HealerInvocationStamp,
    criticality: RepairCriticality,
    route: RepairConsentRoute,
    reason_codes: Vec<String>,
}

impl ReviewedRepair {
    /// Full per-member intent, including claimed actor/source and diagnostic refs.
    #[must_use]
    pub fn proposal(&self) -> &RepairProposal {
        &self.proposal
    }

    /// Engine-stamped identity and source actually used by the Gate.
    #[must_use]
    pub fn invocation(&self) -> &HealerInvocationStamp {
        &self.invocation
    }

    /// Criticality recomputed when this member was reviewed.
    #[must_use]
    pub const fn criticality(&self) -> RepairCriticality {
        self.criticality
    }

    /// Proposal-only route; even AutoEligible performs no repair.
    #[must_use]
    pub const fn route(&self) -> RepairConsentRoute {
        self.route
    }

    /// Ordinary Gate reason codes for this member alone.
    #[must_use]
    pub fn reason_codes(&self) -> &[String] {
        &self.reason_codes
    }
}

/// Session-tagged, per-member review results. There is deliberately no bundle route.
///
/// Even an AutoEligible member has no execution API:
///
/// ```compile_fail
/// use oneiron::self_heal::RepairBundle;
/// fn execute(bundle: &RepairBundle) {
///     bundle.apply();
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RepairBundle {
    session_tag: String,
    proposals: Vec<ReviewedRepair>,
}

impl RepairBundle {
    /// The engine's session tag, shared by every proposal and invocation stamp.
    #[must_use]
    pub fn session_tag(&self) -> &str {
        &self.session_tag
    }

    /// Every member with its own full intent, criticality, provenance, and route.
    #[must_use]
    pub fn proposals(&self) -> &[ReviewedRepair] {
        &self.proposals
    }
}
