//! Moved from `crates/oneiron/src/context_board/self_brief.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::context_board::self_brief::ceilings::BriefActPosture;
pub use crate::context_board::self_brief::ceilings::BriefBranchBound;
pub use crate::context_board::self_brief::ceilings::BriefCeilingTarget;
pub use crate::context_board::self_brief::ceilings::BriefClassPrecedence;
pub use crate::context_board::self_brief::ceilings::BriefConnectorCeiling;
pub use crate::context_board::self_brief::ceilings::BriefContextBound;
pub use crate::context_board::self_brief::ceilings::BriefCredentialCeiling;
pub use crate::context_board::self_brief::ceilings::BriefRunCeiling;
pub use crate::context_board::self_brief::class_verdicts::BriefActionEnvelope;
pub use crate::context_board::self_brief::class_verdicts::BriefDefaultRule;
pub use crate::context_board::self_brief::class_verdicts::BriefPerActCheck;
pub use crate::context_board::self_brief::grants::BriefGrant;
pub use crate::context_board::self_brief::grants::BriefGrants;
pub use crate::context_board::self_brief::working_set::BriefWorkingHandle;
pub use crate::context_board::self_brief::working_set::BriefWorkingSet;
use oneiron_authority::authority::CommReach;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeSet;

/// COMM (Engine ruling 21:47): whom the agent may address, as two separate
/// values, each `None` when no host produced it. `reach` is the run's
/// effective reach; `credential_ceiling` is the verified credential's
/// signed reach. A route is bounded by both. Neither is a recipient list
/// or a message count, and neither is target admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct CommunicationLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reach: Option<CommReach>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ceiling: Option<CommReach>,
}

impl CommunicationLimits {
    /// Whether no host produced either value: identity leaves the limits
    /// out, and the unavailable line names each value.
    fn is_unavailable(&self) -> bool {
        self.reach.is_none() && self.credential_ceiling.is_none()
    }
}

/// The head of the line that names each brief field no host produced.
pub const UNAVAILABLE_HEAD: &str = "unavailable (no producer yet)";

/// A skill index row is resolved from the skill record and reliability claim;
/// the mutable confidence cache is never an authority for this number.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BriefSkillRow {
    pub id: EntityId,
    pub hash: Option<String>,
    pub reliability: f32,
    pub loaded_hash: Option<String>,
}

/// The cached prefix is replaced only at turn one or an epoch fold. A mid-run
/// call returns an append-only tail update without touching the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BriefPlacement {
    TurnOne,
    Fold,
    MidRun,
}
pub mod ceilings;
pub mod class_verdicts;
pub mod grants;
pub mod working_set;
