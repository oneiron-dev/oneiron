//! Moved from `crates/oneiron/src/self_heal/audit.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::receipt::task_type_ref::TypeRef;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

/// The agent's report, not an outcome label. Uncertainty requests examination
/// just as an explicit flaw does, but is not a claim that a flaw exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveConfession {
    pub objective: String,
    /// The agent's own answer; `None` when it gave none (FIX 9466): a
    /// missing or malformed confession is recorded as no answer, never
    /// filled in.
    pub met: Option<bool>,
    pub flaw: Option<String>,
    pub uncertainty: Option<String>,
}

impl ObjectiveConfession {
    #[must_use]
    pub fn confesses_flaw(&self) -> bool {
        self.met == Some(false) || self.flaw.is_some()
    }

    #[must_use]
    pub fn needs_recheck(&self) -> bool {
        self.confesses_flaw() || self.uncertainty.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttemptConfession {
    pub attempt: AttemptId,
    /// The skill or actor this attempt measured.
    pub subject: EntityId,
    pub type_ref: TypeRef,
    /// Every objective the attempt was given, including ones it met.
    pub objectives: Vec<ObjectiveConfession>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SealCheckKind {
    ConfessionRecheck,
    RandomAudit,
}

/// The draw and the rate are saved together, including unselected draws.
/// Changing an owner's seed or pin never redraws an attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditDraw {
    pub rate: f64,
    pub sample: f64,
    pub at: u64,
}

impl AuditDraw {
    #[must_use]
    pub fn selected(&self) -> bool {
        self.sample < self.rate
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealCheckRequest {
    pub reference: String,
    pub attempt: AttemptId,
    pub kind: SealCheckKind,
    pub result_ref: String,
    /// Directed checks name the confessed or uncertain objectives; a random
    /// audit examines every objective, not merely what the agent disclosed.
    pub objectives: Vec<ObjectiveConfession>,
    pub rate: f64,
    pub created_at: u64,
}

/// An independently checked finding, including an evidence ref when clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveFinding {
    pub objective: String,
    pub flaw_present: bool,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealCheckOutcome {
    pub judge_revision: String,
    pub checked_at: u64,
    /// Exactly one independently checked answer per requested objective.
    pub findings: Vec<ObjectiveFinding>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealCheckReceipt {
    pub request: SealCheckRequest,
    pub outcome: Option<SealCheckOutcome>,
    /// When a pass last put the pending check to a checker; none before the
    /// first. A pass asks the never-asked first, then the longest since, so
    /// a check that keeps coming back unsettled cannot hold every slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_asked_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedAttemptReceipt {
    pub confession: AttemptConfession,
    /// The project the attempt ran in, as its stored dispatch names it at
    /// seal time (FIX 2957). `None` when it names none.
    pub project: Option<EntityId>,
    pub executor: String,
    pub result_ref: String,
    pub sealed_at: u64,
    pub passing: bool,
    pub draw: Option<AuditDraw>,
    pub checks: Vec<SealCheckReceipt>,
}
pub mod doors;
