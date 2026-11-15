//! Moved from `crates/oneiron/src/self_heal/audit/contract.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::step_replay::ReplayRoutePin;
use oneiron_model::llm::ModelLocality;
use oneiron_model::model_binding::ModelRole;
use oneiron_verb_wire::self_heal::audit::ObjectiveFinding;
use serde::Deserialize;
use serde::Serialize;

/// The checker a host put a seal check to (FIX 3611): the digest of its
/// protocol and wording, the role its judge was routed on, and the rung
/// that answered there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckerProtocol {
    pub digest: [u8; 32],
    pub role: ModelRole,
    /// Where the judge's answering rung ran, and the route it went out on
    /// as it answered, which names its route prompt by digest, never by
    /// text. `None` when the check could not name that rung: its audit
    /// anchors nothing.
    pub judge_rung: Option<(ModelLocality, ReplayRoutePin)>,
}

/// A completed random audit's frozen contract (FIX 3611): what a
/// contribution check scores both of its forks by. It is taken from the
/// check as it was admitted and never changes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditContract {
    /// The audit's check reference: the outcome receipt its anchor names.
    pub check: String,
    /// The rate the audit was drawn at.
    pub rate: f64,
    /// The checker's protocol, the role its judge was routed on and the
    /// rung that answered there.
    pub protocol: CheckerProtocol,
    /// The independent judge that checked the result, as it served.
    pub judge_revision: String,
    /// Every objective the audit examined, in the order it asked them.
    pub objectives: Vec<String>,
    /// One finding per objective.
    pub findings: Vec<ObjectiveFinding>,
    /// Unix seconds the result was checked.
    pub checked_at: u64,
}

impl AuditContract {
    /// Whether the audited result passed, by [`flaw_free`].
    #[must_use]
    pub fn passed(&self) -> bool {
        flaw_free(&self.findings)
    }
}

/// An audit's pass rule (FIX 3611): no finding names a flaw. The original
/// check and both forks of a contribution check are scored by this rule.
#[must_use]
pub fn flaw_free(findings: &[ObjectiveFinding]) -> bool {
    findings.iter().all(|finding| !finding.flaw_present)
}
