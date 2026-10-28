//! FIX 9913: every unit an artifact ask left without an answer keeps its
//! receipt in the question's ask log, whether or not the ask held a
//! proposal. An answered unit's decision rides its proposal; an abstained
//! unit keeps the decision that declined it (none when it had no input), a
//! refused unit keeps why, and a unit whose copy did not pass the secret scan
//! is kept as omitted, never dropped.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::store::secret_scan_before_put;
use crate::edit_roundtrip::ArtifactAskRun;
use crate::llm::decision::TypedDecision;

/// One unit an artifact ask left without an answer, as its log keeps it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactUnitReceipt {
    /// Asked and not answered: the decision with its receipt, or none when the
    /// unit had no input to read or its state was past the call's bound. A
    /// unit whose ask went to the next authorised role stays here, with that
    /// ask's reason on its receipt, until the role answers.
    Abstained {
        unit: Value,
        decision: Option<TypedDecision>,
    },
    /// Not read as given, and why.
    Refused { unit: Value, reason: String },
    /// A unit whose copy did not pass the secret scan: it was there, its
    /// content is left out.
    Omitted,
}

impl ArtifactUnitReceipt {
    /// Every id the receipt names: its decision's evidence.
    pub(in crate::llm::decision::questions) fn names(&self, id: &crate::EntityId) -> bool {
        match self {
            Self::Abstained {
                decision: Some(decision),
                ..
            } => {
                decision.evidence.contains(id)
                    || decision
                        .receipt
                        .evidence_versions
                        .iter()
                        .any(|pin| pin.id == *id)
            }
            _ => false,
        }
    }
}

/// The receipts of every unit `run` left without an answer, abstained then
/// refused, in the order the ask met them.
pub(crate) fn artifact_unit_receipts(
    run: &ArtifactAskRun,
) -> Vec<ArtifactUnitReceipt> {
    let abstained = run
        .abstained
        .iter()
        .map(|unit| ArtifactUnitReceipt::Abstained {
            unit: unit.unit.clone(),
            decision: unit.decision.clone(),
        });
    let refused = run.refused.iter().map(|unit| ArtifactUnitReceipt::Refused {
        unit: unit.unit.clone(),
        reason: unit.reason.clone(),
    });
    abstained
        .chain(refused)
        .map(|receipt| {
            if secret_scan_before_put(&receipt).is_ok() {
                receipt
            } else {
                ArtifactUnitReceipt::Omitted
            }
        })
        .collect()
}
