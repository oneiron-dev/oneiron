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
use crate::office_body::LivePin;

#[doc(hidden)]
pub use oneiron_verb_wire::llm::decision::questions::artifact_refresh::unit_receipts::ArtifactUnitReceipt;

/// The receipts of every unit `run` left without an answer, abstained then
/// refused, in the order the ask met them.
pub(crate) fn artifact_unit_receipts(run: &ArtifactAskRun) -> Vec<ArtifactUnitReceipt> {
    let abstained = run
        .abstained
        .iter()
        .map(|unit| ArtifactUnitReceipt::Abstained {
            unit: unit.unit.clone(),
            decision: unit.decision.clone(),
            judged_live: unit.judged_live.clone(),
        });
    let refused = run.refused.iter().map(|unit| ArtifactUnitReceipt::Refused {
        unit: unit.unit.clone(),
        reason: unit.reason.clone(),
        judged_live: unit.judged_live.clone(),
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
