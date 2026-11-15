//! Moved from `crates/oneiron/src/llm/decision/questions/artifact_refresh/unit_receipts.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::typed_body::live_pin::LivePin;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

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
        /// The live body the ask read the unit on, when it read one (FIX
        /// 12018).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        judged_live: Option<LivePin>,
    },
    /// Not read as given, and why.
    Refused {
        unit: Value,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        judged_live: Option<LivePin>,
    },
    /// A unit whose copy did not pass the secret scan: it was there, its
    /// content is left out.
    Omitted,
}

impl ArtifactUnitReceipt {
    /// Every id the receipt names: its decision's evidence.
    pub fn names(&self, id: &oneiron_contracts::entity_id::EntityId) -> bool {
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
