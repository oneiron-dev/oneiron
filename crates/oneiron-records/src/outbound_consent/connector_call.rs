//! Moved from `crates/oneiron/src/outbound_consent/connector_call.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::outbound_consent::connector_call_types::ConnectorAwaitingInput;
pub use crate::outbound_consent::connector_call_types::ConnectorCallOutcome;
pub use crate::outbound_consent::connector_call_types::ConnectorQuestion;
pub use crate::outbound_consent::connector_call_types::ConnectorResultAbsence;
pub use crate::outbound_consent::connector_call_types::UntrustedToolResult;
pub use oneiron_verb_wire::outbound_consent::connector_call_types::ConnectorCallRequest;
pub use oneiron_verb_wire::outbound_consent::connector_call_types::ConnectorSource;
use serde::Deserialize;
use serde::Serialize;

/// A held call's terminal outcome, without the tool's reply: the ledger
/// never keeps a reply's bytes, so a recovery from this row is receipt-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettledConnectorCall {
    Delivered {
        intent: Option<[u8; 32]>,
    },
    Refused {
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    Unsettled {
        intent: [u8; 32],
        reasons: Vec<String>,
    },
}

impl SettledConnectorCall {
    pub fn outcome(&self) -> ConnectorCallOutcome {
        match self.clone() {
            Self::Delivered { intent } => ConnectorCallOutcome::Delivered {
                intent,
                result: None,
                result_absence: Some(ConnectorResultAbsence::NotRetained),
                budget_steering: Vec::new(),
            },
            Self::Refused {
                decision_ref,
                reasons,
            } => ConnectorCallOutcome::Refused {
                decision_ref,
                reasons,
            },
            Self::Unsettled { intent, reasons } => ConnectorCallOutcome::PendingDelivery {
                intent,
                call_ref: None,
                reasons,
            },
        }
    }
}
