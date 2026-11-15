//! Moved from `crates/oneiron/src/genui/protocol.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::genui::consent_eval::ConsentActionKind;
use serde::Deserialize;
use serde::Serialize;

/// RCPT-3 component set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Of336ComponentKind {
    ReceiptView,
    ConsentAsk,
    BundleApprove,
    ProjectProposal,
}

impl Of336ComponentKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptView => "receipt_view",
            Self::ConsentAsk => "consent_ask",
            Self::BundleApprove => "bundle_approve",
            Self::ProjectProposal => "project_proposal",
        }
    }
}

/// One stable action advertised by an OF-336 card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Of336ActionDescriptor {
    pub action_id: String,
    pub label: String,
    pub action: ConsentActionKind,
}
