//! Moved from `crates/oneiron/src/consent/widen/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WidenKind {
    Action,
    Disclosure,
    AutoConfirm,
}

impl WidenKind {
    fn label(self) -> &'static str {
        match self {
            Self::Action => "propose_action_widen",
            Self::Disclosure => "propose_disclosure_widen",
            Self::AutoConfirm => "propose_auto_confirm_widen",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "propose_action_widen" => Some(Self::Action),
            "propose_disclosure_widen" => Some(Self::Disclosure),
            "propose_auto_confirm_widen" => Some(Self::AutoConfirm),
            _ => None,
        }
    }
}

/// A proposal receipt confers no authority. It is not a ConsentGrant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidenProposal {
    pub proposal_ref: String,
    pub canonical_delta: Vec<u8>,
    pub proposer: String,
    pub owner_ref: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub decision_id: [u8; 16],
}
