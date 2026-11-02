//! A completed send's admitted presentation (FIX 8815): the space posting
//! and effective policy risk its frozen payload holds. An exact replay of a
//! Done send freezes these, not today's owner settings, so a setting changed
//! since cannot turn its recorded success into a payload mismatch. A send
//! that may still reach transport reads today's presentation instead.

use serde::Deserialize;

use super::request_binding::invalid_replay;
use crate::channel_identity_autonomy::FrozenSpacePosting;
use crate::gate::ExternalEffectPolicyRisk;
use crate::outbound::dispatch_types::OutboundDispatchError;
use crate::outbound_intent_ledger::IntentLedgerRecord;

/// The presentation fields of a frozen outbound payload; every other field
/// is the replay validator's to compare.
#[derive(Deserialize)]
struct FrozenPresentation {
    #[serde(default)]
    space_posting: Option<FrozenSpacePosting>,
    policy_risk: String,
}

/// What a completed send was admitted with.
pub(super) struct CompletedReplayPresentation {
    pub(super) space_posting: Option<FrozenSpacePosting>,
    pub(super) policy_risk: ExternalEffectPolicyRisk,
}

impl CompletedReplayPresentation {
    /// Reads `record`'s admitted presentation from its frozen payload. A
    /// payload that does not hold one is no replay of this send.
    ///
    /// # Errors
    /// An invalid replay when the frozen payload does not read.
    pub(super) fn from_record(record: &IntentLedgerRecord) -> Result<Self, OutboundDispatchError> {
        let frozen: FrozenPresentation =
            serde_json::from_slice(record.payload()).map_err(|_| invalid_replay())?;
        let policy_risk = match frozen.policy_risk.as_str() {
            "normal" => ExternalEffectPolicyRisk::Normal,
            "hold_to_proposal" => ExternalEffectPolicyRisk::HoldToProposal,
            _ => return Err(invalid_replay()),
        };
        Ok(Self {
            space_posting: frozen.space_posting,
            policy_risk,
        })
    }
}
