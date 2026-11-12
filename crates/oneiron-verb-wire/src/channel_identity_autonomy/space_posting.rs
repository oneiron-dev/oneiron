//! Moved from `crates/oneiron/src/channel_identity_autonomy/space_posting.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::consent_bound::ActionClass;
use oneiron_store::consent_bound::ActionEnvelope;
use oneiron_store::consent_bound::ActorBound;
use oneiron_store::consent_bound::GrantBound;
use oneiron_store::gate_decision::types::GATE_DECISION_LEDGER_VERSION;
use oneiron_store::gate_decision::types::GateDecisionId;

/// Posting identity is data. Even owner mode must pass the normal outbound gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpacePostingMode {
    NamedParticipant,
    PostAsOwner,
}
