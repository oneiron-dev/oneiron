//! Moved from `crates/oneiron/src/counterparty_contact/trusted_contact_notice.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::counterparty_contact::trusted_contact::TrustedContact;
use crate::counterparty_contact::trusted_contact::TrustedContactDial;
use crate::counterparty_contact::trusted_contact::TrustedContactTier;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_delivery_vocabulary::delivery_window::types::DeliveryWindowDecision as OutboundDeliveryWindowDecision;
use oneiron_store::attempt_inputs::AttemptInterventionKind;
use oneiron_store::attempt_inputs::ClaimAttempt;
use oneiron_store::attempt_inputs::CompleteAttempt;
use oneiron_store::attempt_inputs::EnqueueAttempt;
use oneiron_store::attempt_inputs::FailAttempt;
use oneiron_store::attempt_inputs::RetryAttempt;
use oneiron_store::attempt_state::AttemptState;
use oneiron_store::gate_decision::types::GateSystemNoticeRecord;
use oneiron_store::outbound_outcome::OutboundDispatchOutcome;
use oneiron_store::outbound_trigger::OutboundIntentTrigger;
use serde::Deserialize;
use serde::Serialize;
use std::sync::PoisonError;
use std::sync::RwLockReadGuard;
use std::sync::RwLockWriteGuard;

/// What authorized one notice, written with it in the transaction that
/// staged it: the person's yes to their ask, or, for a just-call contact, the
/// owner's imminent-tier policy row the gate settled. Never a caller's word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "origin", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustedContactNoticeAuthorization {
    /// The person answered this ask yes, about the naming the notice is for.
    Ask { ask_ref: String },
    /// The policy row whose `RouteToHelp` fired the notice, and its tier.
    Policy {
        row_ref: String,
        tier: TrustedContactTier,
    },
}
