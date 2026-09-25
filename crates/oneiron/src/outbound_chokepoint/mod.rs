//! Replay-first outbound effect execution.
//!
//! This module is the only production lane that may combine governance,
//! budget accounting, durable intent state, and transport.

mod admission;
mod replay;
mod types;

mod fanout;

pub use fanout::FanoutApprovalMode;
pub(crate) use fanout::{
    FanoutAdmission, FanoutApprovalChoice, FanoutApprovalError, FanoutApprovalRow,
    FanoutAutoDecider, FanoutAutoDisposition, FanoutEstimate, FanoutHistory, FanoutPathology,
    FanoutPlan, FanoutPlanEdge, FanoutSurfaceSink, PeerRateSnapshot, admit_fanout_with_history,
    approve_and_resume_fanout, fanout_estimate, fanout_history_pathology, fanout_plan_digest,
};

pub(crate) use self::admission::execute_outbound_effect;
#[cfg(test)]
pub(crate) use self::types::BEFORE_NEW_ADMISSION;
pub(crate) use self::types::{
    OutboundEffectCommand, OutboundEffectError, OutboundEffectResult, OutboundTransport,
    PreparedAuthorization, PreparedEffect, frozen_call_hygiene_headers,
};

#[cfg(test)]
mod tests;

// The flat outbound_chokepoint.rs module used to provide these names to the
// sibling test module through `use super::*`: its own private crate/std
// import header, and every chokepoint-internal item the tests name bare.
// After the directory split the seam re-imports both so `tests.rs` resolves
// exactly as it did before.
#[cfg(test)]
use self::replay::{RecoveryGovernance, recovery_governance, send_pending};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::attempt_queue::AttemptId;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::outbound_consent::OutboundBindingAuthority;
#[cfg(test)]
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, FrozenOutboundCall, IntentEscalation, IntentEscalationReason,
    IntentState, OutboundCallRequest, OutboundSendOutcome, force_sync, insert_pending_in_txn,
};
