//! Device-local durable intent ledger for effectful outbound calls.
//!
//! Effectful calls persist frozen bytes as `Pending` before transport. Replay
//! and recovery reuse the persisted deterministic key; these private
//! `vault_meta` rows never enter replication.

mod codec;
mod dispatch;
mod store;
mod types;

pub use self::codec::INTENT_LEDGER_VALUE_KEYS;
pub use self::dispatch::{derive_intent_id, intent_ledger_records};
pub use self::types::{
    BudgetChargeMarker, BudgetClass, FrozenOutboundCall, INTENT_LEDGER_SCHEMA_VERSION,
    IntentDispatchResult, IntentEscalation, IntentEscalationReason, IntentId,
    IntentLedgerCorruptRow, IntentLedgerError, IntentLedgerListing, IntentLedgerRecord,
    IntentLedgerResult, IntentRecoveryFailure, IntentRecoveryReport, IntentState,
    OUTBOUND_BINDING_VERSION, OutboundAuthorizationBinding, OutboundCallClass, OutboundCallRequest,
    OutboundFailureKind, OutboundSendFailure, OutboundSendOutcome, OutboundToolDescriptor,
    RecordedOutboundOutcome, classify_outbound_tool,
};

#[cfg(test)]
pub(crate) use self::dispatch::execute_outbound_call;
#[cfg(test)]
use self::dispatch::recover_outbound_intents;
pub(crate) use self::dispatch::{IntentRecoveryEntry, intent_recovery_entries};
pub(crate) use self::store::{
    abandon_record, begin_definite_non_delivery_retry, complete_record, force_sync,
    hash_frozen_payload, insert_pending_in_txn, read_intent_for_attempt_in_txn,
    read_intent_record_in_txn, record_definite_non_delivery,
};
#[cfg(test)]
pub(crate) use self::store::{read_intent_record, replace_intent_record_for_test};
#[cfg(test)]
pub(crate) use self::types::OutboundSender;

#[cfg(test)]
mod tests;

// The flat outbound_intent_ledger.rs module used to provide these names to the
// sibling test module through `use super::*`: every ledger-internal item the
// tests name bare, and the module's own private crate/std import header. After
// the directory split the seam re-imports both so `tests.rs` resolves exactly
// as it did before.
#[cfg(test)]
use self::{codec::*, store::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::attempt_queue::AttemptId;
#[cfg(test)]
use crate::connector_key::ScopedCapabilityProvenance;
#[cfg(test)]
use crate::entity_id::{EntityId, bytes_to_hex_lower};
#[cfg(test)]
use rmpv::Value;
