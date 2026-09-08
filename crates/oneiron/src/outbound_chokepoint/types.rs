//! Frozen admission model: error alias, result/command/auth/prepared types, transport trait, hygiene helper, cfg(test) hook.

use crate::attempt_queue::AttemptId;
use crate::connector_key::EffectorBudgetCharge;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::gate::ExternalEffectGateInput;
use crate::outbound_consent::ScopedMcpCallContext;
use crate::outbound_intent_ledger::{
    BudgetClass, FrozenOutboundCall, IntentDispatchResult, IntentId, IntentLedgerError,
    OutboundSendOutcome, derive_intent_id, hash_frozen_payload,
};

pub(crate) type OutboundEffectError = IntentLedgerError;

#[cfg(test)]
std::thread_local! {
    pub(crate) static BEFORE_NEW_ADMISSION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Result of one replay-first effect execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundEffectResult {
    pub(crate) dispatch: IntentDispatchResult,
    pub(crate) gate_decision_id: Option<String>,
    pub(crate) gate_outcome: Option<String>,
    pub(crate) gate_reason_codes: Vec<String>,
    pub(crate) gate_receipt_reasons: Vec<String>,
    pub(crate) budget_charge: Option<EffectorBudgetCharge>,
}

/// The only two commands accepted by the effectful entry.
#[allow(clippy::large_enum_variant)]
pub(crate) enum OutboundEffectCommand {
    New(PreparedEffect),
    Resume(IntentId),
}

/// Authorization material for admission and live retry gate checks.
pub(crate) enum PreparedAuthorization {
    None,
    ScopedMcp {
        grant_id: EntityId,
        principal_ref: String,
        call: ScopedMcpCallContext,
    },
}

/// Fully frozen new-effect input. No transport object can change these axes.
pub(crate) struct PreparedEffect {
    pub(crate) attempt_id: AttemptId,
    pub(crate) call_seq: u64,
    pub(crate) server: String,
    pub(crate) tool: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) idempotency_supported: bool,
    pub(crate) resolved_endpoint: Option<String>,
    pub(crate) gate: ExternalEffectGateInput,
    pub(crate) budget_class: BudgetClass,
    pub(crate) authorization: PreparedAuthorization,
    pub(crate) verified_actor: Option<(EntityId, EdgeActorClass)>,
}

impl PreparedEffect {
    pub(super) fn payload_hash(&self) -> [u8; 32] {
        hash_frozen_payload(&self.payload)
    }

    pub(super) fn intent_id(&self) -> Result<IntentId, IntentLedgerError> {
        derive_intent_id(
            self.attempt_id,
            self.call_seq,
            &self.server,
            &self.tool,
            &self.payload_hash(),
        )
    }
}

/// Connector-agnostic transport. The endpoint, bytes, and idempotency key are
/// readable only from the frozen call supplied here.
pub(crate) trait OutboundTransport {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome;
}

/// The CA-05 send-hygiene headers this call must go out under, read from the
/// FROZEN bytes at the last boundary before transport.
///
/// Reading them here rather than re-deriving them is what makes retries
/// byte-identical: a replay never recomputes an unsubscribe target, it replays
/// the one the ledger froze. A payload that carries no hygiene headers — every
/// non-email send, and every connector payload that was never JSON — yields an
/// empty map, so nothing about existing transports changes.
///
/// # Errors
///
/// [`IntentLedgerError::InvalidRecord`] when the frozen payload carries the
/// hygiene field in a shape that cannot be replayed. A send whose headers the
/// ledger cannot vouch for does not reach the wire.
pub(crate) fn frozen_call_hygiene_headers(
    call: &FrozenOutboundCall,
) -> Result<std::collections::BTreeMap<String, String>, OutboundEffectError> {
    crate::campaign::send_hygiene::frozen_payload_hygiene_headers(call.payload()).map_err(|_| {
        IntentLedgerError::InvalidRecord("frozen outbound payload carries invalid hygiene headers")
    })
}
