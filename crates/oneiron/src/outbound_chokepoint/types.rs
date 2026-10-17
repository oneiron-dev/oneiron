//! Frozen admission model: error alias, result/command/auth/prepared types, transport trait, hygiene helper, cfg(test) hook.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::connector_key::EffectorBudgetCharge;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::gate::ExternalEffectGateInput;
use crate::outbound_consent::tool_call::PreparedToolCall;
use crate::outbound_intent_ledger::{
    BudgetClass, FrozenOutboundCall, IntentDispatchResult, IntentId, IntentLedgerError,
    IntentResolution, OutboundSendOutcome, derive_intent_id, hash_frozen_payload,
};
use crate::receipt::ReceiptRecord;

pub(crate) type OutboundEffectError = IntentLedgerError;

#[cfg(any(test, feature = "test-hooks"))]
std::thread_local! {
    pub(crate) static BEFORE_NEW_ADMISSION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Result of one replay-first effect execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundEffectResult {
    pub(crate) dispatch: IntentDispatchResult,
    pub(crate) resolution: Option<IntentResolution>,
    pub(crate) gate_decision_id: Option<String>,
    pub(crate) gate_outcome: Option<String>,
    pub(crate) gate_reason_codes: Vec<String>,
    pub(crate) gate_receipt_reasons: Vec<String>,
    pub(crate) budget_charge: Option<EffectorBudgetCharge>,
    /// OF-327 suppression is not a Gate denial or a Gate reason code.
    pub(crate) dedupe_suppressed: bool,
    pub(crate) suppression_receipt: Option<ReceiptRecord>,
    /// Set when the admission ceiling held this call before its Pending
    /// insert, to the count it read under the writer lock: nothing was
    /// admitted or sent.
    pub(crate) ceiling_count: Option<u32>,
}

/// The only two commands accepted by the effectful entry.
#[allow(clippy::large_enum_variant)]
pub(crate) enum OutboundEffectCommand {
    New(PreparedEffect),
    /// Ledger-first, governance-only disposition: never starts transport or
    /// charges a budget, but returns terminal history or preserves Pending.
    Park(PreparedEffect),
    Resume(IntentId),
}

/// Authorization material for admission and live retry gate checks.
pub(crate) enum PreparedAuthorization {
    None,
    ScopedMcp {
        grant_id: EntityId,
        principal_ref: String,
        prepared: Box<PreparedToolCall>,
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
    /// The owner whose approval this effect carries. Admission rechecks the
    /// proof under its writer, so a slip revoked while the effect waited for
    /// it admits nothing and never reaches the transport.
    pub(crate) owner_proof: Option<crate::consent::AuthenticatedOwner>,
    /// OF-327 semantic identity; absent for non-dispatch effects.
    pub(crate) dedupe_key: Option<String>,
    /// The caller-facing receipt to commit if this admission is suppressed.
    pub(crate) suppression_receipt: Option<ReceiptRecord>,
    /// A count bound checked under the admission writer lock; `None` for an
    /// effect with no such bound.
    pub(crate) admission_ceiling: Option<AdmissionCeiling>,
    /// A second actor the same mutation speaks for, admitted beside the
    /// primary under the same writer (OF-427).
    pub(crate) co_actor: Option<CoActorAdmission>,
}

/// A second actor one external mutation speaks for (OF-427): the verified
/// writer of the TASK a host scheduler mirrors. Its binding runs under the
/// admission writer, checks the mutation is still the one that actor wrote,
/// and yields the actor's gate input. Both governances must allow; the
/// co-actor's connector key is preflighted before the primary's is charged,
/// and charged only when it is a different key. Both decisions commit with
/// the Pending insert, so one remote mutation spends each key once.
pub(crate) struct CoActorAdmission {
    pub(crate) bind: Box<
        dyn for<'t> FnOnce(
                &Vault,
                &mut heed::RwTxn<'t>,
            ) -> Result<ExternalEffectGateInput, IntentLedgerError>
            + Send,
    >,
}

/// A deterministic count bound on one server and tool. Admission holds the
/// call, never sends it, once the larger of `prior` (the host's own count)
/// and this vault's ledger rows created at or after `since_ms` reaches `cap`.
/// It is read in the same writer transaction as the Pending insert, so two
/// admissions cannot both take the last allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionCeiling {
    pub(crate) since_ms: u64,
    pub(crate) prior: u32,
    pub(crate) cap: u32,
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
