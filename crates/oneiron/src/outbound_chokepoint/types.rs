//! Frozen admission model: error alias, result/command/auth/prepared types, transport trait, hygiene helper, cfg(test) hook.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::connector_key::EffectorBudgetCharge;
use crate::consent::EffectDigest;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::gate::{ApprovalTarget, ExternalEffectGateInput};
use crate::outbound_consent::tool_call::PreparedToolCall;
use crate::outbound_intent_ledger::{
    AdmittedApproval, BudgetClass, FrozenOutboundCall, IntentDispatchResult, IntentId,
    IntentLedgerError, IntentResolution, OutboundSendOutcome, PinnedApproval, derive_intent_id,
    hash_frozen_payload, keep_pinned_approval_in_txn, keep_press_after_admission,
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
    /// FIX 6424 part 2a: the approve-once digest the Gate decision that held
    /// this call names, 64 lower-hex, composed over the very input that
    /// decision evaluated: the primary's, or the co-actor's when the co-actor
    /// held it. `None` for every other result.
    pub(crate) approval_digest: Option<String>,
    /// The actor whose decision held this call, when `approval_digest` is
    /// set: the press it names is that actor's (FIX 6424 part 2a).
    pub(crate) approval_actor: Option<EntityId>,
}

impl OutboundEffectResult {
    /// This Gate rejection, naming the approve-once digest `effect`'s press
    /// carries while the Gate holds it, and `effect`'s actor (FIX 6424 part
    /// 2a).
    pub(super) fn held_by(mut self, effect: &ExternalEffectGateInput) -> Self {
        if self.gate_outcome.as_deref() == Some("pending") {
            self.approval_digest = ApprovalTarget::held_digest(effect);
            self.approval_actor = self
                .approval_digest
                .as_ref()
                .and(effect.provenance.actor_entity_ref);
        }
        self
    }

    /// [`Self::held_by`], unless a code consent wait's own code-bound press
    /// decided this hold (DOOR-079 1a): its owner's answer is that press, so
    /// the hold names no generic digest (FIX 6424 part 3).
    pub(super) fn held_by_outside_code_wait(
        self,
        effect: &ExternalEffectGateInput,
        code_wait: bool,
    ) -> Self {
        if code_wait {
            self
        } else {
            self.held_by(effect)
        }
    }
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
    /// A content-free publisher issue signature (OF-420): admission and
    /// every live retry recheck the delivery's custody under the writer.
    PublisherSignature(Box<crate::outbound::PublisherSignatureAuthorization>),
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
        dyn for<'t> FnOnce(&Vault, &mut heed::RwTxn<'t>) -> Result<CoActorEffect, IntentLedgerError>
            + Send,
    >,
}

/// The co-actor's gate input as its binding yields it, with the press its
/// earlier admission of the same mutation spent, which this admission reuses,
/// and where a press this admission spends is kept (FIX 6424 part 2a).
pub(crate) struct CoActorEffect {
    pub(crate) effect: ExternalEffectGateInput,
    pub(crate) kept_press: Option<AdmittedApproval>,
    pub(crate) keep_press: CoActorKeepPress,
}

/// Keeps the press one co-actor admission spent, in the writer it is given.
pub(crate) type CoActorKeepPress = Box<
    dyn for<'t> FnOnce(&Vault, &mut heed::RwTxn<'t>, EffectDigest) -> Result<(), IntentLedgerError>
        + Send,
>;

/// FIX 6424 part 2a: keeps the presses the committed admission of
/// `intent_id` spent, for its retry: the primary's beside its Pending row,
/// the co-actor's where its binding keeps it, each in a writer of its own
/// after that admission committed. A press that does not write is logged and
/// the admission stands (CALLS `FIX 6424 kept press write failure`).
///
/// # Errors
/// None while that call stands; else a keeper's storage failure.
pub(super) fn keep_spent_presses(
    vault: &Vault,
    intent_id: IntentId,
    pinned: Option<PinnedApproval>,
    co_actor: Option<(EffectDigest, CoActorKeepPress)>,
) -> Result<(), IntentLedgerError> {
    let subject = crate::entity_id::bytes_to_hex_lower(&intent_id);
    if pinned.is_some() {
        keep_press_after_admission(vault, &subject, |wtxn| {
            keep_pinned_approval_in_txn(vault, wtxn, pinned)
        })?;
    }
    if let Some((spent, keep)) = co_actor {
        keep_press_after_admission(vault, &subject, |wtxn| keep(vault, wtxn, spent))?;
    }
    Ok(())
}

/// A deterministic count bound on one server and tool. Admission holds the
/// call, never sends it, once the larger of `prior` (the host's own count)
/// and this vault's ledger rows of the last `window_secs` reaches `cap`.
/// It is read in the same writer transaction as the Pending insert, so two
/// admissions cannot both take the last allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionCeiling {
    /// The window's length; admission anchors it (FIX 5992).
    pub(crate) window_secs: u64,
    pub(crate) prior: u32,
    pub(crate) cap: u32,
}

/// FIX 5992: a new capped send's window, and the timestamps of the ledger row
/// it admits, read the vault's clock once under the admission writer, never
/// the caller's `now_ms`. `false` anchors both at the caller's value.
pub(crate) const SEAT_CAP_USES_VAULT_CLOCK: bool = true;

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

    /// The body the last send's transport returned, when it hands one on:
    /// the send's terminal bridge settles a turn program's step with it
    /// (DOOR-141 PR2). The outcome stays the ACK contract above; by default
    /// a transport hands on none.
    fn settled_result(&self) -> Option<&[u8]> {
        None
    }

    /// The remote task handle the last send's provider accepted it as, when
    /// that send came back [`OutboundSendOutcome::Deferred`] (FIX 7960). By
    /// default a transport hands on none.
    fn remote_task(&self) -> Option<crate::outbound_intent_ledger::RemoteTaskHandle> {
        None
    }

    /// The wait the last send's provider asked for when it refused that send
    /// for rate or quota (FIX 8818). By default a transport names none.
    fn provider_wait(&self) -> Option<crate::outbound_intent_ledger::ProviderWait> {
        None
    }

    /// Judges a new call once more under the writer that would record its
    /// gate decision, before any decision is recorded (FIX 6404): a refusal
    /// records none and sends nothing. By default a transport takes every
    /// call.
    /// # Errors
    /// The transport's own refusal, or the failure of its read.
    fn admit_in(&self, _txn: &heed::RoTxn<'_>) -> Result<(), IntentLedgerError> {
        Ok(())
    }
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
