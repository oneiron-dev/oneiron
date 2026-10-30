//! The shapes of one bound code consent wait: the host-only call site the
//! dispatcher carries, the control row the engine keeps, and what a host
//! reads and sends.

use serde::{Deserialize, Serialize};

use crate::authority::InvocationSlipBinding;
use crate::consent::CodeWaitReceiptLinks;
use crate::entity_id::EntityId;
use crate::runtime_hooks::verb::{VerbAskDoor, VerbAskInstrument, VerbHookPreSnapshot};
use crate::store::GateDecisionId;

/// The binding row's schema version.
pub(super) const CODE_CONSENT_SCHEMA_VERSION: u32 = 1;

/// The three answers canon's confirm offers (DEC-0006): approve once (the
/// default), approve and stop asking, deny (CALLS: outcome names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeConsentChoice {
    ApproveOnce,
    ApproveAndStopAsking,
    Deny,
}

impl CodeConsentChoice {
    /// Every choice, in the order the wait's ask offers them.
    pub(crate) const ALL: [Self; 3] = [Self::ApproveOnce, Self::ApproveAndStopAsking, Self::Deny];

    /// The stable word, which is also the option id the wait's ask offers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApproveOnce => "approve_once",
            Self::ApproveAndStopAsking => "approve_and_stop_asking",
            Self::Deny => "deny",
        }
    }

    /// The choice an ask option id names, if any.
    #[must_use]
    pub fn from_option(option: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|choice| choice.as_str() == option)
    }

    /// Whether the choice lets the effect go to its own gate.
    pub(crate) const fn approves(self) -> bool {
        !matches!(self, Self::Deny)
    }
}

/// What one settled code consent wait came to (CALLS: outcome names). A
/// settlement is its own fact: it is not the answer, and it is not the
/// run's consumption of the reply, which 1b records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeConsentSettleOutcome {
    /// The effect ran and its connector acknowledged it.
    Delivered,
    /// Nothing ran, and nothing runs under this wait.
    Refused,
    /// The effect may have reached its connector; the ledger never sends it
    /// again, and it is never reported as delivered.
    DeliveryUnknown,
}

impl CodeConsentSettleOutcome {
    /// The stable word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Refused => "refused",
            Self::DeliveryUnknown => "delivery_unknown",
        }
    }

    /// The one-byte tag the settlement receipt carries.
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Delivered => 1,
            Self::Refused => 2,
            Self::DeliveryUnknown => 3,
        }
    }

    /// The outcome a settlement receipt's tag names, if any.
    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        [Self::Delivered, Self::Refused, Self::DeliveryUnknown]
            .into_iter()
            .find(|outcome| outcome.tag() == tag)
    }
}

/// Where one code consent wait stands, derived from the row's facts and
/// never stored on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeConsentWaitState {
    /// Minted with its held effect; its parked step has not sealed it, so no
    /// answer reaches it.
    Provisional,
    /// Sealed, with no answer.
    Waiting,
    /// Answered; the effect's own gate has not settled it.
    Settling,
    /// Settled: delivered, refused or of unknown delivery. The parked run
    /// has not taken the reply into its replay yet.
    Settled,
    /// The parked run took the settled reply into its replay, once (1b).
    Consumed,
}

/// Where one code-mode connector call sits in its durable run. The
/// dispatcher builds it from the executor's own bridge position and
/// carries it on the host-owned write origin; no guest field reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeConsentCallSite {
    pub(crate) wait_id: EntityId,
    pub(crate) run_id: EntityId,
    pub(crate) run_ref: String,
    pub(crate) step_start: u64,
    pub(crate) bridge_seq: u64,
    pub(crate) write_ordinal: u64,
    pub(crate) write_receipt_id: EntityId,
    /// BLAKE3 of the call's canonical identity (verb and sorted input).
    pub(crate) request_digest: [u8; 32],
}

/// The instrument a code run's caller was admitted on, kept with its wait:
/// a reference and its witness, never a secret, and no authority on its
/// own. Every judgment verifies the witness again at its own snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentSavedCredential {
    /// The exact instrument, when the host bound one.
    pub instrument: Option<VerbAskInstrument>,
    /// The door the caller came in by, when the host bound one.
    pub door: Option<VerbAskDoor>,
    /// The signed slip the request was admitted on.
    pub witness: InvocationSlipBinding,
}

/// The original caller of a held effect, as its admitted surface bound it.
/// A caller with no credential (an embedded or host surface) keeps none:
/// its grant alone limits the settle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentPrincipal {
    pub(crate) actor_ref: EntityId,
    pub(crate) credential: Option<CodeConsentSavedCredential>,
    /// The slip the opener's request was admitted on, read from the verified
    /// witness at the mint: an answer from that slip, or from one minted
    /// directly under it, is the opener's own lineage.
    pub(crate) opener_slip: Option<[u8; 32]>,
}

/// The held connector call one wait binds (the first adapter).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentConnectorCall {
    pub(crate) call_ref: EntityId,
    pub(crate) attempt_id: [u8; 16],
    pub(crate) call_seq: u64,
    pub(crate) grant_ref: EntityId,
    pub(crate) key_ref: EntityId,
    /// The catalog name the guest called.
    pub(crate) name: String,
    pub(crate) server: String,
    pub(crate) tool: String,
    pub(crate) endpoint: String,
    pub(crate) manifest_hash: [u8; 32],
    pub(crate) protocol_revision: String,
    /// A `self.use` custody record's ref, never its value.
    pub(crate) credential_record: Option<EntityId>,
}

/// The browser act a press held, as its run's session froze it (FIX
/// 10423): the act and its own input, the row it resolved to, the page, tab,
/// document and guest it ran in, and why its grant gave no press. It keeps
/// the call's answer as the held act found it, which the run resumes with
/// when the act does not run: a batch's answer at its stop, whose completed
/// steps and receipts stand, or the page a lone act began on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentBrowserAction {
    /// The verb row of the held act: `self.browser.click` or
    /// `self.browser.click_at`.
    pub act: String,
    /// The act's own input, as JSON text: the settle runs these operands
    /// only.
    pub operands: String,
    /// The effect class the row's name marks on its page.
    pub class: String,
    /// The row the act resolved to: its role, name and locator.
    pub role: String,
    pub name: String,
    pub locator: String,
    /// The page the act began on.
    pub page: Option<String>,
    /// The tab in front when the act began.
    pub tab: String,
    /// The documents the row's live handle was read from; none for a row no
    /// handle names.
    pub document: Option<String>,
    /// The browser guest the act ran in, by its manifest's generation.
    pub session: String,
    /// Why the grant gave no press: `per_send`, or `batch_spent` for a
    /// reviewed batch whose sends were spent.
    pub need: String,
    /// The call's answer as the held act found it, as JSON text: a batch's
    /// answer at its stop, or the page a lone act began on.
    pub stopped: Option<String>,
    /// The outer call's verb-hook pre state, kept at hold time (FIX
    /// 11497), so the answered pass runs the post hooks the first pass
    /// never reached; none for a call no hook chain ran for.
    pub hook_pre: Option<VerbHookPreSnapshot>,
}

/// The pending effect a wait binds. Each effect kind is its own typed
/// adapter at its own gate: a held connector call (1a), or a browser act a
/// press held (FIX 10423).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CodeConsentPendingEffect {
    ConnectorCall(CodeConsentConnectorCall),
    BrowserAction(CodeConsentBrowserAction),
}

impl CodeConsentPendingEffect {
    /// The held connector call, when the effect is one.
    pub(crate) const fn connector_call(&self) -> Option<&CodeConsentConnectorCall> {
        match self {
            Self::ConnectorCall(call) => Some(call),
            Self::BrowserAction(_) => None,
        }
    }

    /// The held browser act, when the effect is one.
    pub(crate) const fn browser_action(&self) -> Option<&CodeConsentBrowserAction> {
        match self {
            Self::BrowserAction(action) => Some(action),
            Self::ConnectorCall(_) => None,
        }
    }
}

/// The capability setting an "approve and stop asking" answer changes: one
/// tool's row on the slate its governing key meets, at the revision the
/// offer was made against (CALLS: stop-asking for connector.call).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentRememberOffer {
    pub(crate) slate_ref: EntityId,
    pub(crate) slate_revision: u64,
    pub(crate) tool: String,
}

/// The question the wait's ask carries: who is asked, and the ids the
/// opener witnesses it under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentQuestion {
    pub(crate) owner: EntityId,
    pub(crate) conversation: EntityId,
    pub(crate) turn: EntityId,
    pub(crate) message: EntityId,
    pub(crate) at: u64,
}

/// The immutable binding a wait is minted with, beside its held effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentBinding {
    pub(crate) schema_version: u32,
    pub(crate) wait_id: EntityId,
    pub(crate) run_id: EntityId,
    pub(crate) run_ref: String,
    pub(crate) step_start: u64,
    pub(crate) bridge_seq: u64,
    pub(crate) write_ordinal: u64,
    pub(crate) write_receipt_id: EntityId,
    pub(crate) verb_row: String,
    pub(crate) request_digest: [u8; 32],
    /// BLAKE3 of the frozen bytes the held pass prepared: the settle sends
    /// only these bytes.
    pub(crate) frozen_input_digest: [u8; 32],
    /// BLAKE3 over every stable fact above and the pending effect, never
    /// over the effect digest, the ask, a time or a receipt.
    pub(crate) binding_digest: [u8; 32],
    /// The code-bound approval digest the effect's own gate looks up.
    pub(crate) effect_digest: [u8; 32],
    pub(crate) original: CodeConsentPrincipal,
    pub(crate) pending: CodeConsentPendingEffect,
    pub(crate) hold_reasons: Vec<String>,
    pub(crate) remember_offer: Option<CodeConsentRememberOffer>,
    pub(crate) question: CodeConsentQuestion,
    /// The policy manifest frontier the hold was decided under.
    pub(crate) policy_frontier: [u8; 32],
    pub(crate) created_at_ms: u64,
}

/// The parked step's seal (1b writes it from the executor's commit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentCheckpoint {
    pub(crate) wait_generation: u64,
    pub(crate) step_hash: [u8; 32],
    pub(crate) bridge_call_count: u64,
    pub(crate) step_checkpoint_count: u64,
    pub(crate) output_count: u64,
    pub(crate) last_state_hash: [u8; 32],
}

/// The first authenticated answer. Kept once: a later answer drops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentAnswerStamp {
    pub(crate) choice: CodeConsentChoice,
    pub(crate) word_ref: EntityId,
    pub(crate) answerer: EntityId,
    pub(crate) principal_ref: String,
    /// The authentication the owner answered under.
    pub(crate) authentication: GateDecisionId,
    /// The consent act's own receipt: approve-once or denied.
    pub(crate) decision: GateDecisionId,
    /// The slate a stop-asking answer changed, at its new revision.
    pub(crate) remembered: Option<(EntityId, u64)>,
    /// The policy manifest frontier the answer was judged under. The owner
    /// gate decided it; no settlement-policy row is named (CALLS).
    pub(crate) policy_frontier: [u8; 32],
    pub(crate) answered_at_ms: u64,
}

/// The effect's own gate admitted it under the answer, in the same writer
/// as the ledger's Pending insert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentAdmission {
    pub(crate) intent_id: [u8; 32],
    pub(crate) gate_decision: GateDecisionId,
    pub(crate) admitted_at_ms: u64,
}

/// What the effect came to, with the receipt that closes the wait and the
/// digest of the reply delivered to the parked run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentSettlement {
    pub(crate) receipt: GateDecisionId,
    pub(crate) outcome: CodeConsentSettleOutcome,
    pub(crate) reason_codes: Vec<String>,
    pub(crate) reply_digest: [u8; 32],
    pub(crate) settled_at_ms: u64,
}

/// The parked run's consumption of the settled reply (1b): written once, by
/// the replay commit that binds the reply as the run's result, and never
/// cleared. The result it names does not carry it, so the result's digest
/// never feeds its own receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentConsumption {
    /// The consumption receipt in the consent Gate family.
    pub(crate) receipt: GateDecisionId,
    /// The settlement receipt it consumed, and the digest of the reply that
    /// settlement delivered.
    pub(crate) settlement_receipt: GateDecisionId,
    pub(crate) reply_digest: [u8; 32],
    /// The parked step's checkpoint index and hash, and the wait generation
    /// the run resumed from.
    pub(crate) step_seq: u64,
    pub(crate) step_hash: [u8; 32],
    pub(crate) wait_generation: u64,
    /// The resumed result: its path in the run's record, its handle and its
    /// body's BLAKE3.
    pub(crate) resumed_path: String,
    pub(crate) result_handle: String,
    pub(crate) result_digest: [u8; 32],
    pub(crate) consumed_at_ms: u64,
}

/// One code consent wait's control row. Status is derived from which facts
/// are present; only the owning module writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CodeConsentWaitRow {
    pub(crate) binding: CodeConsentBinding,
    #[serde(default)]
    pub(crate) ask: Option<EntityId>,
    #[serde(default)]
    pub(crate) checkpoint: Option<CodeConsentCheckpoint>,
    #[serde(default)]
    pub(crate) answer: Option<CodeConsentAnswerStamp>,
    #[serde(default)]
    pub(crate) admission: Option<CodeConsentAdmission>,
    #[serde(default)]
    pub(crate) settlement: Option<CodeConsentSettlement>,
    #[serde(default)]
    pub(crate) consumption: Option<CodeConsentConsumption>,
    pub(crate) revision: u64,
}

impl CodeConsentWaitRow {
    /// Where the wait stands.
    pub(crate) const fn state(&self) -> CodeConsentWaitState {
        if self.consumption.is_some() {
            CodeConsentWaitState::Consumed
        } else if self.settlement.is_some() {
            CodeConsentWaitState::Settled
        } else if self.answer.is_some() {
            CodeConsentWaitState::Settling
        } else if self.checkpoint.is_some() {
            CodeConsentWaitState::Waiting
        } else {
            CodeConsentWaitState::Provisional
        }
    }

    /// Whether the first answer approved and the wait has not settled.
    pub(crate) fn approved_unsettled(&self) -> bool {
        self.settlement.is_none()
            && self
                .answer
                .as_ref()
                .is_some_and(|answer| answer.choice.approves())
    }
}

/// One owner's answer to one sealed wait. The key is the sealed run, wait,
/// generation and step hash with the binding's effect digest, never a key a
/// client chose (CALLS: idempotency key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeConsentAnswerInput {
    pub run_id: EntityId,
    pub wait_id: EntityId,
    pub wait_generation: u64,
    pub step_hash: [u8; 32],
    pub effect_digest: [u8; 32],
    pub choice: CodeConsentChoice,
    /// The owner's own word on the wait's ask, naming the same choice.
    pub word_ref: EntityId,
}

/// One code consent wait as an owner reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeConsentWaitView {
    pub wait_id: EntityId,
    pub run_id: EntityId,
    pub state: CodeConsentWaitState,
    /// The verb row the held effect is.
    pub verb: String,
    /// The catalog name and tool of the held connector call; empty for a
    /// held browser act, which `browser` names.
    pub connector: String,
    pub tool: String,
    /// The held browser act (FIX 10423), when the effect is one.
    pub browser: Option<CodeConsentBrowserAction>,
    /// The code-bound approval digest an answer names.
    pub effect_digest: [u8; 32],
    /// The hold the effect's gate reported.
    pub hold_reasons: Vec<String>,
    /// The ask an answer's word stands on, once it is open.
    pub ask: Option<EntityId>,
    /// The choices this wait offers.
    pub options: Vec<CodeConsentChoice>,
    /// The sealed parked step: its wait generation and step hash.
    pub sealed: Option<(u64, [u8; 32])>,
    pub answer: Option<CodeConsentChoice>,
    pub word_ref: Option<EntityId>,
    /// The consent act's receipt, `gate:<hex>`.
    pub answer_receipt: Option<String>,
    pub outcome: Option<CodeConsentSettleOutcome>,
    /// The settlement receipt, `gate:<hex>`.
    pub settlement_receipt: Option<String>,
    /// The parked run's consumption receipt, `gate:<hex>`, once its replay
    /// took the settled reply. A settled wait may show none yet.
    pub consumption_receipt: Option<String>,
    /// Why the settlement came out so.
    pub reasons: Vec<String>,
    /// When the first answer was recorded, in unix ms.
    pub answered_at_ms: Option<u64>,
    /// When the wait settled, in unix ms.
    pub settled_at_ms: Option<u64>,
    /// The settlement receipt's links as the consent Gate ledger holds them:
    /// the word, the answer act it follows and its facts digest. `None`
    /// before it settled, or once an opted-in retention sweep dropped it.
    pub settlement_links: Option<CodeWaitReceiptLinks>,
    /// The consumption (1b): the parked step's checkpoint index, the path in
    /// the run's record the reply was bound at, that result's handle, and
    /// when, in unix ms.
    pub consumed_step: Option<u64>,
    pub resumed_path: Option<String>,
    pub result_handle: Option<String>,
    pub consumed_at_ms: Option<u64>,
    /// The consumption receipt's links as the ledger holds them: the word
    /// and the settlement it consumed.
    pub consumption_links: Option<CodeWaitReceiptLinks>,
    /// This answer was not the first: the view is the first answer's.
    pub already_answered: bool,
}
