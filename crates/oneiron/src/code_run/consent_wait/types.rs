//! The shapes of one bound code consent wait: the host-only call site the
//! dispatcher carries, the control row the engine keeps, and what a host
//! reads and sends.

use serde::{Deserialize, Serialize};

use crate::authority::InvocationSlipBinding;
use crate::consent::CodeWaitReceiptLinks;
use crate::entity_id::EntityId;
use crate::runtime_hooks::verb::{VerbAskDoor, VerbAskInstrument, VerbHookPreSnapshot};

use super::rebind_types::{CodeConsentRebind, CodeConsentRebindProposal};
use super::resume::{CodeConsentResumeRefusal, CodeConsentRunOrigin};

/// The binding row's schema version.
pub(super) const CODE_CONSENT_SCHEMA_VERSION: u32 = 8;

pub(crate) use crate::consent::code_wait_state::CodeConsentCallSite;
pub use crate::consent::code_wait_state::{
    CodeConsentChoice, CodeConsentSettleOutcome, CodeConsentWaitState,
};

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
    /// The original caller's actor class, as its admitted surface bound it
    /// (FIX 4520): a typed-ask retry rebinds this exact class, never a
    /// guess. The class enum has no serde form, so the row keeps the
    /// canonical byte.
    pub(crate) actor_class: u8,
    pub(crate) credential: Option<CodeConsentSavedCredential>,
    /// The slip the opener's request was admitted on, read from the verified
    /// witness at the mint: an answer from that slip, or from one minted
    /// directly under it, is the opener's own lineage.
    pub(crate) opener_slip: Option<[u8; 32]>,
}

#[doc(hidden)]
pub use oneiron_consent_state::code_run::consent_wait::types::CodeConsentAnswerInput;
#[doc(hidden)]
pub(crate) use oneiron_consent_state::code_run::consent_wait::types::{
    CodeConsentAdmission, CodeConsentAnswerStamp, CodeConsentCheckpoint, CodeConsentConnectorCall,
    CodeConsentConsumption, CodeConsentHolderAnswerBasis, CodeConsentQuestion,
    CodeConsentRememberOffer, CodeConsentSettlement,
};

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
    /// The counterparty the act's send reported (FIX 11907, 12395): the
    /// page origin, or a mailto:/tel: href's normalized scheme+recipient;
    /// none where it names none (a desktop's).
    pub audience: Option<String>,
    /// The hold-time actor class byte (FIX 11908), decoded by
    /// `EdgeActorClass::try_from_u8`: the engine stamps it at the hold from
    /// its own caller, so a host-built action's value never stands.
    #[serde(default)]
    pub actor_class: u8,
    /// The project the hold-time facts named (FIX 11908), stamped by the
    /// engine at the hold like `actor_class`.
    #[serde(default)]
    pub project: Option<EntityId>,
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
    /// The hold-time policy, action requirement and candidates, not authority.
    pub(crate) holder_settlement:
        Option<crate::consent::code_settlement::FrozenCodeConsentSettlement>,
    /// BLAKE3 over every stable fact above and the pending effect, never
    /// over the effect digest, the ask, a time or a receipt.
    pub(crate) binding_digest: [u8; 32],
    /// The code-bound approval digest the effect's own gate looks up.
    pub(crate) effect_digest: [u8; 32],
    pub(crate) original: CodeConsentPrincipal,
    pub(crate) pending: CodeConsentPendingEffect,
    pub(crate) hold_reasons: Vec<String>,
    pub(crate) remember_offer: Option<CodeConsentRememberOffer>,
    pub(crate) standing_offer: Option<super::CodeConsentStandingOffer>,
    pub(crate) question: CodeConsentQuestion,
    /// The policy manifest frontier the hold was decided under.
    pub(crate) policy_frontier: [u8; 32],
    pub(crate) created_at_ms: u64,
    /// The admitted MCP caller the run can be entered again for once the
    /// reply is delivered (FIX 4606), as its host bound it on the run;
    /// `None` for a run no MCP host bound one on.
    pub(crate) origin: Option<CodeConsentRunOrigin>,
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
    /// Why its host refused the run's automatic re-entry for good (FIX
    /// 4606): written once, apart from the answer, the settlement and the
    /// consumption, and never cleared.
    #[serde(default)]
    pub(crate) resume_refusal: Option<CodeConsentResumeRefusal>,
    pub(crate) revision: u64,
    pub(crate) rebind_proposal: Option<CodeConsentRebindProposal>,
    pub(crate) rebinds: Vec<CodeConsentRebind>,
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

/// One code consent wait as an owner reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeConsentWaitView {
    pub wait_id: EntityId,
    pub run_id: EntityId,
    pub state: CodeConsentWaitState,
    pub revision: u64,
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
    /// The exact server-wide standing scope offered, not authority by itself.
    pub standing_offer: Option<super::CodeConsentStandingOffer>,
    /// The sealed parked step: its wait generation and step hash.
    pub sealed: Option<(u64, [u8; 32])>,
    pub answer: Option<CodeConsentChoice>,
    pub word_ref: Option<EntityId>,
    /// The consent act's receipt, `gate:<hex>`.
    pub answer_receipt: Option<String>,
    /// The standing grant actually minted by the first answer, when any.
    pub standing_grant_ref: Option<String>,
    /// Its own creation receipt, separate from the one-shot approval.
    pub standing_receipt_ref: Option<String>,
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
    /// The first answer's actual asking-lineage scope, only for a stop-asking
    /// choice; none before an answer or for other choices.
    pub remember_asking_lineage: Option<bool>,
    /// The first answer's minted standing grant ref, when it minted one.
    pub remembered: Option<String>,
    /// This answer was not the first: the view is the first answer's.
    pub already_answered: bool,
    pub(crate) rebind_proposal: Option<CodeConsentRebindProposal>,
    pub(crate) rebinds: Vec<CodeConsentRebind>,
}
