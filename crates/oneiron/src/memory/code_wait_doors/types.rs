use serde::{Deserialize, Serialize};

use crate::EntityId;

/// Names one code consent wait: the run it parked and the wait itself. The
/// wait id is the one the run's waiting result names, or the hex after
/// `code_consent/` in its ask's intent key. Neither is a capability.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeWaitReceiptRequest {
    pub run_id: EntityId,
    pub wait_id: EntityId,
}

/// The exact sealed wait an answer is for, as `vault.code.waits.receipt`
/// shows it. Every field is checked against the stored wait; a wait whose
/// parked step, generation or held effect differs refuses the answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeWaitTarget {
    pub run_id: EntityId,
    pub wait_id: EntityId,
    /// The wait generation the parked step sealed.
    pub generation: u64,
    /// The parked step's checkpoint hash, 64 lowercase hex.
    pub step_hash: String,
    /// The held effect's code-bound approval digest, 64 lowercase hex.
    pub effect_digest: String,
}

/// The three answers the confirm offers: approve once, approve and stop
/// asking, deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeWaitChoice {
    ApproveOnce,
    ApproveAndStopAsking,
    Deny,
}

/// One answer to one sealed wait, standing on the word the owner gave on
/// the wait's ask. No reply, grant, effect or clock is taken.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeWaitResolveRequest {
    pub target: CodeWaitTarget,
    pub answer: CodeWaitChoice,
    /// The owner's own word on the wait's ask (`tasks.answer`), naming the
    /// same choice.
    pub word_ref: EntityId,
}

/// Where a sealed wait stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeWaitState {
    /// Sealed, with no answer.
    Waiting,
    /// Answered; the effect's own gate has not settled it.
    Settling,
    /// Settled; the parked run has not taken the reply into its replay.
    Settled,
    /// The parked run took the settled reply into its replay, once.
    Consumed,
}

/// What a settled wait came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeWaitSettleOutcome {
    /// The effect ran and its connector acknowledged it.
    Delivered,
    /// Nothing ran, and nothing runs under this wait.
    Refused,
    /// The effect may have reached its connector; it is never sent again.
    DeliveryUnknown,
}

/// The first answer, which every later answer gets back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeWaitAnswerView {
    pub answer: CodeWaitChoice,
    pub word_ref: EntityId,
    /// The consent act's receipt, `gate:<hex>`.
    pub decision_ref: String,
    pub answered_at_ms: u64,
}

/// A receipt's joins as the consent Gate ledger holds them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeWaitLedgerLinks {
    /// The receipt it follows, `gate:<hex>`: a settlement's answer act, or
    /// a consumption's settlement. None for a settlement no one answered.
    pub prior_ref: Option<String>,
    /// The owner's word it names, when one was given.
    pub word_ref: Option<EntityId>,
    /// BLAKE3 of the immutable facts it closes, 64 lowercase hex.
    pub facts_digest: String,
}

/// The settlement: the held effect's actual outcome under its own gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeWaitSettlementView {
    /// The settlement receipt, `gate:<hex>`.
    pub receipt_ref: String,
    pub outcome: CodeWaitSettleOutcome,
    pub reason_codes: Vec<String>,
    pub settled_at_ms: u64,
    /// None once an opted-in retention sweep dropped the ledger record.
    pub ledger: Option<CodeWaitLedgerLinks>,
}

/// The parked run's consumption of the settled reply into its replay. It
/// is scoped to the original run: reading it here enters no run and reads
/// no result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeWaitConsumptionView {
    /// The consumption receipt, `gate:<hex>`.
    pub receipt_ref: String,
    /// The parked step's checkpoint index.
    pub step: u64,
    /// The path in the run's record the reply was bound at.
    pub resumed_path: String,
    /// The resumed result's handle in the run.
    pub result_handle: String,
    pub consumed_at_ms: u64,
    /// None once an opted-in retention sweep dropped the ledger record.
    pub ledger: Option<CodeWaitLedgerLinks>,
}

/// One sealed code consent wait with its answer, settlement and replay
/// consumption, each a separate fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeWaitReceiptView {
    /// The exact target an answer names.
    pub target: CodeWaitTarget,
    pub state: CodeWaitState,
    /// The verb row the held effect is.
    pub verb: String,
    /// The catalog name and tool of the held connector call.
    pub connector: String,
    pub tool: String,
    /// The hold the effect's own gate reported.
    pub hold_reasons: Vec<String>,
    /// The ask an answer's word stands on, once it is open.
    pub ask_ref: Option<EntityId>,
    /// The answers this wait offers.
    pub allowed_answers: Vec<CodeWaitChoice>,
    pub answer: Option<CodeWaitAnswerView>,
    pub settlement: Option<CodeWaitSettlementView>,
    pub consumption: Option<CodeWaitConsumptionView>,
    /// This answer was not the first: the view is the first answer's.
    pub already_answered: bool,
}
