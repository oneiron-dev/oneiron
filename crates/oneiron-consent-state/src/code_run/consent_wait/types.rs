//! Moved from `crates/oneiron/src/code_run/consent_wait/types.rs` (core split slice 2: consent state below core).
//! `oneiron` re-exports each item at its old path.

use crate::consent::code_wait_state::CodeConsentChoice;
use crate::consent::code_wait_state::CodeConsentSettleOutcome;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::gate_decision::types::GateDecisionId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The held connector call one wait binds (the first adapter).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentConnectorCall {
    pub call_ref: EntityId,
    pub attempt_id: [u8; 16],
    pub call_seq: u64,
    pub grant_ref: EntityId,
    pub key_ref: EntityId,
    /// The catalog name the guest called.
    pub name: String,
    pub server: String,
    pub tool: String,
    pub endpoint: String,
    pub payload_data_class: crate::consent::tool_scope::DataClass,
    pub remember_context: Option<crate::connector_key::tool_remember::ConnectorToolRememberContext>,
    pub manifest_hash: [u8; 32],
    pub protocol_revision: String,
    /// A `self.use` custody record's ref, never its value.
    pub credential_record: Option<EntityId>,
}

/// The tool-setting act an "approve and stop asking" answer remembers.
/// Actor, connector and tool come from the same immutable call binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentRememberOffer {
    pub settings_act: EntityId,
}

/// The question the wait's ask carries: who is asked, and the ids the
/// opener witnesses it under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentQuestion {
    pub owners: BTreeSet<EntityId>,
    pub conversation: EntityId,
    pub turn: EntityId,
    pub message: EntityId,
    pub at: u64,
}

/// The parked step's seal (1b writes it from the executor's commit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentCheckpoint {
    pub wait_generation: u64,
    pub step_hash: [u8; 32],
    pub bridge_call_count: u64,
    pub step_checkpoint_count: u64,
    pub output_count: u64,
    pub last_state_hash: [u8; 32],
}

/// The holder's grant and policy basis; identity stays in the answer stamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentHolderAnswerBasis {
    pub grant_ref: String,
    pub policy: crate::gate::code_consent_settlement::ResolvedCodeConsentSettlement,
}

/// The first authenticated answer. Kept once: a later answer drops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentAnswerStamp {
    pub choice: CodeConsentChoice,
    /// Whether the first answer explicitly asked for the asking-lineage scope.
    /// True only for an explicit stop-asking choice; default false.
    pub remember_asking_lineage: bool,
    pub word_ref: EntityId,
    pub answerer: EntityId,
    pub principal_ref: String,
    /// The authentication the person answered under.
    pub authentication: GateDecisionId,
    /// The consent act's own receipt: approve-once or denied.
    pub decision: GateDecisionId,
    /// The native standing consent grant the stop-asking answer minted.
    pub remembered: Option<String>,
    /// The explicit standing offer's grant and its separate creation receipt.
    pub standing_grant: Option<(String, GateDecisionId)>,
    /// The policy manifest frontier the answer was judged under.
    pub policy_frontier: [u8; 32],
    /// Present only for an act admitted by the frozen holder settlement policy.
    pub holder_basis: Option<CodeConsentHolderAnswerBasis>,
    pub answered_at_ms: u64,
}

/// The effect's own gate admitted it under the answer, in the same writer
/// as the ledger's Pending insert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentAdmission {
    pub intent_id: [u8; 32],
    pub gate_decision: GateDecisionId,
    pub admitted_at_ms: u64,
}

/// What the effect came to, with the receipt that closes the wait and the
/// digest of the reply delivered to the parked run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentSettlement {
    pub receipt: GateDecisionId,
    pub outcome: CodeConsentSettleOutcome,
    pub reason_codes: Vec<String>,
    pub reply_digest: [u8; 32],
    /// The actual delivered connector reply carried a foreign result or
    /// questions, after the side-row wall. Delivery without a result is false.
    pub external_reply: bool,
    pub settled_at_ms: u64,
}

/// The parked run's consumption of the settled reply (1b): written once, by
/// the replay commit that binds the reply as the run's result, and never
/// cleared. The result it names does not carry it, so the result's digest
/// never feeds its own receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentConsumption {
    /// The consumption receipt in the consent Gate family.
    pub receipt: GateDecisionId,
    /// The settlement receipt it consumed, and the digest of the reply that
    /// settlement delivered.
    pub settlement_receipt: GateDecisionId,
    pub reply_digest: [u8; 32],
    /// The parked step's checkpoint index and hash, and the wait generation
    /// the run resumed from.
    pub step_seq: u64,
    pub step_hash: [u8; 32],
    pub wait_generation: u64,
    /// The resumed result: its path in the run's record, its handle and its
    /// body's BLAKE3.
    pub resumed_path: String,
    pub result_handle: String,
    pub result_digest: [u8; 32],
    pub consumed_at_ms: u64,
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
    /// Whether the owner explicitly asked for the asking-lineage remember scope.
    /// Explicit choice only; default false. Normalized to false unless
    /// `choice` is approve-and-stop-asking.
    pub remember_asking_lineage: bool,
    /// The owner's own word on the wait's ask, naming the same choice.
    pub word_ref: EntityId,
}
