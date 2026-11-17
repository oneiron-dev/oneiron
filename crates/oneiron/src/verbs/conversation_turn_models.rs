//! `vault.conversations.turns.models` (UNBUILT3-41, FIX
//! THREAD-PROVENANCE-READ; RULED THREAD-PROVENANCE-READER = C): which model
//! answered each turn of a thread, so a reader can mark where the model
//! changed.
//!
//! The caller lists the thread's TURNs in the order it shows them. Each turn
//! answers with the calls linked to its saved reply MESSAGEs
//! (TURN-MODEL-LINK): each call's model id and provider, and nothing of its
//! route, login, credential or seat, which stay the owner's. A turn the
//! caller reads is the only grant: a turn it cannot read, an absent one and
//! a ref that names no TURN all answer `withheld`, so the rest still answer
//! and no answer tells an unreadable turn from a missing one. A readable turn
//! with no linked call answers `unknown`: a reply captured before the link
//! existed, one off the record, or a turn no model answered.

use serde::{Deserialize, Serialize};

use crate::claim::{ClaimReadStatus, ScopedReadResult};
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult, resolve_entity_ref};
use crate::registry::ENTITY_TYPE_TURN;

/// The most TURNs one call reads.
pub const CONVERSATION_TURN_MODELS_MAX_TURNS: usize = 256;

/// `vault.conversations.turns.models`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConversationTurnModelsRequest {
    /// The thread's TURN refs (short refs or 32-hex ids), in the order the
    /// answer keeps; at most 256.
    pub turn_refs: Vec<String>,
}

/// `vault.conversations.turns.models`'s answer: one entry per requested ref,
/// in request order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConversationTurnModelsView {
    pub turns: Vec<TurnModelsView>,
}

/// What one requested turn answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TurnModelsView {
    /// The ref as the caller gave it.
    pub turn_ref: String,
    pub state: TurnModelsState,
    /// The calls that answered into the turn's readable reply MESSAGEs, in
    /// message order and, within one message, in call order. Empty unless
    /// `state` is `answered`.
    pub calls: Vec<TurnModelCallView>,
}

/// Whether a turn names the models that answered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TurnModelsState {
    /// At least one call is linked to a reply of the turn.
    Answered,
    /// The caller reads the turn, but no call is linked to a reply it reads.
    Unknown,
    /// No turn the caller reads: unreadable, absent, or no TURN.
    Withheld,
}

/// One call that answered into a reply of the turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TurnModelCallView {
    /// The saved reply MESSAGE the call answered into, as 32-hex.
    pub message_ref: String,
    /// The model the call ran, `provider/name@revision`.
    pub model: String,
    /// The provider segment of `model`.
    pub provider: String,
}

/// `vault.conversations.turns.models`: each listed turn's answering models,
/// read on the caller's recorded lane in one snapshot. A malformed ref list
/// (more than [`CONVERSATION_TURN_MODELS_MAX_TURNS`]) is a bad request; a ref
/// that does not resolve answers `withheld`.
pub fn conversation_turn_models(
    memory: &Memory<'_>,
    input: ConversationTurnModelsRequest,
) -> MemoryResult<ScopedReadResult<ConversationTurnModelsView>> {
    if input.turn_refs.len() > CONVERSATION_TURN_MODELS_MAX_TURNS {
        return Err(MemoryError::bad_request(
            "vault.conversations.turns.models reads at most 256 turns",
        ));
    }
    let vault = memory.vault();
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let mut resolved = Vec::with_capacity(input.turn_refs.len());
    for reference in &input.turn_refs {
        let turn = match resolve_entity_ref(vault, reference) {
            Ok(turn) => Some(turn),
            Err(error) if error.code == MEMORY_CODE_NOT_FOUND => None,
            Err(error) => return Err(error),
        };
        resolved.push(turn);
    }
    let turns = lane.with_grant_read_snapshot(|txn| -> MemoryResult<_> {
        let policy = lane.live_policy_manifest_in(txn)?;
        let readable = |id: &EntityId| lane.is_entity_readable_with_policy_in(txn, &policy, id);
        let mut turns = Vec::with_capacity(resolved.len());
        for (reference, turn) in input.turn_refs.iter().zip(&resolved) {
            let mut view = TurnModelsView {
                turn_ref: reference.clone(),
                state: TurnModelsState::Withheld,
                calls: Vec::new(),
            };
            let Some(turn) = turn else {
                turns.push(view);
                continue;
            };
            if vault.get_entity_type_in_txn(txn, turn)? != Some(ENTITY_TYPE_TURN)
                || !readable(turn)?
            {
                turns.push(view);
                continue;
            }
            let Some(members) =
                crate::tagging::turn_members_in_txn(vault, &vault.store, txn, turn, false)?
            else {
                turns.push(view);
                continue;
            };
            memory.produced_from([*turn]);
            for (message, _, _) in members {
                if !readable(&message)? {
                    continue;
                }
                let calls = crate::code_run::model_call::model_calls_for_reply_in_txn(
                    vault, txn, &message,
                )?;
                if !calls.is_empty() {
                    memory.produced_from([message]);
                }
                view.calls
                    .extend(calls.into_iter().map(|call| TurnModelCallView {
                        message_ref: message.to_hex(),
                        provider: call.rung.model.provider().to_owned(),
                        model: call.rung.model.as_str().to_owned(),
                    }));
            }
            view.state = if view.calls.is_empty() {
                TurnModelsState::Unknown
            } else {
                TurnModelsState::Answered
            };
            turns.push(view);
        }
        Ok(turns)
    })?;
    let receipt = lane.read_receipt(None, 0)?;
    Ok(ScopedReadResult {
        value: ConversationTurnModelsView { turns },
        receipt,
    })
}
