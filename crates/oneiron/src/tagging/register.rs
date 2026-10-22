//! The conversation register a bulk marker reads (FIX 9520, 10167).
//!
//! A live marker reads its turn with the bounded window of earlier text the
//! live register keeps ([`super::input::turn_input_in_txn`]). An import,
//! backfill or any other bulk marker reads the whole conversation as it is
//! stored and readable now: every earlier turn whole, its own turn, then
//! every later turn, each in conversation order with its original ids, each
//! read as the turn's own text is read (visible, non-empty, hydrated
//! messages; a deleted or archived turn reads as nothing). The host's
//! runtime fits that register into its windows; the engine never cuts it.
//!
//! The marker still saves its own turn alone: spans index its own messages,
//! and a context link names an earlier or later turn's message by id and its
//! offsets in that message as sent. Every source enters the input's digest,
//! and a context link is held to its message's text again at settlement, as
//! a live one is.

use std::collections::BTreeSet;

use super::input::{TurnInput, earlier_turns_in_txn, header_key, input_hash, sole_peer};
use crate::conversation_dag::{
    is_thread_record, keeps_dag_topology, record_has_dag_topology, record_kind, retained_parent,
};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::memory::extraction::{EncoderRegister, EncoderTurn};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::vault::{LiveEntityRow, MAX_EDGE_QUERY_RESULTS, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// The turns of a turn's conversation beside its own, in order.
pub(super) struct ConversationRegister {
    /// Every earlier turn, oldest first.
    pub(super) earlier: Vec<EncoderTurn>,
    /// Every later turn, oldest first.
    pub(super) later: Vec<EncoderTurn>,
}

impl ConversationRegister {
    /// The register of `turn`'s conversation, read in `txn`. A turn with no
    /// single conversation, or whose order the readers cannot prove, reads
    /// alone, as the live window does.
    pub(super) fn read_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        turn: &EntityId,
    ) -> Result<Self> {
        let mut earlier = earlier_turns_in_txn(vault, txn, turn, MAX_ANCESTOR_DEPTH)?;
        earlier.reverse();
        let later = later_turns_in_txn(vault, txn, turn)?;
        Ok(Self {
            earlier: register_turns(vault, txn, &earlier)?,
            later: register_turns(vault, txn, &later)?,
        })
    }
}

/// The input a bulk marker's call reads: `turn`'s own text with its whole
/// conversation register, and the digests of both; as
/// [`super::input::turn_input_in_txn`] reads a live one.
pub(super) fn bulk_register_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<TurnInput> {
    let (mut input, text_hash) = match super::input::turn_text_in_txn(vault, txn, turn)? {
        TurnInput::Ready {
            input, text_hash, ..
        } => (input, text_hash),
        other => return Ok(other),
    };
    let register = ConversationRegister::read_in_txn(vault, txn, turn)?;
    input.context = register.earlier;
    input.following = register.later;
    input.register = EncoderRegister::Conversation;
    let hash = input_hash(&input);
    Ok(TurnInput::Ready {
        input,
        hash,
        text_hash,
    })
}

/// Each of `turns` that reads, as the tagger reads a turn's own text.
fn register_turns(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turns: &[EntityId],
) -> Result<Vec<EncoderTurn>> {
    let mut read = Vec::with_capacity(turns.len());
    for turn in turns {
        if let TurnInput::Ready { input, .. } = super::input::turn_text_in_txn(vault, txn, turn)? {
            read.push(EncoderTurn {
                turn: input.turn,
                messages: input.messages,
                speaker: input.speaker,
            });
        }
    }
    Ok(read)
}

/// The turns after `turn` in its conversation, oldest first, by the order
/// [`earlier_turns_in_txn`] reads backwards: down a DAG, the one line of
/// turns whose `Parent` is the one before, up to the first branch (a turn
/// on one branch never reads another); in a conversation that never adopted
/// the DAG, its `ChildOf` turns of a strictly later second. A turn a DAG
/// adoption parented takes only descendants of a strictly later second. A
/// topology the readers refuse, or no single live conversation, reads no
/// later turn.
fn later_turns_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Vec<EntityId>> {
    let store = &vault.store;
    let Ok(parent) = retained_parent(store, txn, turn) else {
        return Ok(Vec::new());
    };
    let record = match live_entity_row_in_txn(store, txn, turn)? {
        LiveEntityRow::Live { body, .. } => !matches!(record_kind(&body), Ok(None)),
        _ => return Ok(Vec::new()),
    };
    if record {
        return descendants_in_txn(vault, txn, turn, None);
    }
    if parent.is_some() {
        let Some((at, _)) = header_key(vault, txn, turn)? else {
            return Ok(Vec::new());
        };
        return descendants_in_txn(vault, txn, turn, Some(at));
    }
    let Some(conversation) = sole_peer(vault, txn, turn, EdgeKind::ChildOf)? else {
        return Ok(Vec::new());
    };
    if !matches!(
        live_entity_row_in_txn(store, txn, &conversation)?,
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_CONVERSATION
    ) || keeps_dag_topology(store, txn, &conversation).unwrap_or(true)
    {
        return Ok(Vec::new());
    }
    let Some((at, _)) = header_key(vault, txn, turn)? else {
        return Ok(Vec::new());
    };
    let mut later = Vec::new();
    for (examined, edge) in store
        .port_edges(
            txn,
            &conversation,
            EdgeDirection::In,
            Some(EdgeKind::ChildOf),
            None,
        )?
        .enumerate()
    {
        if examined >= MAX_EDGE_QUERY_RESULTS {
            return Ok(Vec::new());
        }
        let id = edge?.target;
        let Some(key) = header_key(vault, txn, &id)? else {
            continue;
        };
        if record_has_dag_topology(vault, txn, &id).unwrap_or(true) {
            if is_thread_record(store, txn, &id).unwrap_or(false) {
                continue;
            }
            return Ok(Vec::new());
        }
        // Only a strictly later second proves a turn came after.
        if key.0 > at {
            later.push(key);
        }
    }
    later.sort_unstable();
    later
        .into_iter()
        .map(|(_, id)| EntityId::from_bytes(id))
        .collect()
}

/// The one line of DAG descendants under `turn`, oldest first: each the
/// only record whose `Parent` is the one before, until a branch or a leaf;
/// with `since`, only those of a strictly later second.
fn descendants_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    since: Option<u64>,
) -> Result<Vec<EntityId>> {
    let store = &vault.store;
    let mut walked = BTreeSet::from([*turn]);
    let mut line = Vec::new();
    let mut cursor = *turn;
    for _ in 0..MAX_ANCESTOR_DEPTH {
        let mut children = store.port_edges(
            txn,
            &cursor,
            EdgeDirection::In,
            Some(EdgeKind::Parent),
            None,
        )?;
        let Some(first) = children.next() else {
            break;
        };
        if children.next().is_some() {
            break;
        }
        let child = first?.target;
        if !walked.insert(child) {
            break;
        }
        let later = match since {
            None => true,
            Some(at) => header_key(vault, txn, &child)?.is_some_and(|(second, _)| second > at),
        };
        if later {
            line.push(child);
        }
        cursor = child;
    }
    Ok(line)
}
