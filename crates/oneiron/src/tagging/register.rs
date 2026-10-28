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
//!
//! Each side reads at most [`MAX_REGISTER_TURNS`] turns, the nearest, and
//! never drops one silently (FIX 10705): where a walk stops short of its
//! conversation's end, at that bound or, walking down a DAG, at a branch
//! whose lines it does not choose between, the register says so
//! ([`RegisterReach`]), and the input's digest and the tagger read it.

use std::collections::{BTreeSet, BinaryHeap};

use super::input::{TurnInput, TurnWalk, earlier_walk_in_txn, header_key, input_hash, sole_peer};
use crate::conversation_dag::{
    is_thread_record, keeps_dag_topology, record_has_dag_topology, record_kind, retained_parent,
};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::memory::extraction::{EncoderRegister, EncoderTurn, RegisterReach};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// Turns a conversation register reads on each side of its turn, at most:
/// its own bound, not the ancestor walk's safety cap. Past it the register
/// keeps the nearest and records that it stopped.
pub(super) const MAX_REGISTER_TURNS: usize = 10_000;

/// The turns of a turn's conversation beside its own, in order.
pub(super) struct ConversationRegister {
    /// Every earlier turn, oldest first.
    pub(super) earlier: Vec<EncoderTurn>,
    /// Every later turn, oldest first.
    pub(super) later: Vec<EncoderTurn>,
    /// Where it stops short of the conversation.
    pub(super) reach: RegisterReach,
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
        let mut earlier = earlier_walk_in_txn(vault, txn, turn, MAX_REGISTER_TURNS, None)?;
        earlier.turns.reverse();
        let later = later_turns_in_txn(vault, txn, turn)?;
        let reach = RegisterReach {
            earlier_cut: earlier.cut,
            later_cut: later.cut,
        };
        if !reach.is_whole() {
            tracing::info!(
                turn = %turn.to_hex(),
                earlier_cut = reach.earlier_cut,
                later_cut = reach.later_cut,
                bound = MAX_REGISTER_TURNS,
                "a conversation register stops short of its conversation; the input records where"
            );
        }
        Ok(Self {
            earlier: register_turns(vault, txn, &earlier.turns)?,
            later: register_turns(vault, txn, &later.turns)?,
            reach,
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
    input.register = EncoderRegister::Conversation(register.reach);
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
/// [`earlier_walk_in_txn`] reads backwards: down a DAG, the one line of
/// turns whose `Parent` is the one before, up to the first branch (a turn
/// on one branch never reads another), which the walk records as a stop;
/// in a conversation that never adopted the DAG, its `ChildOf` turns of a
/// strictly later second, every one examined and the nearest
/// [`MAX_REGISTER_TURNS`] kept. A turn a DAG adoption parented takes only
/// descendants of a strictly later second. A topology the readers refuse,
/// or no single live conversation, reads no later turn.
fn later_turns_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, turn: &EntityId) -> Result<TurnWalk> {
    let store = &vault.store;
    let Ok(parent) = retained_parent(store, txn, turn) else {
        return Ok(TurnWalk::default());
    };
    let record = match live_entity_row_in_txn(store, txn, turn)? {
        LiveEntityRow::Live { body, .. } => !matches!(record_kind(&body), Ok(None)),
        _ => return Ok(TurnWalk::default()),
    };
    if record {
        return descendants_in_txn(vault, txn, turn, None);
    }
    if parent.is_some() {
        let Some((at, _)) = header_key(vault, txn, turn)? else {
            return Ok(TurnWalk::default());
        };
        return descendants_in_txn(vault, txn, turn, Some(at));
    }
    let Some(conversation) = sole_peer(vault, txn, turn, EdgeKind::ChildOf)? else {
        return Ok(TurnWalk::default());
    };
    if !matches!(
        live_entity_row_in_txn(store, txn, &conversation)?,
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_CONVERSATION
    ) || keeps_dag_topology(store, txn, &conversation).unwrap_or(true)
    {
        return Ok(TurnWalk::default());
    }
    let Some((at, _)) = header_key(vault, txn, turn)? else {
        return Ok(TurnWalk::default());
    };
    // The nearest later turns, the farthest of them on top.
    let mut nearest: BinaryHeap<(u64, [u8; 16])> = BinaryHeap::new();
    let mut cut = false;
    for edge in store.port_edges(
        txn,
        &conversation,
        EdgeDirection::In,
        Some(EdgeKind::ChildOf),
        None,
    )? {
        let id = edge?.target;
        let Some(key) = header_key(vault, txn, &id)? else {
            continue;
        };
        if record_has_dag_topology(vault, txn, &id).unwrap_or(true) {
            if is_thread_record(store, txn, &id).unwrap_or(false) {
                continue;
            }
            return Ok(TurnWalk::default());
        }
        // Only a strictly later second proves a turn came after.
        if key.0 > at {
            nearest.push(key);
            if nearest.len() > MAX_REGISTER_TURNS {
                nearest.pop();
                cut = true;
            }
        }
    }
    let mut later = nearest.into_vec();
    later.sort_unstable();
    let turns: Vec<EntityId> = later
        .into_iter()
        .map(|(_, id)| EntityId::from_bytes(id))
        .collect::<Result<_>>()?;
    Ok(TurnWalk { turns, cut })
}

/// The one line of DAG descendants under `turn`, oldest first: each the
/// only record whose `Parent` is the one before, until a leaf, a branch or
/// [`MAX_REGISTER_TURNS`] steps, the last two recorded as a stop; with
/// `since`, only those of a strictly later second.
fn descendants_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    since: Option<u64>,
) -> Result<TurnWalk> {
    let store = &vault.store;
    let mut walked = BTreeSet::from([*turn]);
    let mut line = Vec::new();
    let mut cursor = *turn;
    let mut steps = 0;
    loop {
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
        // A branch, whose lines the walk does not choose between, or the
        // bound: the turns past it stay unread, and the walk says so.
        if children.next().is_some() || steps == MAX_REGISTER_TURNS {
            return Ok(TurnWalk {
                turns: line,
                cut: true,
            });
        }
        steps += 1;
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
    Ok(TurnWalk {
        turns: line,
        cut: false,
    })
}
