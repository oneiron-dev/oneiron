//! The tagger's input for one turn: the turn's MESSAGE rows, and the live
//! register's bounded window of earlier text in the same conversation.

use serde::Deserialize;

use crate::edge::EdgeKind;
use crate::error::Result;
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::memory::extraction::{EncoderInput, EncoderMessage, EncoderTurn};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// Characters of earlier text the window carries per tagger token. The engine
/// cannot count the tagger's tokens, so it over-sends: no token of the
/// serving tokenizer spans more characters than this in practice, so the
/// window holds the runtime's K tokens whenever the conversation has them,
/// and the runtime cuts it to K exactly.
const WINDOW_CHARS_PER_TOKEN: usize = 16;

/// What a marker's turn reads as now.
pub(super) enum TurnInput {
    /// The turn is absent, deleted or archived: nothing is owed.
    Gone,
    /// The turn holds no visible text.
    Empty,
    /// The input the tagger reads, and its digest.
    Ready { input: EncoderInput, hash: String },
}

/// The three MESSAGE-body keys the input needs; every other key is ignored.
#[derive(Deserialize)]
struct MessageText {
    #[serde(default)]
    content: String,
    #[serde(default)]
    is_visible: bool,
    #[serde(default)]
    order: u32,
}

/// Reads the turn's visible, non-empty MESSAGE children in message order,
/// with the earlier text of its conversation the live window holds.
///
/// The text is the hydrated body, so an edited message reads as edited. A
/// body this build cannot decode is skipped, never guessed at. The window
/// enters the digest, so an answer settles only against the text and the
/// window it read.
pub(super) fn turn_input_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<TurnInput> {
    let Some(messages) = turn_messages_in_txn(vault, txn, turn)? else {
        return Ok(TurnInput::Gone);
    };
    if messages.is_empty() {
        return Ok(TurnInput::Empty);
    }
    let tokens = vault
        .config
        .tagging
        .as_ref()
        .map_or(0, |tagging| tagging.live_window_tokens);
    let input = EncoderInput {
        turn: turn.to_hex(),
        messages,
        context: live_window_in_txn(vault, txn, turn, tokens)?,
    };
    let hash = input_hash(&input);
    Ok(TurnInput::Ready { input, hash })
}

/// A live TURN's visible, non-empty messages in message order; `None` for a
/// turn that is absent, deleted, of another type or archived.
fn turn_messages_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<Vec<EncoderMessage>>> {
    match live_entity_row_in_txn(&vault.store, txn, turn)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_TURN => {}
        _ => return Ok(None),
    }
    if vault.archive_tombstone_in_txn(txn, turn)?.is_some() {
        return Ok(None);
    }
    let children = vault.filtered_edge_peers(
        txn,
        EdgeDirection::In,
        turn,
        EdgeKind::PartOf,
        Some(ENTITY_TYPE_MESSAGE),
        "tagging input messages",
    )?;
    let mut rows = Vec::new();
    for id in children {
        if vault.archive_tombstone_in_txn(txn, &id)?.is_some() {
            continue;
        }
        let Some(body) = crate::ports::safe_read_text(vault, txn, &id)? else {
            continue;
        };
        let Ok(message) = rmp_serde::from_slice::<MessageText>(&body) else {
            continue;
        };
        if message.is_visible && !message.content.is_empty() {
            rows.push((message.order, id, message.content));
        }
    }
    rows.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
    });
    Ok(Some(
        rows.into_iter()
            .map(|(_, id, text)| EncoderMessage {
                id: id.to_hex(),
                text,
            })
            .collect(),
    ))
}

/// The live window: the conversation's earlier turns, oldest first, whole
/// but for the oldest, which is cut from the left to fit. It holds at most
/// `tokens` turns and `tokens` × [`WINDOW_CHARS_PER_TOKEN`] characters, and
/// never a turn that comes after `turn`. A turn with no earlier text, or with
/// no single conversation, reads alone.
fn live_window_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    tokens: u32,
) -> Result<Vec<EncoderTurn>> {
    let max_turns = usize::try_from(tokens).unwrap_or(usize::MAX);
    let mut remaining = max_turns.saturating_mul(WINDOW_CHARS_PER_TOKEN);
    let mut window = Vec::new();
    if max_turns == 0 {
        return Ok(window);
    }
    for earlier in earlier_turns_in_txn(vault, txn, turn, max_turns)? {
        if window.len() == max_turns || remaining == 0 {
            break;
        }
        let Some(messages) = turn_messages_in_txn(vault, txn, &earlier)? else {
            continue;
        };
        let mut kept = Vec::new();
        for message in messages.into_iter().rev() {
            if remaining == 0 {
                break;
            }
            let chars = message.text.chars().count();
            let text = if chars <= remaining {
                message.text
            } else {
                last_chars(&message.text, remaining).to_owned()
            };
            remaining = remaining.saturating_sub(chars);
            kept.push(EncoderMessage {
                id: message.id,
                text,
            });
        }
        if kept.is_empty() {
            continue;
        }
        kept.reverse();
        window.push(EncoderTurn {
            turn: earlier.to_hex(),
            messages: kept,
        });
    }
    window.reverse();
    Ok(window)
}

/// The last `count` characters of `text`.
fn last_chars(text: &str, count: usize) -> &str {
    let Some(last) = count.checked_sub(1) else {
        return "";
    };
    let start = text.char_indices().rev().nth(last).map_or(0, |(at, _)| at);
    &text[start..]
}

/// Up to `limit` turns before `turn` in its conversation, nearest first.
///
/// A turn on a conversation DAG reads its `Parent` ancestry, so a branch
/// never reads another branch. Any other turn reads its conversation's
/// `ChildOf` turns that come before it in time, those of one second in id
/// order.
fn earlier_turns_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    limit: usize,
) -> Result<Vec<EntityId>> {
    let store = &vault.store;
    let limit = limit.min(MAX_ANCESTOR_DEPTH);
    if let Some(parent) = sole_peer(vault, txn, turn, EdgeKind::Parent)? {
        let mut ancestry = vec![parent];
        let mut cursor = parent;
        while ancestry.len() < limit {
            let Some(next) = sole_peer(vault, txn, &cursor, EdgeKind::Parent)? else {
                break;
            };
            if next == *turn || ancestry.contains(&next) {
                break;
            }
            ancestry.push(next);
            cursor = next;
        }
        return Ok(ancestry);
    }
    let Some(conversation) = sole_peer(vault, txn, turn, EdgeKind::ChildOf)? else {
        return Ok(Vec::new());
    };
    let Some(current) = store.port_entity_record(txn, turn)? else {
        return Ok(Vec::new());
    };
    let at = (current.occurred.start, *turn.as_bytes());
    let mut earlier = Vec::new();
    for edge in store.port_edges(
        txn,
        &conversation,
        EdgeDirection::In,
        Some(EdgeKind::ChildOf),
        None,
    )? {
        let id = edge?.target;
        let Some(record) = store.port_entity_record(txn, &id)? else {
            continue;
        };
        let key = (record.occurred.start, *id.as_bytes());
        if record.entity_type == ENTITY_TYPE_TURN && key < at {
            earlier.push((key, id));
        }
    }
    earlier.sort_unstable_by_key(|(key, _)| std::cmp::Reverse(*key));
    Ok(earlier.into_iter().take(limit).map(|(_, id)| id).collect())
}

/// The one entity `id` points at through `kind`; `None` when it points at
/// none or at more than one.
fn sole_peer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: EdgeKind,
) -> Result<Option<EntityId>> {
    let mut peers = vault
        .store
        .port_edges(txn, id, EdgeDirection::Out, Some(kind), None)?;
    let Some(first) = peers.next() else {
        return Ok(None);
    };
    let first = first?.target;
    Ok(peers.next().is_none().then_some(first))
}

/// The digest `Memory::witness_with_shadow` stamps on its trace, computed by
/// the same function, so a shadow trace and a tagging trace of one input
/// agree.
pub(super) fn input_hash(input: &EncoderInput) -> String {
    crate::memory::extraction::hash_input(input)
}
