//! The tagger's input for one turn: the turn's MESSAGE rows, and the live
//! register's bounded window of earlier text in the same conversation.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use serde::Deserialize;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::conversation_dag::{
    keeps_dag_topology, record_has_dag_topology, record_kind, retained_parent,
};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::memory::extraction::{EncoderInput, EncoderMessage, EncoderTurn};
use crate::ports::{EdgeDirection, EdgeStoreRead, TombstoneStore};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, MAX_EDGE_QUERY_RESULTS, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// Characters of earlier text the window carries per tagger token. The engine
/// cannot count the tagger's tokens, so it over-sends: no token of the
/// serving tokenizer spans more characters than this in practice, so the
/// window holds the runtime's K tokens whenever the conversation has them,
/// and the runtime cuts it to K exactly.
const WINDOW_CHARS_PER_TOKEN: usize = 16;

/// The most MESSAGE children of one earlier turn the window reads: an earlier
/// turn with more ends the window before it.
const MAX_CONTEXT_MESSAGES: usize = 256;

/// What a marker's turn reads as now.
pub(super) enum TurnInput {
    /// The turn is absent, deleted or archived: nothing is owed.
    Gone,
    /// The turn holds no visible text.
    Empty,
    /// The input the tagger reads; the digest of the whole input, window
    /// included; and the digest of the turn's own text, which is all an
    /// answer's spans index.
    Ready {
        input: EncoderInput,
        hash: String,
        text_hash: String,
    },
}

/// What an earlier message gives the window.
enum ContextText {
    /// No visible text: absent, deleted, archived, stale or undecodable.
    Nothing,
    /// Its text lives in an entity document, which only a whole-document read
    /// can give: the window ends here.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    Unbounded,
    /// The newest characters of its text that fit, and how many.
    Text(String, usize),
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
/// with the earlier text of its conversation the live window holds: the
/// input a tagger call sends.
///
/// The text is the hydrated body, so an edited message reads as edited. A
/// body this build cannot decode is skipped, never guessed at. The window
/// enters the input's digest, which the trace records.
pub(super) fn turn_input_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<TurnInput> {
    let tokens = vault
        .config
        .tagging
        .as_ref()
        .map_or(0, |tagging| tagging.live_window_tokens);
    read_in_txn(vault, txn, turn, tokens)
}

/// [`turn_input_in_txn`] with no window: the turn's own text, the one thing
/// an answer's spans index, so an answer settles against the text it tagged.
/// A settling write reads only this, so no write waits on a window.
pub(super) fn turn_text_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<TurnInput> {
    read_in_txn(vault, txn, turn, 0)
}

fn read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    tokens: u32,
) -> Result<TurnInput> {
    let Some(messages) = turn_messages_in_txn(vault, txn, turn)? else {
        return Ok(TurnInput::Gone);
    };
    if messages.is_empty() {
        return Ok(TurnInput::Empty);
    }
    let mut input = EncoderInput {
        turn: turn.to_hex(),
        messages,
        context: Vec::new(),
    };
    let text_hash = input_hash(&input);
    input.context = live_window_in_txn(vault, txn, turn, tokens)?;
    let hash = if input.context.is_empty() {
        text_hash.clone()
    } else {
        input_hash(&input)
    };
    Ok(TurnInput::Ready {
        input,
        hash,
        text_hash,
    })
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
/// never a turn that comes after `turn`. Turns are read nearest first, each
/// through [`context_text_in_txn`], and the read stops once the window is
/// full. A message whose text lives in an entity document ends the window
/// with it: only a whole-document read gives that text. A turn with no
/// earlier text, or with no single conversation, reads alone.
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
        let Some((messages, used, ends)) = context_text_in_txn(vault, txn, &earlier, remaining)?
        else {
            break;
        };
        remaining = remaining.saturating_sub(used);
        if !messages.is_empty() {
            window.push(EncoderTurn {
                turn: earlier.to_hex(),
                messages,
            });
        }
        if ends {
            break;
        }
    }
    window.reverse();
    Ok(window)
}

/// An earlier turn's newest visible text, at most `budget` characters, oldest
/// message first; the characters it used; and whether the window ends with
/// it. Its messages are ordered from their stored rows without copying any
/// text, then read newest first only until the budget is spent, each through
/// [`context_message_in_txn`], so a large earlier turn costs the window what
/// it keeps of it. `None` for a turn with more than [`MAX_CONTEXT_MESSAGES`]
/// messages: the window ends before it, and the current turn is still read.
fn context_text_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    budget: usize,
) -> Result<Option<(Vec<EncoderMessage>, usize, bool)>> {
    let store = &vault.store;
    match live_entity_row_in_txn(store, txn, turn)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_TURN => {}
        _ => return Ok(Some((Vec::new(), 0, false))),
    }
    if vault.archive_tombstone_in_txn(txn, turn)?.is_some() {
        return Ok(Some((Vec::new(), 0, false)));
    }
    let mut places = Vec::new();
    for (examined, edge) in store
        .port_edges(txn, turn, EdgeDirection::In, Some(EdgeKind::PartOf), None)?
        .enumerate()
    {
        if examined >= MAX_CONTEXT_MESSAGES {
            return Ok(None);
        }
        let id = edge?.target;
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_MESSAGE)
        {
            continue;
        }
        let place = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .and_then(super::body::message_fields);
        if let Some(place) = place.filter(|place| place.is_visible) {
            places.push((place.order, *id.as_bytes()));
        }
    }
    places.sort_unstable_by_key(|place| Reverse(*place));
    let mut remaining = budget;
    let mut kept = Vec::new();
    let mut ends = false;
    for (_, id) in places {
        if remaining == 0 {
            break;
        }
        let id = EntityId::from_bytes(id)?;
        match context_message_in_txn(vault, txn, &id, remaining)? {
            ContextText::Nothing => {}
            ContextText::Unbounded => {
                ends = true;
                break;
            }
            ContextText::Text(text, chars) => {
                remaining = remaining.saturating_sub(chars);
                kept.push(EncoderMessage {
                    id: id.to_hex(),
                    text,
                });
            }
        }
    }
    kept.reverse();
    Ok(Some((kept, budget - remaining, ends)))
}

/// An earlier MESSAGE's newest `budget` characters, read from its stored row
/// through [`super::body`]: the work and the copy are bounded by what the
/// window keeps, not by the message.
fn context_message_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    budget: usize,
) -> Result<ContextText> {
    let store = &vault.store;
    if vault.archive_tombstone_in_txn(txn, id)?.is_some()
        || vault.port_tombstone_is_deleted(txn, id)?
        || crate::ports::stale_in_txn(store, txn, id)?
    {
        return Ok(ContextText::Nothing);
    }
    #[cfg(feature = "sync")]
    if crate::entity_doc::has_record_head(store, txn, id)? {
        return Ok(ContextText::Unbounded);
    }
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(ContextText::Nothing);
    };
    let Some(message) = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(super::body::message_fields)
    else {
        return Ok(ContextText::Nothing);
    };
    if message.stale || !message.is_visible || message.content.is_empty() {
        return Ok(ContextText::Nothing);
    }
    Ok(match super::body::newest_chars(message.content, budget) {
        Some((text, chars)) => ContextText::Text(text.to_owned(), chars),
        None => ContextText::Nothing,
    })
}

/// Up to `limit` turns before `turn` in its conversation, nearest first.
///
/// A turn with a DAG parent reads its retained ancestry (the `Parent` edge,
/// or the parent an erasure pin kept), so a branch never reads another
/// branch. A DAG record with no parent, or any turn of a conversation that
/// adopted the DAG, is a root and reads alone, as is a turn whose `ChildOf`
/// owner is not one live conversation, or one of whose turns carries DAG
/// topology of its own (a received `Parent`, say). Only a conversation that
/// never adopted it is ordered by time: its `ChildOf` turns that occurred in
/// an earlier second than `turn`. A turn of the same second is left out,
/// since nothing orders the two: a turn's id may be its caller's choice, and
/// its time has one-second precision. That read takes each turn's row
/// header, never its body, keeps only the nearest `limit`, and reads alone
/// past [`MAX_EDGE_QUERY_RESULTS`] turns. A topology the DAG readers refuse
/// reads alone too: the window is context, and a refusal must not keep the
/// marker from settling.
pub(super) fn earlier_turns_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    limit: usize,
) -> Result<Vec<EntityId>> {
    let store = &vault.store;
    let limit = limit.min(MAX_ANCESTOR_DEPTH);
    if limit == 0 {
        return Ok(Vec::new());
    }
    let Ok(parent) = retained_parent(store, txn, turn) else {
        return Ok(Vec::new());
    };
    if let Some(parent) = parent {
        let mut ancestry = vec![parent];
        let mut cursor = parent;
        while ancestry.len() < limit {
            let Ok(Some(next)) = retained_parent(store, txn, &cursor) else {
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
    // Only a live conversation's turns are a window; a turn under another
    // structural parent reads alone.
    if !matches!(
        live_entity_row_in_txn(store, txn, &conversation)?,
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_CONVERSATION
    ) {
        return Ok(Vec::new());
    }
    let dag_record = match live_entity_row_in_txn(store, txn, turn)? {
        LiveEntityRow::Live { body, .. } => !matches!(record_kind(&body), Ok(None)),
        _ => return Ok(Vec::new()),
    };
    if dag_record || keeps_dag_topology(store, txn, &conversation).unwrap_or(true) {
        return Ok(Vec::new());
    }
    let Some((at, _)) = header_key(vault, txn, turn)? else {
        return Ok(Vec::new());
    };
    // The nearest `limit` earlier turns, the farthest of them on top.
    let mut nearest: BinaryHeap<Reverse<(u64, [u8; 16])>> = BinaryHeap::new();
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
        // A turn of the room with DAG topology of its own, a received one
        // before this replica adopts the DAG among them, means time does not
        // order the room: the turn reads alone.
        if record_has_dag_topology(vault, txn, &id).unwrap_or(true) {
            return Ok(Vec::new());
        }
        // Only a strictly earlier second proves a turn came first.
        if key.0 >= at {
            continue;
        }
        nearest.push(Reverse(key));
        if nearest.len() > limit {
            nearest.pop();
        }
    }
    let mut earlier: Vec<(u64, [u8; 16])> = nearest.into_iter().map(|Reverse(key)| key).collect();
    earlier.sort_unstable_by_key(|key| Reverse(*key));
    earlier
        .into_iter()
        .map(|(_, id)| EntityId::from_bytes(id))
        .collect()
}

/// A TURN's place in time, read from its row header: its occurred second,
/// then its id, which only makes the order of one second's turns stable.
/// `None` for a row that is absent or not a TURN.
fn header_key(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(u64, [u8; 16])>> {
    let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    Ok(EntityMetadataHeader::parse(&raw)
        .filter(|header| header.entity_type == ENTITY_TYPE_TURN)
        .map(|header| (header.occurred_start, *id.as_bytes())))
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
