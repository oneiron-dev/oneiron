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
use crate::gate::{WITNESS_AUTHOR_COMPANION, WITNESS_AUTHOR_SYSTEM, WITNESS_AUTHOR_USER};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::memory::extraction::{EncoderInput, EncoderMessage, EncoderTurn, SpeakerRole};
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
    Unbounded,
    /// The newest characters of its text that fit, and how many.
    Text(String, usize),
}

/// The MESSAGE-body keys the input needs; every other key is ignored. The
/// author is read as any value, so a body is never skipped for its author.
#[derive(Deserialize)]
struct MessageText {
    #[serde(default)]
    content: String,
    #[serde(default)]
    is_visible: bool,
    #[serde(default)]
    order: u32,
    #[serde(default)]
    author: Option<rmpv::Value>,
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
    let Some(members) = members_in_txn(vault, &vault.store, txn, turn, false)? else {
        return Ok(TurnInput::Gone);
    };
    let speaker = turn_role(
        members
            .iter()
            .filter(|member| member.text.is_some())
            .map(|member| member.author.as_slice()),
    );
    let messages: Vec<EncoderMessage> = members.into_iter().filter_map(Member::sent).collect();
    if messages.is_empty() {
        return Ok(TurnInput::Empty);
    }
    let mut input = EncoderInput {
        turn: turn.to_hex(),
        messages,
        context: Vec::new(),
        // No stored or configured fact names a turn's language yet, so the
        // tagger detects it.
        language: None,
        speaker,
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
/// turn that is absent, deleted, of another type or archived. The embedder
/// reads a turn's text through this too, so both read the same words.
pub(crate) fn turn_messages_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<Vec<EncoderMessage>>> {
    Ok(members_in_txn(vault, &vault.store, txn, turn, false)?
        .map(|members| members.into_iter().filter_map(Member::sent).collect()))
}

/// A live MESSAGE child of a turn, with the text it shows there
/// ([`shown_message_text`]): `None` for a hidden or empty one; and, when it
/// was asked for and the message shows text, the body that text is read
/// from, its entity document's text in it (else empty).
pub(crate) type TurnMember = (EntityId, Option<String>, Vec<u8>);

/// Every live MESSAGE child of a live TURN, in message order. `None` for a
/// turn [`turn_messages_in_txn`] reads as gone.
///
/// `store` is the content read: the vault's own, or a room's view, whose
/// turns and messages compose with base.
pub(crate) fn turn_members_in_txn(
    vault: &Vault,
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    bodies: bool,
) -> Result<Option<Vec<TurnMember>>> {
    Ok(
        members_in_txn(vault, store, txn, turn, bodies)?.map(|members| {
            members
                .into_iter()
                .map(|member| (member.id, member.text, member.body))
                .collect()
        }),
    )
}

/// A live MESSAGE child of a turn: its text as [`TurnMember`] has it, its
/// stored author's bytes (empty when it names none as a string), and the
/// body both are read from.
struct Member {
    id: EntityId,
    text: Option<String>,
    author: Vec<u8>,
    body: Vec<u8>,
}

impl Member {
    /// The message as the tagger reads it; `None` for one it does not show.
    fn sent(self) -> Option<EncoderMessage> {
        Some(EncoderMessage {
            id: self.id.to_hex(),
            text: self.text?,
        })
    }
}

/// [`turn_members_in_txn`] with each message's stored author. A body is kept
/// only for a message that shows text, and only when `bodies` asks for it.
fn members_in_txn(
    vault: &Vault,
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    bodies: bool,
) -> Result<Option<Vec<Member>>> {
    match live_entity_row_in_txn(store, txn, turn)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_TURN => {}
        _ => return Ok(None),
    }
    if vault.archive_tombstone_in_txn(txn, turn)?.is_some() {
        return Ok(None);
    }
    let children = crate::vault::filtered_edge_peers_in(
        store,
        txn,
        EdgeDirection::In,
        turn,
        EdgeKind::PartOf,
        Some(ENTITY_TYPE_MESSAGE),
    )?;
    let mut rows = Vec::new();
    for id in children {
        if vault.archive_tombstone_in_txn(txn, &id)?.is_some() {
            continue;
        }
        let Some(body) = vault
            .live_entity_in_txn(store, txn, &id)?
            .map(|row| row.body)
        else {
            continue;
        };
        let Ok(message) = rmp_serde::from_slice::<MessageText>(&body) else {
            continue;
        };
        let author = match &message.author {
            Some(rmpv::Value::String(author)) => author.as_bytes().to_vec(),
            _ => Vec::new(),
        };
        let order = message.order;
        let text = message.shown();
        let body = if bodies && text.is_some() {
            body
        } else {
            Vec::new()
        };
        rows.push((order, id, text, author, body));
    }
    rows.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
    });
    Ok(Some(
        rows.into_iter()
            .map(|(_, id, text, author, body)| Member {
                id,
                text,
                author,
                body,
            })
            .collect(),
    ))
}

/// The side a turn's sent messages are on, from their stored authors: the
/// one non-system author among them, the user's (`A`) or the companion's
/// (`B`). `None` when they name none, both, or an author this build does not
/// know: a role is never guessed.
pub(crate) fn turn_role<A: AsRef<[u8]>>(
    authors: impl IntoIterator<Item = A>,
) -> Option<SpeakerRole> {
    let mut role = None;
    for author in authors {
        let author = author.as_ref();
        let this = if author == WITNESS_AUTHOR_USER.as_bytes() {
            SpeakerRole::User
        } else if author == WITNESS_AUTHOR_COMPANION.as_bytes() {
            SpeakerRole::Companion
        } else if author == WITNESS_AUTHOR_SYSTEM.as_bytes() {
            continue;
        } else {
            return None;
        };
        if role.is_some_and(|known| known != this) {
            return None;
        }
        role = Some(this);
    }
    role
}

/// The text a MESSAGE body shows in its turn: its content, when the message
/// is visible and the content is not empty. `None` for a body this build
/// cannot decode.
pub(crate) fn shown_message_text(body: &[u8]) -> Option<String> {
    rmp_serde::from_slice::<MessageText>(body).ok()?.shown()
}

impl MessageText {
    fn shown(self) -> Option<String> {
        (self.is_visible && !self.content.is_empty()).then_some(self.content)
    }
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
        let Some((messages, speaker, used, ends)) =
            context_text_in_txn(vault, txn, &earlier, remaining)?
        else {
            break;
        };
        remaining = remaining.saturating_sub(used);
        if !messages.is_empty() {
            window.push(EncoderTurn {
                turn: earlier.to_hex(),
                messages,
                speaker,
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
/// message first; the side named by the authors of every message it shows
/// text in ([`turn_role`]), kept or not, since the budget trims text and
/// never a stored fact; the characters it used; and whether the window ends
/// with it. Its messages are ordered from their stored rows without copying any
/// text, then read newest first only until the budget is spent, each through
/// [`context_message_in_txn`], so a large earlier turn costs the window what
/// it keeps of it. `None` for a turn with more than [`MAX_CONTEXT_MESSAGES`]
/// messages: the window ends before it, and the current turn is still read.
fn context_text_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    budget: usize,
) -> Result<Option<ContextTurn>> {
    let store = &vault.store;
    match live_entity_row_in_txn(store, txn, turn)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_TURN => {}
        _ => return Ok(Some((Vec::new(), None, 0, false))),
    }
    if vault.archive_tombstone_in_txn(txn, turn)?.is_some() {
        return Ok(Some((Vec::new(), None, 0, false)));
    }
    let mut places = Vec::new();
    let mut authors = Vec::new();
    for (examined, edge) in store
        .port_edges(txn, turn, EdgeDirection::In, Some(EdgeKind::PartOf), None)?
        .enumerate()
    {
        if examined >= MAX_CONTEXT_MESSAGES {
            return Ok(None);
        }
        let id = edge?.target;
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
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
            if !place.stale && !place.content.is_empty() && !hidden_in_txn(vault, txn, &id)? {
                authors.push(place.author.to_vec());
            }
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
    let speaker = turn_role(authors.iter().map(Vec::as_slice));
    Ok(Some((kept, speaker, budget - remaining, ends)))
}

/// What [`context_text_in_txn`] keeps of one earlier turn.
type ContextTurn = (Vec<EncoderMessage>, Option<SpeakerRole>, usize, bool);

/// An earlier MESSAGE's newest `budget` characters, read from its stored row
/// through [`super::body`]: the work and the copy are bounded by what the
/// window keeps, not by the message.
fn context_message_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    budget: usize,
) -> Result<ContextText> {
    let content = match context_row_in_txn(vault, txn, id)? {
        ContextRow::Nothing => return Ok(ContextText::Nothing),
        ContextRow::Unbounded => return Ok(ContextText::Unbounded),
        ContextRow::Shown(content) => content,
    };
    Ok(match super::body::newest_chars(&content, budget) {
        Some((text, chars)) => ContextText::Text(text.to_owned(), chars),
        None => ContextText::Nothing,
    })
}

/// An earlier MESSAGE's stored row as the window reads it.
enum ContextRow {
    /// No visible text: absent, deleted, archived, stale or undecodable.
    Nothing,
    /// Its text lives in an entity document.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    Unbounded,
    /// Its visible, non-empty text, as stored.
    Shown(Vec<u8>),
}

fn context_row_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<ContextRow> {
    let store = &vault.store;
    if hidden_in_txn(vault, txn, id)? {
        return Ok(ContextRow::Nothing);
    }
    #[cfg(feature = "sync")]
    if crate::entity_doc::has_record_head(store, txn, id)? {
        return Ok(ContextRow::Unbounded);
    }
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(ContextRow::Nothing);
    };
    let Some(message) = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(super::body::message_fields)
    else {
        return Ok(ContextRow::Nothing);
    };
    if message.stale || !message.is_visible || message.content.is_empty() {
        return Ok(ContextRow::Nothing);
    }
    Ok(ContextRow::Shown(message.content.to_vec()))
}

/// Whether an earlier MESSAGE is archived, deleted or stale: it shows no
/// text, whatever its row holds.
fn hidden_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(vault.archive_tombstone_in_txn(txn, id)?.is_some()
        || vault.port_tombstone_is_deleted(txn, id)?
        || crate::ports::stale_in_txn(&vault.store, txn, id)?)
}

/// Where the text the window sent for an earlier MESSAGE starts in the text
/// that message shows now: the window sends a message's newest characters,
/// so what it sent is a suffix of the text. `None` when the message no
/// longer shows text ending in what was sent: deleted, archived, stale,
/// hidden, edited, or held in an entity document.
pub(super) fn sent_text_offset_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    sent: &str,
) -> Result<Option<usize>> {
    let ContextRow::Shown(content) = context_row_in_txn(vault, txn, id)? else {
        return Ok(None);
    };
    Ok(content
        .ends_with(sent.as_bytes())
        .then(|| content.len() - sent.len()))
}

/// Up to `limit` turns before `turn` in its conversation, nearest first.
///
/// A turn with a DAG parent reads its retained ancestry (the `Parent` edge,
/// or the parent an erasure pin kept), so a branch never reads another
/// branch. A legacy turn's ancestry is the order a room's adoption of the
/// DAG gave it, by time and then id, so it keeps only the turns of an
/// earlier second. A DAG record with no parent, or any turn of a conversation that
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
        // A DAG record's parent existed when the append door wrote it, and
        // adoption writes Parent edges only in a room with no DAG record yet,
        // so its whole ancestry came first. Any other turn's Parent came from
        // adoption, which orders one second's turns by id: through it only a
        // turn of a strictly earlier second is earlier.
        let since = match live_entity_row_in_txn(store, txn, turn)? {
            LiveEntityRow::Live { body, .. } if matches!(record_kind(&body), Ok(Some(_))) => None,
            LiveEntityRow::Live { .. } => match header_key(vault, txn, turn)? {
                Some((at, _)) => Some(at),
                None => return Ok(Vec::new()),
            },
            _ => return Ok(Vec::new()),
        };
        let mut walked = vec![*turn];
        let mut ancestry = Vec::new();
        let mut cursor = Some(parent);
        for _ in 0..limit {
            let Some(id) = cursor.filter(|id| !walked.contains(id)) else {
                break;
            };
            walked.push(id);
            let earlier = match since {
                None => true,
                Some(at) => header_key(vault, txn, &id)?.is_some_and(|(second, _)| second < at),
            };
            if earlier {
                ancestry.push(id);
            }
            cursor = retained_parent(store, txn, &id).ok().flatten();
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
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)? else {
        return Ok(None);
    };
    Ok(EntityMetadataHeader::parse(&raw)
        .filter(|header| header.entity_type == ENTITY_TYPE_TURN)
        .map(|header| (header.occurred_start, *id.as_bytes())))
}

/// The one entity `id` points at through `kind`; `None` when it points at
/// none or at more than one.
pub(super) fn sole_peer(
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
