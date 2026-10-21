//! What a session judge reads (FIX 2079): every readable line of the
//! conversations a session window's runs were retrieved for, whole.
//!
//! A run names its turn by the caller's `turn_id`. A turn id that is a stored
//! TURN leads to each CONVERSATION it is a child of; the caller's
//! `episode_id` is only its grouping and is never taken for a conversation.
//! Ids and topology come from the store, and every body through a scoped
//! read as the reader read off this device with no machine proved: a
//! device-local world's rows never reach a judge, local or not, even under
//! the owner's identity, and no raw transcript is read around that. A
//! conversation's transcript is read page after page to its end, and a
//! legacy TURN that carries its own words is read beside the MESSAGE
//! children. A row the reader may not read here is left out by authority;
//! none is left out for its size.
//!
//! A MESSAGE's result attachment rides beside its words (FIX 6113), its
//! whole body read through the MESSAGE's own result reads, page after page
//! to the last, under each read's own checks; a MESSAGE that carries only a
//! result is a line too. An attachment this reader cannot read whole now is
//! marked unavailable on its line, which keeps its words.

use std::collections::BTreeMap;

use base64::Engine as _;
use rmpv::Value;
use serde::Serialize;

use crate::claim::{CallerLocality, ClaimReadStatus, PointRead, ScopedRead};
use crate::code_run::ResultFacet;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::memory::{MAX_TRANSCRIPT_PAGE_TURNS, MEMORY_CODE_NOT_FOUND, Memory, MemoryError};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::RetrievalRunRecord;
use crate::{EntityId, Error, Result, Vault};

/// The readable text of a session window's conversations.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SessionText {
    /// Every readable line: conversation by conversation in the order the
    /// window first names them, each in transcript order, a turn's own words
    /// before its messages.
    pub lines: Vec<SessionLine>,
}

/// One readable line of a session: who said it, where, when, and all of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionLine {
    /// 32-hex conversation id; `None` for a turn that belongs to none.
    pub conversation: Option<String>,
    /// 32-hex turn id.
    pub turn: String,
    /// 32-hex message id; `None` for the words a TURN carries itself.
    pub message: Option<String>,
    /// Who said it, as its writer recorded them.
    pub role: Option<String>,
    /// When it occurred (Unix seconds).
    pub occurred: u64,
    /// What it says, whole.
    pub text: String,
    /// The result attachment the message carries, whole or marked
    /// unavailable (FIX 6113); `None` for a line that carries none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SessionResult>,
}

/// A message's result attachment as its session line carries it (FIX 6113):
/// the whole body, or why this reader cannot read it whole now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionResult {
    /// A text body, whole.
    Text {
        /// The body, as its reads show text.
        text: String,
        /// Bytes of the body that are not UTF-8 are shown replaced.
        lossy: bool,
    },
    /// A binary body, whole.
    Binary {
        /// The body's bytes, as base64.
        base64: String,
    },
    /// Not readable whole by this reader now: withheld, refused or gone.
    Unavailable {
        /// The read's own code: a refusal's, a withholding's or an error's.
        reason: String,
    },
}

/// One message's line while a turn is gathered: its 32-hex id, writer,
/// time, words and result attachment.
type MessageWords = (String, Option<String>, u64, String, Option<SessionResult>);

/// One turn's readable words while its conversation is gathered.
#[derive(Default)]
struct TurnText {
    occurred: u64,
    /// The words the TURN carries itself, and who said them.
    said: Option<(Option<String>, String)>,
    messages: Vec<MessageWords>,
}

impl Vault {
    /// Every readable line of the conversations `runs` were retrieved for,
    /// read as `reader` off this device with no machine proved (FIX 2079).
    /// A conversation the reader may not read there is left out; a run whose
    /// turn id is no stored TURN names no text.
    ///
    /// # Errors
    ///
    /// Storage errors, or a transcript refusal other than a withheld
    /// conversation, by its code only.
    pub fn session_judge_context(
        &self,
        reader: EntityId,
        runs: &[RetrievalRunRecord],
    ) -> Result<SessionText> {
        let (conversations, loose) = self.session_topology(runs)?;
        let memory = self
            .memory(reader, EdgeActorClass::Human)
            .at(CallerLocality::OffDevice);
        let lane = memory
            .read_lane(ClaimReadStatus::Recorded)
            .map_err(refused)?;
        let mut lines = Vec::new();
        for conversation in conversations {
            lines.extend(self.conversation_lines(&memory, &lane, conversation)?);
        }
        for turn in loose {
            lines.extend(self.loose_turn_lines(&memory, &lane, turn)?);
        }
        Ok(SessionText { lines })
    }

    /// The conversations the turns `runs` name are children of, in the order
    /// the runs first name them, and the named TURNs that belong to none.
    /// Ids and topology only; no body is read here.
    fn session_topology(
        &self,
        runs: &[RetrievalRunRecord],
    ) -> Result<(Vec<EntityId>, Vec<EntityId>)> {
        let mut named = Vec::new();
        for run in runs {
            if let Some(turn) = run.turn
                && let Ok(id) = EntityId::from_bytes(turn.turn_id)
                && !named.contains(&id)
            {
                named.push(id);
            }
        }
        let txn = self.store.env.read_txn()?;
        let mut conversations = Vec::new();
        let mut loose = Vec::new();
        for turn in named {
            if self.get_entity_type_in_txn(&txn, &turn)? != Some(ENTITY_TYPE_TURN) {
                continue;
            }
            let parents = self.neighbors_in(
                &txn,
                &turn,
                EdgeDirection::Out,
                EdgeKind::ChildOf,
                ENTITY_TYPE_CONVERSATION,
            )?;
            if parents.is_empty() {
                loose.push(turn);
            }
            for parent in parents {
                if !conversations.contains(&parent) {
                    conversations.push(parent);
                }
            }
        }
        Ok((conversations, loose))
    }

    /// Every row of `entity_type` on a `kind` edge of `center` in `direction`:
    /// the whole adjacency, so no row the reader may not read can end it.
    fn neighbors_in(
        &self,
        txn: &heed::RoTxn<'_>,
        center: &EntityId,
        direction: EdgeDirection,
        kind: EdgeKind,
        entity_type: u8,
    ) -> Result<Vec<EntityId>> {
        let mut rows = Vec::new();
        for edge in self
            .store
            .port_edges(txn, center, direction, Some(kind), None)?
        {
            let id = edge?.target;
            if self.get_entity_type_in_txn(txn, &id)? == Some(entity_type) {
                rows.push(id);
            }
        }
        Ok(rows)
    }

    /// One conversation's readable lines: its transcript to the last page,
    /// and the words each of its TURNs carries itself, which the transcript
    /// does not read. None when the reader may not read the conversation.
    fn conversation_lines(
        &self,
        memory: &Memory<'_>,
        lane: &ScopedRead<'_>,
        conversation: EntityId,
    ) -> Result<Vec<SessionLine>> {
        let mut turns: BTreeMap<EntityId, TurnText> = BTreeMap::new();
        let mut after: Option<String> = None;
        loop {
            let page = match memory.conversation_transcript(
                &conversation,
                after.as_deref(),
                MAX_TRANSCRIPT_PAGE_TURNS,
            ) {
                Ok(page) => page.value,
                // Withheld from this reader here: by authority, never size.
                Err(error) if error.code == MEMORY_CODE_NOT_FOUND => return Ok(Vec::new()),
                Err(error) => return Err(refused(error)),
            };
            for turn in page.turns {
                let gathered = turns.entry(EntityId::from_hex(&turn.id)?).or_default();
                gathered.occurred = turn.occurred_start;
                for message in turn.messages {
                    // The transcript showed a result: its whole body, or
                    // unavailable when it is gone since.
                    let result = if message.result.is_some() {
                        let id = EntityId::from_hex(&message.id)?;
                        Some(
                            whole_result(memory, &id)
                                .unwrap_or_else(|| unavailable(MEMORY_CODE_NOT_FOUND)),
                        )
                    } else {
                        None
                    };
                    gathered.messages.push((
                        message.id,
                        Some(message.role),
                        message.occurred,
                        message.text,
                        result,
                    ));
                }
            }
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        let listed = {
            let txn = self.store.env.read_txn()?;
            self.neighbors_in(
                &txn,
                &conversation,
                EdgeDirection::In,
                EdgeKind::ChildOf,
                ENTITY_TYPE_TURN,
            )?
        };
        if !listed.is_empty() {
            let reads: Vec<_> = listed.into_iter().map(PointRead::id).collect();
            for row in lane.read(&reads, None)?.value.into_iter().flatten() {
                let said = row.body.as_deref().and_then(turn_words);
                if row.entity_type != ENTITY_TYPE_TURN || said.is_none() {
                    continue;
                }
                let gathered = turns.entry(row.id).or_insert_with(|| TurnText {
                    occurred: row.occurred.start,
                    ..TurnText::default()
                });
                gathered.said = said;
            }
        }
        Ok(ordered(Some(conversation), turns))
    }

    /// A TURN that belongs to no conversation, as the transcript would read
    /// it: its own words and its visible MESSAGE children, each through the
    /// lane, with the result a child carries. None when the reader may not
    /// read the turn.
    fn loose_turn_lines(
        &self,
        memory: &Memory<'_>,
        lane: &ScopedRead<'_>,
        turn: EntityId,
    ) -> Result<Vec<SessionLine>> {
        let messages = {
            let txn = self.store.env.read_txn()?;
            self.neighbors_in(
                &txn,
                &turn,
                EdgeDirection::In,
                EdgeKind::PartOf,
                ENTITY_TYPE_MESSAGE,
            )?
        };
        let reads: Vec<_> = std::iter::once(turn)
            .chain(messages)
            .map(PointRead::id)
            .collect();
        let mut rows = lane.read(&reads, None)?.value.into_iter();
        let Some(Some(row)) = rows.next() else {
            return Ok(Vec::new());
        };
        if row.entity_type != ENTITY_TYPE_TURN {
            return Ok(Vec::new());
        }
        let mut said = Vec::new();
        for message in rows.flatten() {
            if message.entity_type != ENTITY_TYPE_MESSAGE {
                continue;
            }
            if let Some((order, role, text, metadata)) =
                message.body.as_deref().and_then(message_words)
            {
                // Only a MESSAGE with metadata can carry a result.
                let result = if metadata {
                    whole_result(memory, &message.id)
                } else {
                    None
                };
                said.push((
                    order,
                    message.id,
                    role,
                    message.occurred.start,
                    text,
                    result,
                ));
            }
        }
        said.sort_by_key(|(order, id, ..)| (*order, *id.as_bytes()));
        let gathered = TurnText {
            occurred: row.occurred.start,
            said: row.body.as_deref().and_then(turn_words),
            messages: said
                .into_iter()
                .map(|(_, id, role, occurred, text, result)| {
                    (id.to_hex(), role, occurred, text, result)
                })
                .collect(),
        };
        Ok(ordered(None, BTreeMap::from([(turn, gathered)])))
    }
}

/// `turns` as lines, by when each occurred and then by id, as a transcript
/// orders them: a turn's own words first, then its messages in order. A line
/// with no words and no result says nothing and is not one.
fn ordered(
    conversation: Option<EntityId>,
    turns: BTreeMap<EntityId, TurnText>,
) -> Vec<SessionLine> {
    let conversation = conversation.map(|id| id.to_hex());
    let mut turns: Vec<(EntityId, TurnText)> = turns.into_iter().collect();
    turns.sort_by_key(|(id, gathered)| (gathered.occurred, *id.as_bytes()));
    let mut lines = Vec::new();
    for (id, gathered) in turns {
        let turn = id.to_hex();
        if let Some((role, text)) = gathered.said
            && !text.is_empty()
        {
            lines.push(SessionLine {
                conversation: conversation.clone(),
                turn: turn.clone(),
                message: None,
                role,
                occurred: gathered.occurred,
                text,
                result: None,
            });
        }
        for (message, role, occurred, text, result) in gathered.messages {
            if text.is_empty() && result.is_none() {
                continue;
            }
            lines.push(SessionLine {
                conversation: conversation.clone(),
                turn: turn.clone(),
                message: Some(message),
                role,
                occurred,
                text,
                result,
            });
        }
    }
    lines
}

/// A MessagePack body's map entries; `None` for any other shape.
fn entries_of(body: &[u8]) -> Option<Vec<(Value, Value)>> {
    match rmpv::decode::read_value(&mut std::io::Cursor::new(body)) {
        Ok(Value::Map(entries)) => Some(entries),
        _ => None,
    }
}

/// The value under the first of `keys` the entries hold.
fn field<'a>(entries: &'a [(Value, Value)], keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| {
        entries
            .iter()
            .find(|(name, _)| name.as_str() == Some(*key))
            .map(|(_, value)| value)
    })
}

/// The words a TURN body carries itself and who said them, by either
/// documented spelling of each key; `None` for one whose words are its
/// MESSAGE children.
fn turn_words(body: &[u8]) -> Option<(Option<String>, String)> {
    let entries = entries_of(body)?;
    let text = field(&entries, &["txt", "text"])?.as_str()?.to_owned();
    let speaker = field(&entries, &["spkr", "speaker"])
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some((speaker, text))
}

/// A visible MESSAGE body's order, writer and words, as a transcript reads
/// them, and whether it carries metadata, where a result rides; `None` for a
/// hidden one.
fn message_words(body: &[u8]) -> Option<(u64, Option<String>, String, bool)> {
    let entries = entries_of(body)?;
    if field(&entries, &["is_visible"]).and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let order = field(&entries, &["order"])
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let role = field(&entries, &["author"])
        .and_then(Value::as_str)
        .map(str::to_owned);
    let text = field(&entries, &["content"])
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let metadata = field(&entries, &["metadata"]).is_some_and(|value| !value.is_nil());
    Some((order, role, text, metadata))
}

/// The whole body of the result MESSAGE `message` carries, as `memory`
/// reads it: its `slice` from the first byte, then each reply's `next`, to
/// the reply that says it is done (FIX 6113). Every page passes that read's
/// own admission, served-row and taint checks; nothing here reads around
/// them, and nothing bounds the body. `None` when the first read finds no
/// result this reader may read on the MESSAGE; a page withheld or refused,
/// or a read that fails or stops moving, marks it unavailable by its code.
pub(super) fn whole_result(memory: &Memory<'_>, message: &EntityId) -> Option<SessionResult> {
    let mut input = serde_json::json!({ "bytes": [0] });
    let mut text = String::new();
    let mut bytes = Vec::new();
    let mut lossy = false;
    let mut binary = false;
    let mut first = true;
    loop {
        let reply = match memory.read_message_result(message, Some(ResultFacet::Slice), input) {
            Ok(reply) => reply,
            Err(error) if first && error.code == MEMORY_CODE_NOT_FOUND => return None,
            Err(error) => return Some(unavailable(&error.code)),
        };
        first = false;
        let Some(page) = reply.get("output") else {
            let code = reply.get("denied").and_then(serde_json::Value::as_str);
            return Some(unavailable(code.unwrap_or("denied")));
        };
        if let Some(withheld) = page.get("withheld") {
            return Some(unavailable(withheld.as_str().unwrap_or("withheld")));
        }
        if let Some(shown) = page.get("text").and_then(serde_json::Value::as_str) {
            text.push_str(shown);
            lossy |= page.get("lossy").and_then(serde_json::Value::as_bool) == Some(true);
        } else if let Some(shown) = page.get("base64").and_then(serde_json::Value::as_str) {
            binary = true;
            match base64::engine::general_purpose::STANDARD.decode(shown) {
                Ok(decoded) => bytes.extend(decoded),
                Err(_) => return Some(unavailable("undecodable")),
            }
        } else {
            return Some(unavailable("unreadable"));
        }
        if page.get("done").and_then(serde_json::Value::as_bool) == Some(true) {
            break;
        }
        let (start, end) = (page["start"].as_u64(), page["end"].as_u64());
        match (page.get("next"), start, end) {
            (Some(next), Some(start), Some(end)) if end > start => input = next.clone(),
            _ => return Some(unavailable("no_progress")),
        }
    }
    Some(if binary {
        SessionResult::Binary {
            base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    } else {
        SessionResult::Text { text, lossy }
    })
}

/// An attachment this reader cannot read whole now, by the read's code.
fn unavailable(reason: &str) -> SessionResult {
    SessionResult::Unavailable {
        reason: reason.to_owned(),
    }
}

/// A transcript refusal other than a withheld conversation, by its code
/// only: its message can quote the vault.
fn refused(error: MemoryError) -> Error {
    Error::InvalidConfig(format!("session text refused: {}", error.code))
}
