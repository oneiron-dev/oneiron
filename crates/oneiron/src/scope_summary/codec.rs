//! Strict, versioned scope-summary MessagePack codec (distinct from epochs).

use crate::conversation_dag::{ScopePath, ScopeSelector};
use crate::error::{Error, RecordError, Result};
use crate::{EntityId, limits::MAX_ANCESTOR_DEPTH};
use rmpv::Value;
use std::collections::HashSet;

/// Scope-summary payload. Outside tests the text is the Dreamer's.
///
/// Version 1 names the covered records. Version 2, the Dreamer's composed
/// body, also names the MESSAGEs its words came from and the composition
/// memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSummaryBody {
    /// Codec version: 1, or 2 for a composed body.
    pub v: u8,
    /// Selector resolved in the mint transaction.
    pub scope: ScopeSelector,
    /// The body as its producer wrote it, never rewritten by the engine.
    pub text: String,
    /// Validated producer's 32-hex entity id.
    pub actor: String,
    /// Complete, unique record list, independent of the edge cap.
    pub covers: Vec<EntityId>,
    /// Mint timestamp in Unix seconds.
    pub minted_at: u64,
    /// The MESSAGEs whose text the body was written from, each at the
    /// revision read (version 2). The summary is served only while every one
    /// still stands.
    pub messages: Vec<SummarySourceMessage>,
    /// What was composed (version 2): the scope, every source at its version
    /// and the composing policy. A declaration whose memo matches a standing
    /// summary reuses it instead of composing again.
    pub memo: Option<[u8; 32]>,
}

/// One MESSAGE a composed summary's words came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SummarySourceMessage {
    pub id: EntityId,
    /// Content hash of the logical body the Dreamer read.
    pub revision: [u8; 32],
}

pub(super) fn invalid(reason: &'static str) -> Error {
    RecordError::InvalidScopeSummary(reason).into()
}

pub(super) fn scope_value(scope: &ScopeSelector) -> Value {
    let path = match scope.path {
        ScopePath::Canonical => Value::from("canonical"),
        ScopePath::Branch(id) => {
            Value::Map(vec![(Value::from("branch"), Value::from(id.to_hex()))])
        }
        ScopePath::SubSession(id) => {
            Value::Map(vec![(Value::from("sub_session"), Value::from(id.to_hex()))])
        }
        ScopePath::BranchSpan { after, through } => Value::Map(vec![(
            Value::from("branch_span"),
            Value::Map(vec![
                (Value::from("after"), Value::from(after.to_hex())),
                (Value::from("through"), Value::from(through.to_hex())),
            ]),
        )]),
    };
    Value::Map(vec![
        (
            Value::from("conversation"),
            Value::from(scope.conversation.to_hex()),
        ),
        (
            Value::from("session"),
            scope
                .session
                .map_or(Value::Nil, |id| Value::from(id.to_hex())),
        ),
        (Value::from("path"), path),
        (
            Value::from("include_forks"),
            Value::Boolean(scope.include_forks),
        ),
    ])
}

fn closed_map<'a>(value: &'a Value, keys: &[&str]) -> Result<Vec<&'a Value>> {
    let Value::Map(entries) = value else {
        return Err(invalid("expected a map"));
    };
    if entries.len() != keys.len() {
        return Err(invalid("wrong key set"));
    }
    let mut values = Vec::with_capacity(keys.len());
    for expected in keys {
        let mut matching = entries
            .iter()
            .filter(|(key, _)| key.as_str() == Some(*expected));
        let (_, value) = matching
            .next()
            .ok_or_else(|| invalid("missing summary key"))?;
        if matching.next().is_some() {
            return Err(invalid("duplicate summary key"));
        }
        values.push(value);
    }
    Ok(values)
}

fn id(value: &Value) -> Result<EntityId> {
    EntityId::from_hex(value.as_str().ok_or_else(|| invalid("expected a hex id"))?)
        .map_err(|_| invalid("invalid summary id"))
}

pub(super) fn parse_scope(value: &Value) -> Result<ScopeSelector> {
    let v = closed_map(value, &["conversation", "session", "path", "include_forks"])?;
    let path = if v[2].as_str() == Some("canonical") {
        ScopePath::Canonical
    } else if let Value::Map(entries) = v[2] {
        if entries.len() != 1 {
            return Err(invalid("invalid scope path"));
        }
        match entries[0].0.as_str() {
            Some("branch") => ScopePath::Branch(id(&entries[0].1)?),
            Some("sub_session") => ScopePath::SubSession(id(&entries[0].1)?),
            Some("branch_span") => {
                let span = closed_map(&entries[0].1, &["after", "through"])?;
                ScopePath::BranchSpan {
                    after: id(span[0])?,
                    through: id(span[1])?,
                }
            }
            _ => return Err(invalid("unknown scope path")),
        }
    } else {
        return Err(invalid("unknown scope path"));
    };
    Ok(ScopeSelector {
        conversation: id(v[0])?,
        session: if v[1].is_nil() { None } else { Some(id(v[1])?) },
        path,
        include_forks: v[3]
            .as_bool()
            .ok_or_else(|| invalid("include_forks must be boolean"))?,
    })
}

fn validate(body: &ScopeSummaryBody) -> Result<()> {
    match body.v {
        1 if body.messages.is_empty() && body.memo.is_none() => {}
        2 if body.memo.is_some() => {}
        _ => return Err(invalid("unsupported scope summary version")),
    }
    if body.messages.len() > MAX_ANCESTOR_DEPTH {
        return Err(invalid("summary messages exceed walk limit"));
    }
    let unique: HashSet<_> = body.messages.iter().map(|message| message.id).collect();
    if unique.len() != body.messages.len() {
        return Err(invalid("duplicate source message"));
    }
    if body.text.trim().is_empty() {
        return Err(invalid("summary text is blank"));
    }
    EntityId::from_hex(&body.actor).map_err(|_| invalid("invalid summary actor"))?;
    if body.covers.len() > MAX_ANCESTOR_DEPTH {
        return Err(invalid("summary covers exceed walk limit"));
    }
    let unique: HashSet<_> = body.covers.iter().collect();
    if unique.len() != body.covers.len() {
        return Err(invalid("duplicate covered record"));
    }
    if let ScopePath::SubSession(session) = body.scope.path
        && body.scope.session.is_some_and(|id| id != session)
    {
        return Err(invalid("conflicting summary session selectors"));
    }
    if matches!(body.scope.path, ScopePath::BranchSpan { .. })
        && (body.scope.include_forks || body.covers.is_empty())
    {
        return Err(invalid("branch span requires nonempty no-forks covers"));
    }
    Ok(())
}

const V1_KEYS: [&str; 6] = ["v", "scope", "text", "actor", "covers", "minted_at"];
const V2_KEYS: [&str; 8] = [
    "v",
    "scope",
    "text",
    "actor",
    "covers",
    "minted_at",
    "messages",
    "memo",
];

fn hash_hex(hash: &[u8; 32]) -> Value {
    Value::from(blake3::Hash::from_bytes(*hash).to_hex().as_str())
}

fn hash(value: &Value) -> Result<[u8; 32]> {
    value
        .as_str()
        .and_then(|text| blake3::Hash::from_hex(text).ok())
        .map(|hash| *hash.as_bytes())
        .ok_or_else(|| invalid("expected a 32-byte hex hash"))
}

/// Encodes exactly the pinned keys of the body's version after validating
/// the complete body.
pub fn encode_scope_summary_body(body: &ScopeSummaryBody) -> Result<Vec<u8>> {
    validate(body)?;
    let mut entries = vec![
        (Value::from("v"), Value::from(body.v)),
        (Value::from("scope"), scope_value(&body.scope)),
        (Value::from("text"), Value::from(body.text.clone())),
        (Value::from("actor"), Value::from(body.actor.clone())),
        (
            Value::from("covers"),
            Value::Array(
                body.covers
                    .iter()
                    .map(|id| Value::from(id.to_hex()))
                    .collect(),
            ),
        ),
        (Value::from("minted_at"), Value::from(body.minted_at)),
    ];
    if let Some(memo) = &body.memo {
        entries.push((
            Value::from("messages"),
            Value::Array(
                body.messages
                    .iter()
                    .map(|message| {
                        Value::Array(vec![
                            Value::from(message.id.to_hex()),
                            hash_hex(&message.revision),
                        ])
                    })
                    .collect(),
            ),
        ));
        entries.push((Value::from("memo"), hash_hex(memo)));
    }
    let value = Value::Map(entries);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).map_err(|_| invalid("summary encode failed"))?;
    Ok(bytes)
}

/// Refuses unknown versions, unknown/duplicate/missing keys and trailing bytes.
pub fn decode_scope_summary_body(bytes: &[u8]) -> Result<ScopeSummaryBody> {
    let mut bytes = bytes;
    let value =
        rmpv::decode::read_value(&mut bytes).map_err(|_| invalid("invalid summary MessagePack"))?;
    if !bytes.is_empty() {
        return Err(invalid("trailing summary bytes"));
    }
    let version = match &value {
        Value::Map(entries) => entries
            .iter()
            .find(|(key, _)| key.as_str() == Some("v"))
            .and_then(|(_, v)| v.as_u64()),
        _ => None,
    };
    let v = closed_map(
        &value,
        if version == Some(2) {
            &V2_KEYS[..]
        } else {
            &V1_KEYS[..]
        },
    )?;
    let covers = v[4]
        .as_array()
        .ok_or_else(|| invalid("covers must be an array"))?;
    if covers.len() > MAX_ANCESTOR_DEPTH {
        return Err(invalid("summary covers exceed walk limit"));
    }
    let (messages, memo) = match (v.get(6), v.get(7)) {
        (Some(messages), Some(memo)) => {
            let messages = messages
                .as_array()
                .ok_or_else(|| invalid("messages must be an array"))?;
            if messages.len() > MAX_ANCESTOR_DEPTH {
                return Err(invalid("summary messages exceed walk limit"));
            }
            let messages = messages
                .iter()
                .map(|pair| match pair.as_array().map(Vec::as_slice) {
                    Some([message, revision]) => Ok(SummarySourceMessage {
                        id: id(message)?,
                        revision: hash(revision)?,
                    }),
                    _ => Err(invalid("source message must be an id and a revision")),
                })
                .collect::<Result<_>>()?;
            (messages, Some(hash(memo)?))
        }
        _ => (Vec::new(), None),
    };
    let body = ScopeSummaryBody {
        v: v[0]
            .as_u64()
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| invalid("invalid summary version"))?,
        scope: parse_scope(v[1])?,
        text: v[2]
            .as_str()
            .ok_or_else(|| invalid("text must be a string"))?
            .to_owned(),
        actor: v[3]
            .as_str()
            .ok_or_else(|| invalid("actor must be a string"))?
            .to_owned(),
        covers: covers.iter().map(id).collect::<Result<_>>()?,
        minted_at: v[5]
            .as_u64()
            .ok_or_else(|| invalid("minted_at must be a timestamp"))?,
        messages,
        memo,
    };
    validate(&body)?;
    Ok(body)
}

/// Recognizes scope-summary identity before strict decoding, including a
/// damaged suffix after a family-specific key.
pub(super) fn is_scope_summary(bytes: &[u8]) -> bool {
    let (pairs, mut cursor) = match bytes {
        [marker @ 0x80..=0x8f, rest @ ..] => (u32::from(*marker & 0x0f), rest),
        [0xde, a, b, rest @ ..] => (u32::from(u16::from_be_bytes([*a, *b])), rest),
        [0xdf, a, b, c, d, rest @ ..] => (u32::from_be_bytes([*a, *b, *c, *d]), rest),
        _ => return false,
    };
    for _ in 0..pairs {
        let Ok(key) = rmpv::decode::read_value(&mut cursor) else {
            break;
        };
        if matches!(key.as_str(), Some("scope" | "covers" | "minted_at")) {
            return true;
        }
        if rmpv::decode::read_value(&mut cursor).is_err() {
            break;
        }
    }
    false
}

pub(super) fn reply_summary(bytes: &[u8]) -> Result<Option<EntityId>> {
    let mut cursor = bytes;
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(None);
    };
    let mut summaries = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("summary"));
    let Some((_, summary)) = summaries.next() else {
        return Ok(None);
    };
    if summaries.next().is_some() || !cursor.is_empty() {
        return Err(invalid("invalid reply summary association"));
    }
    Ok(Some(id(summary)?))
}
