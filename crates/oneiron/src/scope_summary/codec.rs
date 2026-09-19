//! Strict, versioned scope-summary MessagePack codec (distinct from epochs).

use crate::conversation_dag::{ScopePath, ScopeSelector};
use crate::error::{Error, RecordError, Result};
use crate::{EntityId, limits::MAX_ANCESTOR_DEPTH};
use rmpv::Value;
use std::collections::HashSet;

/// Version-one scope-summary payload. The caller owns the text verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSummaryBody {
    /// Codec version; currently exactly 1.
    pub v: u8,
    /// Selector resolved in the mint transaction.
    pub scope: ScopeSelector,
    /// Caller-provided text, never composed or rewritten by the engine.
    pub text: String,
    /// Validated producer's 32-hex entity id.
    pub actor: String,
    /// Complete, unique record list, independent of the edge cap.
    pub covers: Vec<EntityId>,
    /// Mint timestamp in Unix seconds.
    pub minted_at: u64,
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
                .map(|id| Value::from(id.to_hex()))
                .unwrap_or(Value::Nil),
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

fn parse_scope(value: &Value) -> Result<ScopeSelector> {
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
    if body.v != 1 {
        return Err(invalid("unsupported scope summary version"));
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
    Ok(())
}

/// Encodes exactly the six pinned keys after validating the complete body.
pub fn encode_scope_summary_body(body: &ScopeSummaryBody) -> Result<Vec<u8>> {
    validate(body)?;
    let value = Value::Map(vec![
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
    ]);
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
    let v = closed_map(
        &value,
        &["v", "scope", "text", "actor", "covers", "minted_at"],
    )?;
    let covers = v[4]
        .as_array()
        .ok_or_else(|| invalid("covers must be an array"))?;
    if covers.len() > MAX_ANCESTOR_DEPTH {
        return Err(invalid("summary covers exceed walk limit"));
    }
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
    };
    validate(&body)?;
    Ok(body)
}
