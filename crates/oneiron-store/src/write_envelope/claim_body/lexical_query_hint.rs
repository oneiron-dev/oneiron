//! Codec primitives for `core.lexical.query_hint` side records.
//!
//! This module owns only the encode/decode/normalize/target-extraction and
//! id primitives; `crate::batch` owns hint materialization and dedup, and
//! `crate::bm25` owns the scoring collapse.

use rmpv::Value;

use super::*;
use oneiron_contracts::entity_id::derived_domains::LEXICAL_QUERY_HINT;
use oneiron_contracts::entity_id::{ENTITY_ID_LEN, EntityId};
use oneiron_contracts::error::{Error, Result};

/// Predicate used for synthetic prospective-query hint side records.
pub const PREDICATE_LEXICAL_QUERY_HINT: &str = "core.lexical.query_hint";

/// Maximum number of lexical query hints one claim-candidate write may emit.
pub const MAX_LEXICAL_QUERY_HINTS_PER_CLAIM: usize = 8;

/// Maximum UTF-8 byte length of one prospective query hint.
pub const MAX_LEXICAL_QUERY_HINT_BYTES: usize = 256;

const LEXICAL_HINT_KIND: &str = "prospective_query";
const LEXICAL_HINT_VALUE_KEY_KIND: &str = "kind";
const LEXICAL_HINT_VALUE_KEY_QUERY: &str = "query";
const LEXICAL_HINT_VALUE_KEY_TARGET: &str = "target";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalQueryHintValue {
    pub target: EntityId,
    pub query: String,
}

pub fn normalize_lexical_query_hints(hints: &[&str]) -> Result<Vec<String>> {
    let mut normalized = Vec::<String>::new();
    for hint in hints {
        let hint = hint.trim();
        if hint.is_empty() {
            continue;
        }
        if normalized.iter().any(|existing| existing == hint) {
            continue;
        }
        if normalized.len() == MAX_LEXICAL_QUERY_HINTS_PER_CLAIM {
            break;
        }
        if hint.len() > MAX_LEXICAL_QUERY_HINT_BYTES {
            return Err(Error::InvalidClaimBody(
                "lexical query hint exceeds 256 bytes",
            ));
        }
        normalized.push(hint.to_owned());
    }
    Ok(normalized)
}

#[must_use]
pub fn encode_lexical_query_hint_value(target: &EntityId, query: &str) -> Value {
    Value::Map(vec![
        (
            Value::from(LEXICAL_HINT_VALUE_KEY_KIND),
            Value::from(LEXICAL_HINT_KIND),
        ),
        (
            Value::from(LEXICAL_HINT_VALUE_KEY_QUERY),
            Value::from(query),
        ),
        (
            Value::from(LEXICAL_HINT_VALUE_KEY_TARGET),
            Value::Binary(target.as_bytes().to_vec()),
        ),
    ])
}

pub fn decode_lexical_query_hint_value(value: &Value) -> Result<LexicalQueryHintValue> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody(
            "lexical query hint value must be a map",
        ));
    };

    let mut kind: Option<&str> = None;
    let mut query: Option<String> = None;
    let mut target: Option<EntityId> = None;
    let mut seen_kind = false;
    let mut seen_query = false;
    let mut seen_target = false;

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidClaimBody(
                "lexical query hint value keys must be strings",
            ));
        };
        match key {
            LEXICAL_HINT_VALUE_KEY_KIND => {
                if seen_kind {
                    return Err(Error::InvalidClaimBody(
                        "duplicate lexical query hint value key",
                    ));
                }
                seen_kind = true;
                kind = value.as_str();
            }
            LEXICAL_HINT_VALUE_KEY_QUERY => {
                if seen_query {
                    return Err(Error::InvalidClaimBody(
                        "duplicate lexical query hint value key",
                    ));
                }
                seen_query = true;
                let Some(raw_query) = value.as_str() else {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint query must be a string",
                    ));
                };
                let normalized = normalize_lexical_query_hints(&[raw_query])?;
                let Some(raw_query) = normalized.into_iter().next() else {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint query must be non-empty",
                    ));
                };
                query = Some(raw_query);
            }
            LEXICAL_HINT_VALUE_KEY_TARGET => {
                if seen_target {
                    return Err(Error::InvalidClaimBody(
                        "duplicate lexical query hint value key",
                    ));
                }
                seen_target = true;
                let Value::Binary(bytes) = value else {
                    return Err(Error::InvalidClaimBody(
                        "lexical query hint target must be binary",
                    ));
                };
                let arr: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().map_err(|_| {
                    Error::InvalidClaimBody("lexical query hint target must be a 16-byte entity id")
                })?;
                target = Some(EntityId::from_bytes(arr).map_err(|_| {
                    Error::InvalidClaimBody("lexical query hint target id is reserved")
                })?);
            }
            _ => {
                return Err(Error::InvalidClaimBody(
                    "lexical query hint value key is not in the pinned set",
                ));
            }
        }
    }

    if kind != Some(LEXICAL_HINT_KIND) {
        return Err(Error::InvalidClaimBody(
            "lexical query hint kind must be prospective_query",
        ));
    }
    Ok(LexicalQueryHintValue {
        target: target.ok_or(Error::InvalidClaimBody("missing lexical query hint target"))?,
        query: query.ok_or(Error::InvalidClaimBody("missing lexical query hint query"))?,
    })
}

pub fn lexical_query_hint_target(body: &ClaimBody) -> Result<Option<EntityId>> {
    if body.predicate != PREDICATE_LEXICAL_QUERY_HINT {
        return Ok(None);
    }
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "lexical query hint subject must be an entity",
        ));
    };
    let value = decode_lexical_query_hint_value(&body.value)?;
    if value.target != subject {
        return Err(Error::InvalidClaimBody(
            "lexical query hint subject must match target",
        ));
    }
    Ok(Some(subject))
}

/// The id of the hint CLAIM that carries normalized `query` for `target`:
/// `EntityId::derive` under `derived_domains::LEXICAL_QUERY_HINT` of the
/// target's id bytes and the query's UTF-8 bytes.
pub fn lexical_query_hint_claim_id(target: &EntityId, query: &str) -> Result<EntityId> {
    EntityId::derive(LEXICAL_QUERY_HINT, &[target.as_bytes(), query.as_bytes()])
        .map_err(|_| Error::InvariantViolation("lexical query hint id derivation failed"))
}

/// The hint `body` carries when it is a lexical query hint stored under its
/// own id: the hint predicate, a subject equal to the encoded target, and
/// `id` equal to [`lexical_query_hint_claim_id`] of that target and query.
/// `None` for a CLAIM of any other predicate and for a hint body under any
/// other id; an error for a malformed hint body.
pub fn canonical_lexical_query_hint(
    id: &EntityId,
    body: &ClaimBody,
) -> Result<Option<LexicalQueryHintValue>> {
    if !id.has_derived_stamp() || lexical_query_hint_target(body)?.is_none() {
        return Ok(None);
    }
    let hint = decode_lexical_query_hint_value(&body.value)?;
    if lexical_query_hint_claim_id(&hint.target, &hint.query)? != *id {
        return Ok(None);
    }
    Ok(Some(hint))
}
