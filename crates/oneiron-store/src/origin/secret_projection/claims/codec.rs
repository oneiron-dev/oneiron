//! The strict codec of a masked copy's records (FIX 7608 slice 2b-i,
//! CALL M): each record's fields at schema 1, the graph record's strict
//! decoder, and the value helpers every reader shares. Moved out of
//! `claims.rs` whole.

use rmpv::Value;

use crate::git_wire::ids::GitOid;
use crate::origin::secret_projection::claims::REPO_SECRET_PROJECTION_PREDICATE;
use crate::origin::secret_projection::claims::RepoProjectionPlace;
use crate::origin::secret_projection::claims::corrupt;
use crate::write_envelope::claim_body::ClaimBody;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;

/// A copy every masked reader is served, as a record names it.
pub const AUDIENCE_MASKED: &str = "masked";

/// A copy one proven recipient is served (FIX 9328), as a record names it.
pub const AUDIENCE_RECIPIENT: &str = "recipient";

/// CALL P2, as a record names it.
pub const POLICY_PRESERVE_PAYLOAD: &str = "preserve_payload";

/// CALL P3, as a record names it.
pub const LIFETIME_SOURCE_BOUND: &str = "source_bound";

pub fn place_value(place: &RepoProjectionPlace) -> Value {
    match place {
        RepoProjectionPlace::TreeEntry { mode, name } => Value::Array(vec![
            Value::from("tree_entry"),
            Value::from(*mode),
            Value::Binary(name.clone()),
        ]),
        RepoProjectionPlace::CommitTree => Value::Array(vec![Value::from("commit_tree")]),
        RepoProjectionPlace::CommitParent { index } => {
            Value::Array(vec![Value::from("commit_parent"), Value::from(*index)])
        }
        RepoProjectionPlace::TagTarget => Value::Array(vec![Value::from("tag_target")]),
    }
}

/// The place `value` names, as [`place_value`] wrote it.
pub fn decode_place(value: &Value) -> Result<RepoProjectionPlace> {
    let parts = value.as_array().ok_or_else(corrupt)?;
    let number = |value: &Value| {
        value
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .ok_or_else(corrupt)
    };
    match (parts.first().and_then(Value::as_str), parts.as_slice()) {
        (Some("tree_entry"), [_, mode, Value::Binary(name)]) => {
            Ok(RepoProjectionPlace::TreeEntry {
                mode: number(mode)?,
                name: name.clone(),
            })
        }
        (Some("commit_tree"), [_]) => Ok(RepoProjectionPlace::CommitTree),
        (Some("commit_parent"), [_, index]) => Ok(RepoProjectionPlace::CommitParent {
            index: number(index)?,
        }),
        (Some("tag_target"), [_]) => Ok(RepoProjectionPlace::TagTarget),
        _ => Err(corrupt()),
    }
}

/// An object's or a parent's occurrence: its byte path, or `nil`.
pub fn occurrence_value(occurrence: Option<&[u8]>) -> Value {
    occurrence.map_or(Value::Nil, |path| Value::Binary(path.to_vec()))
}

pub fn oid(oid: &GitOid) -> Value {
    Value::from(oid.as_str())
}

pub fn ids(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect())
}

pub fn fields(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

pub fn packed(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| Error::InvariantViolation("a masked copy record part did not encode"))?;
    Ok(out)
}

pub fn field<'v>(map: &'v [(Value, Value)], key: &str) -> Result<&'v Value> {
    map.iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
        .ok_or_else(corrupt)
}

pub fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(corrupt)
}

pub fn entity(value: &Value) -> Result<EntityId> {
    EntityId::from_hex(text(value)?).map_err(|_| corrupt())
}

pub fn digest_value(digest: &[u8; 32]) -> Value {
    Value::from(oneiron_contracts::entity_id::bytes_to_hex_lower(digest))
}

pub fn digest_of(value: &Value) -> Result<[u8; 32]> {
    let hex = text(value)?.as_bytes();
    let mut digest = [0_u8; 32];
    if hex.len() != 64 {
        return Err(corrupt());
    }
    for (at, pair) in hex.chunks(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| corrupt())?;
        digest[at] = u8::from_str_radix(pair, 16).map_err(|_| corrupt())?;
    }
    Ok(digest)
}

pub fn git_oid(value: &Value) -> Result<GitOid> {
    GitOid::parse_hex(text(value)?).map_err(|_| corrupt())
}
