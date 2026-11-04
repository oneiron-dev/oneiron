//! World-access authority values and their strict claim-value codecs.

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use rmpv::Value;
use std::collections::BTreeSet;

pub use crate::store::world_authority::{
    ActiveWorldSelection, ResolvedWorldAuthority, WorldAuthoritySet,
};
pub use crate::write_envelope::world_access_predicates::{
    PREDICATE_WORLD_ACCESS_ALLOWED_SET, PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
};

/// Pinned schema version of both world-access authority claim values
/// (ONE-1420). A stored row carrying any other version fails closed instead of
/// being read under an assumed shape.
pub const WORLD_ACCESS_SCHEMA_VERSION: u64 = 1;

const WORLD_ACCESS_VALUE_KEY_SCHEMA_VERSION: &str = "schema_version";
const WORLD_ACCESS_VALUE_KEY_INCLUDE_BASE: &str = "include_base";
const WORLD_ACCESS_VALUE_KEY_WORLDS: &str = "worlds";

/// Builds the CLAIM body for one world-access authority row.
///
/// The row is an ORDINARY bitemporal claim: subject = the agent entity, value
/// = the pinned strict map, lifecycle = active, and the caller's `source` /
/// `approval` / `valid_from` / `valid_to` verbatim. Writing it goes through the
/// ordinary claim door, so supersession, retraction and the write gate behave
/// exactly as they do for every other claim.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when `predicate` is not one of the two pinned
/// world-access predicates, or when the validity window is empty
/// (`valid_to <= valid_from`), which would mint a row that is never in force.
pub fn world_access_claim_body(
    predicate: &'static str,
    agent_ref: EntityId,
    value: &WorldAuthoritySet,
    source: ClaimSource,
    approval: ClaimApprovalStatus,
    valid_from: Option<u64>,
    valid_to: Option<u64>,
) -> Result<ClaimBody> {
    if predicate != PREDICATE_WORLD_ACCESS_ALLOWED_SET
        && predicate != PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET
    {
        return Err(Error::InvalidConfig(format!(
            "{predicate} is not a world-access authority predicate"
        )));
    }
    if let (Some(from), Some(to)) = (valid_from, valid_to)
        && to <= from
    {
        return Err(Error::InvalidConfig(format!(
            "world-access validity window is empty: valid_to {to} does not follow valid_from {from}"
        )));
    }

    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(agent_ref),
        encode_world_access_claim_value(value),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(source);
    body.valid_from = valid_from;
    body.valid_to = valid_to;
    Ok(body)
}

/// Encodes an authority set as the pinned strict claim value.
///
/// `worlds` is emitted from the `BTreeSet`, so the array is sorted and unique
/// on the wire by construction — the exact shape
/// [`decode_world_access_claim_value`] admits.
fn encode_world_access_claim_value(value: &WorldAuthoritySet) -> Value {
    Value::Map(vec![
        (
            Value::from(WORLD_ACCESS_VALUE_KEY_SCHEMA_VERSION),
            Value::from(WORLD_ACCESS_SCHEMA_VERSION),
        ),
        (
            Value::from(WORLD_ACCESS_VALUE_KEY_INCLUDE_BASE),
            Value::Boolean(value.include_base()),
        ),
        (
            Value::from(WORLD_ACCESS_VALUE_KEY_WORLDS),
            Value::Array(
                value
                    .worlds()
                    .iter()
                    .map(|world| Value::Binary(world.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
    ])
}

/// Decodes the strict world-access claim value:
///
/// ```text
/// { "schema_version": 1, "include_base": <bool>, "worlds": [<16-byte binary>, ...] }
/// ```
///
/// Every deviation fails CLOSED with [`Error::InvalidConfig`]: a non-map value,
/// a non-string key, an unknown or duplicated key, a missing key, an
/// unsupported `schema_version`, a non-boolean `include_base`, a non-array
/// `worlds`, an element that is not exactly 16 bytes of MessagePack binary, and
/// an out-of-order or duplicated world id. A list of any length is read whole
/// (FIX 8668). A malformed authority row can therefore never
/// be read as a WIDER authority than it encodes — the read that consulted it
/// refuses instead.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for every shape listed above.
pub fn decode_world_access_claim_value(body: &ClaimBody) -> Result<WorldAuthoritySet> {
    let Value::Map(entries) = &body.value else {
        return Err(invalid_world_access_value("must be a MessagePack map"));
    };

    let mut schema_version: Option<u64> = None;
    let mut include_base: Option<bool> = None;
    let mut worlds: Option<BTreeSet<EntityId>> = None;

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_world_access_value("keys must be strings"));
        };
        match key {
            WORLD_ACCESS_VALUE_KEY_SCHEMA_VERSION => {
                if schema_version.is_some() {
                    return Err(invalid_world_access_value("repeats schema_version"));
                }
                let version = value.as_u64().ok_or_else(|| {
                    invalid_world_access_value("schema_version must be an unsigned integer")
                })?;
                schema_version = Some(version);
            }
            WORLD_ACCESS_VALUE_KEY_INCLUDE_BASE => {
                if include_base.is_some() {
                    return Err(invalid_world_access_value("repeats include_base"));
                }
                let Value::Boolean(flag) = value else {
                    return Err(invalid_world_access_value("include_base must be a boolean"));
                };
                include_base = Some(*flag);
            }
            WORLD_ACCESS_VALUE_KEY_WORLDS => {
                if worlds.is_some() {
                    return Err(invalid_world_access_value("repeats worlds"));
                }
                worlds = Some(decode_world_access_members(value)?);
            }
            _ => {
                return Err(invalid_world_access_value(
                    "carries a key outside schema_version/include_base/worlds",
                ));
            }
        }
    }

    let schema_version =
        schema_version.ok_or_else(|| invalid_world_access_value("is missing schema_version"))?;
    if schema_version != WORLD_ACCESS_SCHEMA_VERSION {
        return Err(Error::InvalidConfig(format!(
            "world-access claim value schema_version {schema_version} is not the supported \
             {WORLD_ACCESS_SCHEMA_VERSION}"
        )));
    }
    let include_base =
        include_base.ok_or_else(|| invalid_world_access_value("is missing include_base"))?;
    let worlds = worlds.ok_or_else(|| invalid_world_access_value("is missing worlds"))?;

    WorldAuthoritySet::new(include_base, worlds)
}

/// Decodes the `worlds` array: strictly ascending 16-byte binary ids, every
/// one of them.
fn decode_world_access_members(value: &Value) -> Result<BTreeSet<EntityId>> {
    let Value::Array(items) = value else {
        return Err(invalid_world_access_value("worlds must be an array"));
    };
    let mut members = BTreeSet::new();
    let mut previous: Option<EntityId> = None;
    for item in items {
        let Value::Binary(bytes) = item else {
            return Err(invalid_world_access_value(
                "world ids must be MessagePack binary",
            ));
        };
        let raw: [u8; ENTITY_ID_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid_world_access_value("world ids must be exactly 16 binary bytes"))?;
        let world = EntityId::from_bytes(raw)
            .map_err(|_| invalid_world_access_value("carries a reserved world id"))?;
        if previous.is_some_and(|previous| previous >= world) {
            return Err(invalid_world_access_value(
                "worlds must be sorted ascending and unique",
            ));
        }
        previous = Some(world);
        members.insert(world);
    }
    Ok(members)
}

fn invalid_world_access_value(reason: &str) -> Error {
    Error::InvalidConfig(format!("world-access claim value {reason}"))
}
