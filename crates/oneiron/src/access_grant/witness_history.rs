//! Unsigned witness-read lifecycle metadata, stored with its grant body.

use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;

use super::codec::{
    KEY_WITNESS_HISTORY, decode_entity_ref, decode_live_access_grant_body, invalid_grant,
    read_body, required_value, validate_keys,
};
use super::{AccessGrant, AccessGrantStatus};

const HISTORY_KEYS: [&str; 2] = ["generation_ref", "prior"];
const GENERATION_KEYS: [&str; 4] = ["generation_ref", "created_at", "revoked_at", "status"];

struct WitnessReadHistory {
    generation_ref: EntityId,
    prior: Vec<WitnessReadGeneration>,
}

pub(crate) struct WitnessReadGeneration {
    pub(crate) generation_ref: EntityId,
    pub(crate) created_at: u64,
    pub(crate) revoked_at: Option<u64>,
    pub(crate) status: AccessGrantStatus,
}

impl WitnessReadGeneration {
    fn from_grant(generation_ref: EntityId, grant: &AccessGrant) -> Self {
        Self {
            generation_ref,
            created_at: grant.created_at,
            revoked_at: grant.revoked_at,
            status: grant.status,
        }
    }
}

/// Carries lifecycle metadata through the grant's existing same-writer Put.
/// Erased bodies bypass the carry: their encoder's nil metadata remains nil.
pub(super) fn with_witness_read_history_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    data: Vec<u8>,
) -> Result<Vec<u8>> {
    let Some(grant) = decode_live_access_grant_body(&data)? else {
        return Ok(data);
    };
    if crate::ingest::connector_witness_read_reason(id, &grant).is_none() {
        return Ok(data);
    }
    let standing = match crate::vault::live_entity_row_in_txn(&vault.store, txn, id)? {
        crate::vault::LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_ACCESS_GRANT,
            body,
        } => match decode_live_access_grant_body(&body)? {
            Some(old) if crate::ingest::connector_witness_read_reason(id, &old).is_some() => {
                decode_history(&body)?.map(|history| (old, history))
            }
            _ => None,
        },
        _ => None,
    };
    let history = match standing {
        Some((old, mut history)) => {
            let new_generation = grant.created_at != old.created_at
                || (grant.status == AccessGrantStatus::Active
                    && old.effective_status_at(grant.created_at) != AccessGrantStatus::Active);
            if new_generation {
                history.prior.push(WitnessReadGeneration::from_grant(
                    history.generation_ref,
                    &old,
                ));
                history.generation_ref = EntityId::now();
            }
            history
        }
        None => WitnessReadHistory {
            generation_ref: EntityId::now(),
            prior: Vec::new(),
        },
    };
    let Value::Map(mut entries) = read_body(&data)? else {
        return Err(invalid_grant());
    };
    let value = entries
        .iter_mut()
        .find_map(|(key, value)| (key.as_str() == Some(KEY_WITNESS_HISTORY)).then_some(value))
        .ok_or_else(invalid_grant)?;
    *value = encode_history(&history);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("access grant history MessagePack encode failed"))?;
    Ok(out)
}

/// Returns prior snapshots and the current generation, never a synthesized id.
/// This metadata is not an authority input or an owner-act signature.
pub(crate) fn witness_read_generations(
    body: &[u8],
    grant: &AccessGrant,
) -> Result<Vec<WitnessReadGeneration>> {
    let Some(mut history) = decode_history(body)? else {
        return Ok(Vec::new());
    };
    history.prior.push(WitnessReadGeneration::from_grant(
        history.generation_ref,
        grant,
    ));
    Ok(history.prior)
}

fn encode_history(history: &WitnessReadHistory) -> Value {
    Value::Map(vec![
        (
            HISTORY_KEYS[0].into(),
            history.generation_ref.to_hex().into(),
        ),
        (
            HISTORY_KEYS[1].into(),
            Value::Array(history.prior.iter().map(encode_generation).collect()),
        ),
    ])
}

fn encode_generation(generation: &WitnessReadGeneration) -> Value {
    Value::Map(vec![
        (
            GENERATION_KEYS[0].into(),
            generation.generation_ref.to_hex().into(),
        ),
        (GENERATION_KEYS[1].into(), generation.created_at.into()),
        (
            GENERATION_KEYS[2].into(),
            generation.revoked_at.map_or(Value::Nil, Value::from),
        ),
        (GENERATION_KEYS[3].into(), generation.status.as_str().into()),
    ])
}

fn decode_history(body: &[u8]) -> Result<Option<WitnessReadHistory>> {
    let Value::Map(entries) = read_body(body)? else {
        return Err(invalid_grant());
    };
    let value = required_value(&entries, KEY_WITNESS_HISTORY)?;
    let Value::Map(history) = value else {
        return match value {
            Value::Nil => Ok(None),
            _ => Err(invalid_grant()),
        };
    };
    validate_keys(history, &HISTORY_KEYS)?;
    let generation_ref = decode_entity_ref(required_value(history, HISTORY_KEYS[0])?)?;
    let prior = required_value(history, HISTORY_KEYS[1])?
        .as_array()
        .ok_or_else(invalid_grant)?
        .iter()
        .map(decode_generation)
        .collect::<Result<Vec<_>>>()?;
    let mut identities = std::collections::BTreeSet::from([generation_ref]);
    if prior
        .iter()
        .any(|generation| !identities.insert(generation.generation_ref))
    {
        return Err(invalid_grant());
    }
    Ok(Some(WitnessReadHistory {
        generation_ref,
        prior,
    }))
}

fn decode_generation(value: &Value) -> Result<WitnessReadGeneration> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    validate_keys(entries, &GENERATION_KEYS)?;
    let generation_ref = decode_entity_ref(required_value(entries, GENERATION_KEYS[0])?)?;
    let created_at = required_value(entries, GENERATION_KEYS[1])?
        .as_u64()
        .ok_or_else(invalid_grant)?;
    let revoked_at = match required_value(entries, GENERATION_KEYS[2])? {
        Value::Nil => None,
        value => Some(value.as_u64().ok_or_else(invalid_grant)?),
    };
    let status = required_value(entries, GENERATION_KEYS[3])?
        .as_str()
        .and_then(AccessGrantStatus::parse)
        .ok_or_else(invalid_grant)?;
    if match (status, revoked_at) {
        (AccessGrantStatus::Active | AccessGrantStatus::Expired, None) => false,
        (AccessGrantStatus::Revoked, Some(at)) => at < created_at,
        _ => true,
    } {
        return Err(invalid_grant());
    }
    Ok(WitnessReadGeneration {
        generation_ref,
        created_at,
        revoked_at,
        status,
    })
}
