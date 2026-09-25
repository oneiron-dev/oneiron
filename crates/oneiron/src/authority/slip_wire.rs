//! Field-by-field signed capability claims and six-axis Scope wire codec.
use super::wire_decode::decode_optional_hash;
use super::*;
use crate::error::Result;
use crate::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use rmpv::Value;
use std::collections::BTreeSet;

pub(super) fn slip_mint_value(action: &SlipMintAction) -> Value {
    let claims = &action.claims;
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(OP_KIND_SLIP_MINT)),
        (Value::from(SLIP_KEY_SLIP_ID), binary_value(claims.slip_id)),
        (
            Value::from(SLIP_KEY_VAULT_ID),
            binary_value(claims.vault_id),
        ),
        (
            Value::from(SLIP_KEY_PARENT_ID),
            claims.parent_id.map_or(Value::Nil, binary_value),
        ),
        (
            Value::from(SLIP_KEY_HOLDER_REF),
            Value::from(claims.holder_ref.as_str()),
        ),
        (
            Value::from(SLIP_KEY_BINDING_KEY),
            binary_value(claims.binding_key),
        ),
        (Value::from(SLIP_KEY_SCOPE), scope_value(&claims.scope)),
        (
            Value::from(SLIP_KEY_ISSUED_AT),
            Value::from(claims.issued_at),
        ),
        (
            Value::from(SLIP_KEY_EXPIRES_AT),
            Value::from(claims.expires_at),
        ),
        (Value::from(SLIP_KEY_TTL_SECS), Value::from(claims.ttl_secs)),
        (
            Value::from(SLIP_KEY_SINGLE_USE),
            Value::from(claims.single_use),
        ),
        (
            Value::from(SLIP_KEY_RECORDS),
            strings_value(&claims.records),
        ),
        (
            Value::from(SLIP_KEY_CHANNELS),
            strings_value(&claims.channels),
        ),
        (
            Value::from(SLIP_KEY_ACTOR_CLASS),
            claims
                .actor_class
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(SLIP_KEY_ORG_REF),
            claims.org_ref.as_deref().map_or(Value::Nil, Value::from),
        ),
    ])
}

pub(super) fn decode_slip_mint(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &SLIP_MINT_KEYS)?;
    let claims = SlipClaims {
        slip_id: {
            let value = required(entries, SLIP_KEY_SLIP_ID)?;
            decode_hash(value)?
        },
        vault_id: {
            let value = required(entries, SLIP_KEY_VAULT_ID)?;
            decode_hash(value)?
        },
        parent_id: {
            let value = required(entries, SLIP_KEY_PARENT_ID)?;
            decode_optional_hash(value)?
        },
        holder_ref: {
            let value = required(entries, SLIP_KEY_HOLDER_REF)?;
            decode_string(value)?
        },
        binding_key: {
            let value = required(entries, SLIP_KEY_BINDING_KEY)?;
            decode_hash(value)?
        },
        scope: {
            let value = required(entries, SLIP_KEY_SCOPE)?;
            decode_scope(value)?
        },
        issued_at: {
            let value = required(entries, SLIP_KEY_ISSUED_AT)?;
            value.as_u64().ok_or_else(invalid_authority)?
        },
        expires_at: {
            let value = required(entries, SLIP_KEY_EXPIRES_AT)?;
            value.as_u64().ok_or_else(invalid_authority)?
        },
        ttl_secs: {
            let value = required(entries, SLIP_KEY_TTL_SECS)?;
            value.as_u64().ok_or_else(invalid_authority)?
        },
        single_use: {
            let value = required(entries, SLIP_KEY_SINGLE_USE)?;
            value.as_bool().ok_or_else(invalid_authority)?
        },
        records: {
            let value = required(entries, SLIP_KEY_RECORDS)?;
            decode_set(value, decode_string)?
        },
        channels: {
            let value = required(entries, SLIP_KEY_CHANNELS)?;
            decode_set(value, decode_string)?
        },
        actor_class: {
            let value = required(entries, SLIP_KEY_ACTOR_CLASS)?;
            decode_optional_string(value)?
        },
        org_ref: {
            let value = required(entries, SLIP_KEY_ORG_REF)?;
            decode_optional_string(value)?
        },
    };
    claims.validate()?;
    Ok(AuthorityOp::SlipMint(SlipMintAction { claims }))
}

fn strings_value(values: &BTreeSet<String>) -> Value {
    Value::Array(values.iter().map(|v| Value::from(v.as_str())).collect())
}

fn axis_value<T: Ord>(axis: &ScopeAxis<T>, encode: impl Fn(&T) -> Value) -> Value {
    match axis {
        ScopeAxis::Bottom => Value::Nil,
        ScopeAxis::All => Value::Boolean(true),
        ScopeAxis::Some(values) if values.is_empty() => Value::Nil,
        ScopeAxis::Some(values) => Value::Array(values.iter().map(encode).collect()),
    }
}

fn scope_value(scope: &Scope) -> Value {
    let id = |v: &ScopeId| Value::from(v.0.to_hex());
    Value::Map(vec![
        (Value::from(SCOPE_KEY_WORLDS), axis_value(&scope.worlds, id)),
        (Value::from(SCOPE_KEY_FACETS), axis_value(&scope.facets, id)),
        (
            Value::from(SCOPE_KEY_BANDS),
            axis_value(&scope.bands, |v| Value::from(*v)),
        ),
        (
            Value::from(SCOPE_KEY_AUDIENCE),
            axis_value(&scope.audience, id),
        ),
        (
            Value::from(SCOPE_KEY_VERBS),
            axis_value(&scope.verbs, |v| Value::from(v.as_str())),
        ),
        (
            Value::from(SCOPE_KEY_SENSITIVITY),
            match scope.sensitivity {
                SensitivityCeiling::Bottom => Value::Nil,
                SensitivityCeiling::AtMost(band) => Value::from(band.as_str()),
            },
        ),
    ])
}

fn decode_scope(value: &Value) -> Result<Scope> {
    let entries = map_entries(value)?;
    validate_keys(entries, &SLIP_SCOPE_KEYS)?;
    let id = |v: &Value| decode_id(v).map(ScopeId);
    Ok(Scope {
        worlds: decode_axis(required(entries, SCOPE_KEY_WORLDS)?, id)?,
        facets: decode_axis(required(entries, SCOPE_KEY_FACETS)?, id)?,
        bands: decode_axis(required(entries, SCOPE_KEY_BANDS)?, |v| {
            u8::try_from(v.as_u64().ok_or_else(invalid_authority)?).map_err(|_| invalid_authority())
        })?,
        audience: decode_axis(required(entries, SCOPE_KEY_AUDIENCE)?, id)?,
        verbs: decode_axis(required(entries, SCOPE_KEY_VERBS)?, decode_string)?,
        sensitivity: match required(entries, SCOPE_KEY_SENSITIVITY)? {
            Value::Nil => SensitivityCeiling::Bottom,
            v => SensitivityCeiling::AtMost(
                v.as_str()
                    .and_then(Sensitivity::parse)
                    .ok_or_else(invalid_authority)?,
            ),
        },
    })
}

fn decode_axis<T: Ord>(
    value: &Value,
    decode: impl Fn(&Value) -> Result<T>,
) -> Result<ScopeAxis<T>> {
    match value {
        Value::Nil => Ok(ScopeAxis::Bottom),
        Value::Boolean(true) => Ok(ScopeAxis::All),
        Value::Array(_) => {
            let values = decode_set(value, decode)?;
            if values.is_empty() {
                return Err(invalid_authority());
            }
            Ok(ScopeAxis::Some(values))
        }
        _ => Err(invalid_authority()),
    }
}

fn decode_set<T: Ord>(value: &Value, decode: impl Fn(&Value) -> Result<T>) -> Result<BTreeSet<T>> {
    let values = value.as_array().ok_or_else(invalid_authority)?;
    let set: BTreeSet<T> = values.iter().map(decode).collect::<Result<_>>()?;
    if set.len() != values.len() {
        return Err(invalid_authority());
    }
    Ok(set)
}

fn decode_id(value: &Value) -> Result<crate::EntityId> {
    let text = value.as_str().ok_or_else(invalid_authority)?;
    let id = crate::EntityId::from_hex(text).map_err(|_| invalid_authority())?;
    if id.to_hex() != text {
        return Err(invalid_authority());
    }
    Ok(id)
}

fn decode_string(value: &Value) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(invalid_authority)
}
fn decode_optional_string(value: &Value) -> Result<Option<String>> {
    if value.is_nil() {
        Ok(None)
    } else {
        decode_string(value).map(Some)
    }
}
