//! The GOV-10 charter blocks of a connector key body: the stamped
//! charter and the staged proposal.

use rmpv::Value;

use crate::error::Result;

use super::super::record::{ConnectorCharterBlock, PendingConnectorCharter};
use super::{
    decode_compiled_policy, decode_hash32, decode_non_empty_string, encode_compiled_policy,
    malformed, required_value, validate_keys,
};

const CHARTER_BLOCK_KEYS: [&str; 7] = [
    "text",
    "text_hash",
    "compiled",
    "compiled_hash",
    "stamped_aggregate",
    "stamped_by",
    "stamped_at",
];
const PENDING_CHARTER_KEYS: [&str; 5] = [
    "text",
    "text_hash",
    "compiled",
    "compiled_hash",
    "proposed_at",
];

pub(super) fn encode_charter_block(charter: &ConnectorCharterBlock) -> Value {
    Value::Map(vec![
        (
            Value::from(CHARTER_BLOCK_KEYS[0]),
            Value::from(charter.text.clone()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[1]),
            Value::Binary(charter.text_hash.to_vec()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[2]),
            encode_compiled_policy(&charter.compiled),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[3]),
            Value::Binary(charter.compiled_hash.to_vec()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[4]),
            Value::Binary(charter.stamped_aggregate.to_vec()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[5]),
            Value::from(charter.stamped_by.clone()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[6]),
            Value::from(charter.stamped_at),
        ),
    ])
}

pub(super) fn encode_pending_charter(pending: &PendingConnectorCharter) -> Value {
    Value::Map(vec![
        (
            Value::from(PENDING_CHARTER_KEYS[0]),
            Value::from(pending.text.clone()),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[1]),
            Value::Binary(pending.text_hash.to_vec()),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[2]),
            encode_compiled_policy(&pending.compiled),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[3]),
            Value::Binary(pending.compiled_hash.to_vec()),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[4]),
            Value::from(pending.proposed_at),
        ),
    ])
}

pub(super) fn decode_optional_charter_block(
    value: &Value,
) -> Result<Option<ConnectorCharterBlock>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &CHARTER_BLOCK_KEYS)?;
    Ok(Some(ConnectorCharterBlock {
        text: decode_non_empty_string(required_value(entries, CHARTER_BLOCK_KEYS[0])?)?,
        text_hash: decode_hash32(required_value(entries, CHARTER_BLOCK_KEYS[1])?)?,
        compiled: decode_compiled_policy(required_value(entries, CHARTER_BLOCK_KEYS[2])?)?,
        compiled_hash: decode_hash32(required_value(entries, CHARTER_BLOCK_KEYS[3])?)?,
        stamped_aggregate: decode_hash32(required_value(entries, CHARTER_BLOCK_KEYS[4])?)?,
        stamped_by: decode_non_empty_string(required_value(entries, CHARTER_BLOCK_KEYS[5])?)?,
        stamped_at: required_value(entries, CHARTER_BLOCK_KEYS[6])?
            .as_u64()
            .ok_or_else(malformed)?,
    }))
}

pub(super) fn decode_optional_pending_charter(
    value: &Value,
) -> Result<Option<PendingConnectorCharter>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &PENDING_CHARTER_KEYS)?;
    Ok(Some(PendingConnectorCharter {
        text: decode_non_empty_string(required_value(entries, PENDING_CHARTER_KEYS[0])?)?,
        text_hash: decode_hash32(required_value(entries, PENDING_CHARTER_KEYS[1])?)?,
        compiled: decode_compiled_policy(required_value(entries, PENDING_CHARTER_KEYS[2])?)?,
        compiled_hash: decode_hash32(required_value(entries, PENDING_CHARTER_KEYS[3])?)?,
        proposed_at: required_value(entries, PENDING_CHARTER_KEYS[4])?
            .as_u64()
            .ok_or_else(malformed)?,
    }))
}
