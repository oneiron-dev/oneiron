//! Msgpack codec for ledger records and usage error mapping.
use super::allowance::{ConsumerAllowanceRecord, ConsumerTopUp};
use super::ledger::StoredUsageEvent;
use super::model::UsageRollup;

pub(super) fn encode_entry(entry: &StoredUsageEvent) -> Result<Vec<u8>, UsageError> {
    rmp_serde::to_vec_named(entry).map_err(UsageError::encode)
}

pub(super) fn decode_entry(raw: &[u8]) -> Result<StoredUsageEvent, UsageError> {
    rmp_serde::from_slice(raw).map_err(UsageError::decode)
}

pub(super) fn encode_rollup(rollup: &UsageRollup) -> Result<Vec<u8>, UsageError> {
    rmp_serde::to_vec_named(rollup).map_err(UsageError::encode)
}

pub(super) fn decode_rollup(raw: &[u8]) -> Result<UsageRollup, UsageError> {
    rmp_serde::from_slice(raw).map_err(UsageError::decode)
}

pub(super) fn encode_allowance(allowance: &ConsumerAllowanceRecord) -> Result<Vec<u8>, UsageError> {
    rmp_serde::to_vec_named(allowance).map_err(UsageError::encode)
}

pub(super) fn decode_allowance(raw: &[u8]) -> Result<ConsumerAllowanceRecord, UsageError> {
    rmp_serde::from_slice(raw).map_err(UsageError::decode)
}

pub(super) fn encode_top_up(top_up: &ConsumerTopUp) -> Result<Vec<u8>, UsageError> {
    rmp_serde::to_vec_named(top_up).map_err(UsageError::encode)
}

pub(super) fn decode_top_up(raw: &[u8]) -> Result<ConsumerTopUp, UsageError> {
    rmp_serde::from_slice(raw).map_err(UsageError::decode)
}

#[derive(Debug, thiserror::Error)]
pub enum UsageError {
    #[error("{field}: {message}")]
    InvalidField {
        field: &'static str,
        message: &'static str,
    },
    #[error("usage ledger storage error: {0}")]
    Storage(#[from] oneiron::Error),
    #[error("usage ledger encode error: {0}")]
    Encode(rmp_serde::encode::Error),
    #[error("usage ledger decode error: {0}")]
    Decode(rmp_serde::decode::Error),
    #[error(
        "idempotency key {idempotency_key} for tenant {tenant_id} conflicts with a recorded top-up"
    )]
    IdempotencyConflict {
        tenant_id: String,
        idempotency_key: String,
    },
    #[error("usage ledger lock poisoned")]
    LockPoisoned,
}

impl UsageError {
    fn encode(error: rmp_serde::encode::Error) -> Self {
        Self::Encode(error)
    }

    fn decode(error: rmp_serde::decode::Error) -> Self {
        Self::Decode(error)
    }

    pub fn field(&self) -> Option<&'static str> {
        match self {
            Self::InvalidField { field, .. } => Some(field),
            _ => None,
        }
    }
}
