//! Msgpack codec for durable meter facts.
use super::{ledger::StoredUsageEvent, model::UsageRollup};
pub(super) fn encode_entry(value: &StoredUsageEvent) -> Result<Vec<u8>, UsageError> {
    Ok(rmp_serde::to_vec_named(value)?)
}
pub(super) fn decode_entry(raw: &[u8]) -> Result<StoredUsageEvent, UsageError> {
    Ok(rmp_serde::from_slice(raw)?)
}
pub(super) fn encode_rollup(value: &UsageRollup) -> Result<Vec<u8>, UsageError> {
    Ok(rmp_serde::to_vec_named(value)?)
}
pub(super) fn decode_rollup(raw: &[u8]) -> Result<UsageRollup, UsageError> {
    Ok(rmp_serde::from_slice(raw)?)
}
#[derive(Debug, thiserror::Error)]
pub enum UsageError {
    #[error("{field}: {message}")]
    InvalidField {
        field: &'static str,
        message: &'static str,
    },
    #[error("usage storage: {0}")]
    Storage(#[from] oneiron::Error),
    #[error("usage encode: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("usage decode: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("idempotency key conflicts with recorded usage")]
    IdempotencyConflict,
    #[error("usage arithmetic overflow")]
    Overflow,
    #[error("budget denied: {0}")]
    BudgetDenied(#[from] oneiron::llm::BudgetDenied),
}
impl UsageError {
    pub fn field(&self) -> Option<&'static str> {
        if let Self::InvalidField { field, .. } = self {
            Some(field)
        } else {
            None
        }
    }
}
