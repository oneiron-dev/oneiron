//! Historical money facts from the exact measured call's native usage settlement.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

/// The monetary quote frozen by the usage meter at admission, in nano-currency
/// units per million tokens. This snapshot is not a new price table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalMonetaryRates {
    pub currency: Option<String>,
    pub price_table_snapshot: String,
    pub input_per_million: u64,
    pub output_per_million: u64,
    pub cache_read_per_million: Option<u64>,
    pub cache_write_per_million: Option<u64>,
}

/// One priced physical call, matched to the exact measured binding. Counts
/// retain the provider's cache split; amount is in nano-currency units. A null
/// currency is possible only for the meter's existing free-in-any-currency case.
/// This is historical evidence, not current permission, a live quote or proof
/// that a ledger write completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCallPrice {
    pub binding_fingerprint: String,
    pub instance: String,
    pub lease: String,
    pub rates: EvalMonetaryRates,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub amount: u64,
    pub source_rows: Option<Vec<EntityId>>,
}
