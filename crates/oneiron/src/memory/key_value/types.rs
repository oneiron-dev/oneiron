//! Typed actor-owned, worldless keyed-memory requests and results.
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::key_value::types::{
    KeyValueAddress, KeyValueNamespaces, KeyValuePut, KeyValueSearch,
};
#[doc(hidden)]
use oneiron_verb_wire::memory::key_value::types::{default_limit, generated_source};

/// An exact, committed item. Times are Unix seconds, not milliseconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyValueItem {
    pub namespace: Vec<String>,
    pub key: String,
    pub value: serde_json::Value,
    pub created_at: u64,
    pub updated_at: u64,
    pub revision: String,
}

/// No proposed/rejected write is represented as a successful put.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyValuePutReceipt {
    pub item: KeyValueItem,
    pub replayed: bool,
    pub receipt_ref: String,
}

/// Deletion withdraws the caller's claims; it does not erase history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyValueDeleteReceipt {
    pub existed: bool,
    pub receipt_refs: Vec<String>,
}
