//! Moved from `crates/oneiron/src/memory/key_value/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::memory::key_value::types::KeyValueAddress;
pub use oneiron_verb_wire::memory::key_value::types::KeyValueNamespaces;
pub use oneiron_verb_wire::memory::key_value::types::KeyValuePut;
pub use oneiron_verb_wire::memory::key_value::types::KeyValueSearch;
use serde::Deserialize;
use serde::Serialize;

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
