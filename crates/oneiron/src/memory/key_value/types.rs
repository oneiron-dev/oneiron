//! Typed actor-owned, worldless keyed-memory requests and results.
use serde::{Deserialize, Serialize};

/// Exact address. Segments are data, never wildcard or path syntax.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct KeyValueAddress {
    pub namespace: Vec<String>,
    pub key: String,
}

/// One synchronous write. Reuse request_id ONLY for an identical retry.
/// Replacement preserves claim source-trust rules: generated output cannot
/// supersede user-stated truth, even for the same actor/address. Never relabel
/// provenance to work around refusal; use a separate key for generated output.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyValuePut {
    pub namespace: Vec<String>,
    pub key: String,
    pub value: serde_json::Value,
    pub request_id: String,
    /// Claim source; omitted means generated, never observed/user_stated.
    #[serde(default = "generated_source")]
    pub source: String,
}

fn generated_source() -> String {
    "generated".to_owned()
}

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

/// Lexical, exact-segment namespace search, not ranked recall.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyValueSearch {
    #[serde(default)]
    pub namespace_prefix: Vec<String>,
    /// Exact top-level JSON value equality. Operators are not accepted.
    /// Numbers retain their JSON representation: integer `2` differs from
    /// floating `2.0`. Integers are never normalized through lossy `f64`.
    pub filter: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

/// Enumerates non-empty namespaces in lexical order; pages are live snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyValueNamespaces {
    #[serde(default)]
    pub prefix: Vec<String>,
    #[serde(default)]
    pub suffix: Vec<String>,
    pub max_depth: Option<usize>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}
fn default_limit() -> usize {
    100
}

impl Default for KeyValueSearch {
    fn default() -> Self {
        Self {
            namespace_prefix: Vec::new(),
            filter: None,
            limit: 100,
            offset: 0,
        }
    }
}
impl Default for KeyValueNamespaces {
    fn default() -> Self {
        Self {
            prefix: Vec::new(),
            suffix: Vec::new(),
            max_depth: None,
            limit: 100,
            offset: 0,
        }
    }
}
