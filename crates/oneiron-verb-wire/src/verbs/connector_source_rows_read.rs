//! Moved from `crates/oneiron/src/verbs/connector_source_rows_read.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `connector.call_source_rows`'s answer: the call's ref and the source rows the caller's
/// lane admits, 32 hex each, in the call's stored order. `None` is a call whose rows are
/// unknown, and an acknowledged call whose rows ride its wait's reply instead; `Some` keeps
/// an empty set distinct from unknown. Withheld rows are dropped silently, never an error,
/// and add no public count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorCallSourceRows {
    /// The `call_ref` read, 32 hex.
    pub call_ref: String,
    /// The rows the call's passes picked that the caller's lane admits, 32 hex each.
    pub source_rows: Option<Vec<String>>,
}
