//! `connector.call_source_rows`: one held call's source rows the caller's lane admits, by ref.

use serde::{Deserialize, Serialize};

use super::connector_call::ConnectorCallStatusRequest;
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};

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

/// `connector.call_source_rows` on a handle: reads `input.call_ref` as the handle's actor.
/// An agent needs its live owner Grant listing the verb, checked in the serving snapshot;
/// a person stands by liveness. Only the caller and the vault's owner read a call, with
/// the exact not-found `connector.call_status` reads for a foreign or missing ref.
pub fn connector_call_source_rows_embedded(
    memory: &Memory<'_>,
    input: ConnectorCallStatusRequest,
) -> MemoryResult<ConnectorCallSourceRows> {
    let call_ref = EntityId::from_hex(&input.call_ref)
        .map_err(|_| MemoryError::bad_request("call_ref must be 32 hex"))?;
    let source_rows = memory.connector_call_source_rows(&call_ref)?;
    Ok(ConnectorCallSourceRows {
        call_ref: call_ref.to_hex(),
        source_rows: source_rows.map(|ids| ids.iter().map(|id| id.to_hex()).collect()),
    })
}
