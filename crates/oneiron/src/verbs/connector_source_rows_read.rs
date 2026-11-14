//! `connector.call_source_rows`: one held call's source rows the caller's lane admits, by ref.

use super::connector_call::ConnectorCallStatusRequest;
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::connector_source_rows_read::ConnectorCallSourceRows;

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
