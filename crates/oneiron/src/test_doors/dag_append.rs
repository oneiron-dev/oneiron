//! Doors for `tests/dag_append_composed_source.rs` (DAG-APPEND-SOURCE-LABEL):
//! the source label each of the DAG append door's two gate checks gives a
//! record. Read-only; nothing is written.

use crate::WriteActor;
use crate::claim::ClaimSource;

/// The label a record that holds its writer's own words carries: every
/// public append door's, and a thread reply's.
#[must_use]
pub fn append_source(writer: WriteActor) -> ClaimSource {
    crate::conversation_dag::append_source(writer)
}

/// The label a record whose words the engine composed carries, whoever's
/// actor it lands under: a scope summary's reply and a Retry's turn.
#[must_use]
pub fn composed_append_source() -> ClaimSource {
    crate::conversation_dag::composed_append_source()
}
