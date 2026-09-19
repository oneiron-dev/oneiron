//! Conversation DAG topology, local HEAD state and exact scope resolution.
//!
//! Parent/SpawnedBy/RepliesTo are structural edges. HEAD and canonical marks
//! are device-local sidecars, not replicated authority. Every topology walk
//! fails closed at the shared ancestor cap.

mod admission;
mod graph;
pub(crate) use admission::validate_local_membership;
mod membership;
mod migration;
pub(crate) use membership::{stage_session_carrier, validate_session_carrier};

mod policy;
mod reply;
mod scopes;
mod types;
mod writes;

pub(crate) use graph::{actor_in_txn, conversation_of, edge_ids, require_type};
pub use reply::ReplyStrip;
pub(crate) use scopes::resolve_in_txn;
pub use types::{
    AppendRecord, AppendedRecord, DagPage, DagPageRequest, ResolvedScope, ScopePath, ScopeSelector,
};
pub(crate) use writes::append_in_txn;

#[cfg(test)]
#[path = "tests/support.rs"]
pub(crate) mod fixtures;

#[cfg(test)]
mod tests;

#[cfg(any(test, all(feature = "sync", feature = "test-hooks")))]
pub mod test_support;
