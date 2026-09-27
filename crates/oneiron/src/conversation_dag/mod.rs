//! Conversation DAG topology, local HEAD state and exact scope resolution.
//!
//! Parent/SpawnedBy/RepliesTo are structural edges. HEAD and canonical marks
//! are device-local sidecars, not replicated authority. Every topology walk
//! fails closed at the shared ancestor cap.

mod admission;
mod graph;
#[cfg(feature = "sync")]
pub(crate) use admission::{addressed_to_echo, addressed_to_echo_in_txn};
pub(crate) mod topology;
pub(crate) use admission::{
    guard_record_put, keep_membership_pin, pin_membership, pin_typed_record,
    validate_local_membership,
};
#[cfg(feature = "sync")]
pub(crate) use admission::{validate_received_edge, validate_received_parent_value};
mod membership;
mod migration;
pub(crate) use membership::{stage_session_carrier, validate_session_carrier};

mod branch_scope;
mod policy;
mod reply;
pub(crate) mod retained_path;
mod scopes;
mod thread_projection;
mod types;
mod writes;

pub(crate) use branch_scope::{prove_branch_anchor, prove_branch_span};
pub(crate) use graph::{
    actor_in_txn, conversation_of, edge_ids, is_sub_session_record, require_type,
};
pub use reply::{ReplyStrip, Thread, ThreadMeta};
pub(crate) use reply::{invalidate_thread_meta, invalidate_thread_meta_for_turn_put};
pub(crate) use scopes::resolve_in_txn;
pub(crate) use thread_projection::selected_thread_in_txn;
pub use types::{
    AddressMode, AppendRecord, AppendedRecord, DagPage, DagPageRequest, ResolvedScope, ScopePath,
    ScopeSelector,
};
pub(crate) use writes::append_in_txn;

#[cfg(test)]
pub(crate) mod fixtures;

#[cfg(test)]
mod tests;

#[cfg(any(test, all(feature = "sync", feature = "test-hooks")))]
pub mod test_support;

pub(crate) use migration::migrate_in_txn;
