//! Conversation DAG topology, local HEAD state and exact scope resolution.
//!
//! Parent/SpawnedBy/RepliesTo are structural edges. A thread chain runs on
//! Parent; RepliesTo is the semantic reply target, so a thread reply may
//! answer or quote a trunk message. HEAD and canonical marks are
//! device-local sidecars, not replicated authority. Every topology walk
//! fails closed at the shared ancestor cap.

mod admission;
mod graph;
#[cfg(feature = "sync")]
pub(crate) use admission::{addressed_to_echo, addressed_to_echo_in_txn};
pub(crate) mod topology;
#[cfg(test)]
pub(crate) use admission::stored_body_pin_for_test;
pub(crate) use admission::{
    guard_record_put, guard_room_membership_delete, guard_room_turn_delete, keep_membership_pin,
    pin_membership, pin_typed_record, room_turn_owner, validate_local_membership,
};
#[cfg(feature = "sync")]
pub(crate) use admission::{validate_received_edge, validate_received_parent_value};
pub(crate) use topology::record_kind;
mod membership;
mod migration;
pub(crate) use membership::{stage_session_carrier, validate_session_carrier};

mod branch_scope;
mod participation;
mod policy;
mod quote;
mod quote_strips;
mod redacted;
mod reply;
pub(crate) mod retained_path;
mod scopes;
mod thread_projection;
mod types;
mod writes;

pub(crate) use branch_scope::{prove_branch_anchor, prove_branch_span};
pub(crate) use graph::{
    actor_in_txn, conversation_of, edge_ids, is_sub_session_record, is_thread_record,
    keeps_dag_topology, parent as retained_parent, record_has_dag_topology, require_type,
};
pub(crate) use participation::erased_thread_room_in_txn;
pub(crate) use quote::{QuotedReply, carries_quote};
pub use quote_strips::{
    QuoteReplyGroup, QuoteReplyStrip, QuoteStripStatus, ReplyStripsPage, ReplyStripsRequest,
};
pub(crate) use redacted::{capture_before_erase, read as redacted_record_pin};
pub use reply::{ReplyStrip, Thread, ThreadMeta};
pub(crate) use reply::{
    invalidate_thread_meta, invalidate_thread_meta_for_turn_put,
    rebuild_thread_meta_projection_in_txn,
};
pub(crate) use scopes::resolve_in_txn;
pub(crate) use thread_projection::selected_thread_in_txn;
pub use types::{
    AddressMode, AppendRecord, AppendedRecord, DagPage, DagPageRequest, QuoteSpan, ResolvedScope,
    ScopePath, ScopeSelector,
};
pub(crate) use writes::append_in_txn;

#[cfg(test)]
pub(crate) mod fixtures;

#[cfg(test)]
mod tests;

#[cfg(any(test, all(feature = "sync", feature = "test-hooks")))]
pub mod test_support;

pub(crate) use migration::migrate_in_txn;
