//! Immutable message reactions and their live, audience-bound projections.
mod admission;
mod body;
mod identity;
mod outbound;
mod purge;
mod read;
mod signal;
mod state;
mod surface;
mod write;

pub(crate) use admission::{
    guard_edge, guard_edge_delete, guard_put, guard_recorded_at, index_external, index_triple,
};
pub use body::{ReactionBody, ReactionExternalId};
pub use identity::{ReactionAcknowledgment, ReactionBindingBody, ReactionGeneration};
pub(crate) use identity::{index_binding, purge_for_reaction, purge_suppressed_aliases};
pub use outbound::{REACTION_OUTBOUND_ATTEMPT_KIND, ReactionOutboundAttempt};
pub(crate) use purge::purge_derived_in_txn;
pub use read::{ReactionPill, ReactionSignal};
pub use signal::ReactionSignalPage;
pub(crate) use signal::{
    flush_pending_after_dependency, flush_pending_after_edge, flush_pending_after_membership,
    record_put_in_store, record_replayed_revoke, record_revoke,
};
pub(crate) use state::{ReactionResolution, resolve as resolve_state};
pub use surface::ReactionIngress;
pub use write::{ReactionChange, ReactionInput, ReactionState};

#[cfg(test)]
mod tests;
