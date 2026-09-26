//! Immutable message reactions and their live, audience-bound projections.
mod admission;
mod body;
mod outbound;
mod read;
mod signal;
mod surface;
mod write;

pub(crate) use admission::{
    guard_edge, guard_edge_delete, guard_put, guard_recorded_at, index_external, index_triple,
};
pub use body::{ReactionBody, ReactionExternalId};
pub use outbound::{REACTION_OUTBOUND_ATTEMPT_KIND, ReactionOutboundAttempt};
pub use read::{ReactionPill, ReactionSignal};
pub(crate) use signal::{
    flush_pending_for_author_edge, record_put_in_store, record_replayed_revoke, record_revoke,
};
pub use write::{ReactionChange, ReactionInput, ReactionState};

#[cfg(test)]
mod tests;
