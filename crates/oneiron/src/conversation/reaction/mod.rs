//! Reactions: append-only records, message-scoped visibility, and derived projections.
mod codec;
mod lifecycle;
mod materialize;
mod outbound;
mod projection;
#[cfg(test)]
mod tests;

pub use codec::*;
pub(crate) use materialize::{
    batch_needs_inbox_rejoin, purge_signals, rebuild_inbox_in_txn, stage_put, stage_revoked,
    validate_edge, validate_put,
};

#[cfg(feature = "sync")]
mod replay;
#[cfg(feature = "sync")]
pub(crate) use replay::{materialize_soft_audit, soft_audit_blob};
