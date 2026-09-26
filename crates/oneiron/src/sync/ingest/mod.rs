//! One ingest entry per replicated container: every entities-map value and every tombstone
//! takes the same ladder whether forward rematerialization or Observer B carries it.
//!
//! The passes keep only what differs between them: forward rematerialization opens a write
//! transaction per entity and keeps the window's marker ledger; Observer B batches a delta
//! under one transaction and flags `rm:` markers when that transaction dies. Endpoint
//! hydration and the recovery preflight call the same entity ladder.

mod entity;
mod tombstone;

pub(in crate::sync) use self::entity::{
    EntityStep, IngestCtx, RefusalRetry, ingest_entity_in_savepoint, ingest_entity_in_txn,
};
pub(in crate::sync) use self::tombstone::{TombstoneStep, classify_tombstone};
