//! One ingest entry per replicated container: every entities-map value and every tombstone
//! takes the same ladder whether forward rematerialization or Observer B carries it.
//!
//! The passes keep only what differs between them: forward rematerialization opens a write
//! transaction per entity and keeps the window's marker ledger; Observer B batches a delta
//! under one transaction and flags `rm:` markers when that transaction dies. Endpoint
//! hydration and the recovery preflight call the same entity ladder.

mod birth_watch;
mod delivery;
mod entity;
mod order;
mod peer_import;
mod tombstone;

pub(in crate::sync) use self::birth_watch::{note_born, watch_births, watches};
pub(in crate::sync) use self::delivery::{
    Delivery, delivered_rows, note_delivered_in_txn, with_delivery,
};

pub(in crate::sync) use self::entity::{
    EntityStep, IngestCtx, RefusalRetry, Residence, ingest_entity_in_savepoint,
    ingest_entity_in_txn, waits_for_sibling_row,
};
pub(in crate::sync) use self::order::{authority_parent_order, is_authority_row};
pub(in crate::sync) use self::peer_import::{
    forget_peer_rows, peer_row_in_txn, peer_rows, record_peer_rows,
};
pub(in crate::sync) use self::tombstone::{TombstoneStep, classify_tombstone};
