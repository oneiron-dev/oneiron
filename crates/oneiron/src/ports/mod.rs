//! Transaction-composable storage ports. The caller owns commit and abort.
//!
//! Port contracts do not name heed, LMDB, or OverlayDb. Backend transaction
//! types are associated types; the LMDB implementation keeps the original
//! transaction and the in-memory implementation owns an isolated snapshot.
mod contracts;
mod lmdb_retrieval;
mod retrieval;
pub(crate) use lmdb_retrieval::text_index;
pub(crate) use retrieval::*;
mod lmdb_operational_edges;
mod lmdb_operational_entities;
mod maintenance;
pub(crate) use maintenance::*;
mod lmdb_phonetic;
mod lmdb_query;
mod lmdb_timeline;
mod lmdb_visibility;
mod query;
pub use query::*;
mod integrity;
mod lmdb_aux;
mod lmdb_claim;
mod lmdb_entity;
mod lmdb_index;
mod mutation;
mod records;
pub(crate) use mutation::{
    EntityPutAudit, MutationAudit, audit_entity_put_in_txn, audit_mutation_in_txn,
};
mod regeneration;
mod safe_read;
mod time;
pub use safe_read::{safe_read_asset_text, safe_read_text};
#[cfg(test)]
mod memory;
#[cfg(test)]
mod tests;
pub use contracts::*;
pub(crate) use integrity::{
    invalidate_source_in_txn, record_dependency_in_txn, record_derived_edge_in_txn,
    record_source_frontiers_in_txn, stale_in_txn,
};
pub use records::*;
pub(crate) use time::{CLOCK_FLOOR, recorded_at_in_txn};
pub use time::{Clock, IdGen, StoreClock};
mod manual_clock;
pub use manual_clock::ManualClock;
pub(crate) use time::ID_FLOOR;
