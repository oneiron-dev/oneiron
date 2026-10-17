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
mod document_fields;
pub(crate) use document_fields::{is_metadata_field, is_text_field, validate_metadata};
mod document_rows;
mod lmdb_document_rows;
pub(crate) use document_rows::*;
mod lmdb_operational_edges;
mod lmdb_operational_entities;
mod maintenance;
pub(crate) use maintenance::*;
mod lmdb_phonetic;
mod lmdb_query;
mod lmdb_retrieval_inventory;
mod lmdb_staging;
mod lmdb_timeline;
mod lmdb_visibility;
mod lmdb_window_rows;
mod query;
pub use query::*;
mod retrieval_index;
pub(crate) use retrieval_index::{IndexMetaKey, IndexRows, RetrievalIndexInventory};
mod window_rows;
pub(crate) use window_rows::{WindowAddress, WindowDeletionRows};
mod dependent_walk;
pub use dependent_walk::{
    DEFAULT_DEPENDENT_WALK_BATCH, DEFAULT_DEPENDENT_WALK_CHECK_THRESHOLD, DependentWalkCheck,
    DependentWalkPolicy, DependentWalkProgress,
};
pub(crate) use dependent_walk::{
    DependentWalkDoor, any_pending_walk, withdraw_before_rewrite_in_txn,
};
mod integrity;
mod lmdb_aux;
mod lmdb_claim;
#[cfg(test)]
pub(crate) use lmdb_claim::MAX_PREDICATE_LIST_ROWS;
mod lmdb_entity;
pub(crate) use lmdb_entity::reindex_named_entities;
mod lmdb_index;
mod lmdb_short_id_maintenance;
mod mutation;
mod records;
pub(crate) use mutation::{
    EntityPutAudit, MutationAudit, audit_entity_put_in_txn, audit_mutation_in_txn,
};
mod regeneration;
mod safe_read;
mod time;
pub(crate) use safe_read::{
    BodyStale, body_readable_in_txn, raw_readable_in_txn, withdrawn_in_txn,
};
pub use safe_read::{safe_read_asset_text, safe_read_text};
#[cfg(test)]
mod memory;
#[cfg(test)]
pub(crate) mod row_copies;
#[cfg(test)]
mod tests;
pub use contracts::*;
pub(crate) use integrity::{
    invalidate_source_in_txn, keep_deleted_worlds_in_txn, keep_worlds_of_unmade_epoch_in_txn,
    record_dependency_in_txn, record_derived_edge_in_txn, record_withdrawn_in_txn,
    retire_withdrawn_in_txn, source_has_dependents_in_txn, stale_in_txn,
    withdraw_from_lost_source_in_txn, withdrawn_worlds_in,
};
pub use records::*;
pub(crate) use regeneration::dependency_sources_in;
pub(crate) use time::{
    CLOCK_FLOOR, authorization_floor_in_txn, job_recorded_at_in_txn, observe_clock_floor_in_txn,
    persist_id_floor_in_txn, recorded_at_in_txn,
};
pub use time::{Clock, IdGen, StoreClock};
mod manual_clock;
pub(crate) use lmdb_visibility::removed_in_txn;
pub use manual_clock::ManualClock;
pub(crate) use time::ID_FLOOR;
