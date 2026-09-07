pub mod export;
pub(crate) mod secret_scan;

mod authority_log;
mod builder;
mod child_of_overlay;
mod claim_candidate_apply;
mod deindex;
mod edge_apply;
mod facet_validation;
mod lexical_query_hints;
mod ops_pipeline;
mod phonetic_apply;
mod put_apply;
mod short_id;
mod txn_builder;
mod types;
mod vector_apply;

#[cfg(test)]
mod tests;

pub use self::builder::BatchBuilder;
pub use self::txn_builder::TxnBatchBuilder;

pub(crate) use self::authority_log::validate_replicated_authority_log_for_local_vault;
pub(crate) use self::builder::BatchOp;
pub(crate) use self::child_of_overlay::child_of_prefix;
#[cfg(test)]
pub(crate) use self::deindex::deindex_entity_for_test;
pub(crate) use self::deindex::{deindex_entity, deindex_lexical_query_hints_for_target};
pub(crate) use self::facet_validation::validate_facet_of_edge;
pub(crate) use self::lexical_query_hints::reject_family_owned_candidate;
// Reached only from sync-gated modules (`sync::selector`); the re-exports keep
// the historical `crate::batch::` paths resolvable in sync builds.
#[cfg_attr(not(feature = "sync"), allow(unused_imports))]
pub(crate) use self::facet_validation::{
    facet_of_endpoint_types_on_table, facet_of_endpoints_provably_off_table, stored_entity_type,
};
pub(crate) use self::ops_pipeline::{
    ApplyOpsGateMode, BaseWriteOrigin, apply_ops, apply_ops_session, apply_ops_with_gate_mode,
    apply_ops_with_origin, apply_session_bundle_claim_puts, reject_overlay_member_base_write,
};
pub(crate) use self::phonetic_apply::delete_from_phonetic_postings;
pub(crate) use self::put_apply::delete_entity_index_rows;
pub(crate) use self::short_id::{encode_short_id_forward_key, parse_short_id_value};
pub(crate) use self::types::{
    ENTITY_METADATA_HEADER_LEN, EdgeValueFields, EntityMetadataHeader,
    LONG_INTERVAL_THRESHOLD_SECS, SHORT_ID_COUNTER_LEN,
};
// Reached only from the crate-root white-box test module (`crate::tests`); the
// re-exports keep the historical `crate::batch::` paths resolvable there.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use self::types::{
    ENTITY_BODY_OFFSET, ENTITY_LEARNED_AT_OFFSET, ENTITY_OCCURRED_END_OFFSET,
    ENTITY_OCCURRED_START_OFFSET, ENTITY_TYPE_OFFSET,
};
// Private re-exports preserving the module's original flat namespace for
// sibling files and the white-box test module (`tests.rs` uses `super::*`).
use self::authority_log::*;
// `builder`'s module-private items are reached cross-file only from sync-gated
// code (`replicated_put_op`); its public items route via the re-exports above.
#[cfg_attr(not(feature = "sync"), allow(unused_imports))]
use self::builder::*;
use self::child_of_overlay::*;
use self::claim_candidate_apply::*;
use self::deindex::*;
use self::edge_apply::*;
use self::lexical_query_hints::*;
use self::ops_pipeline::*;
use self::phonetic_apply::*;
use self::put_apply::*;
use self::short_id::*;
use self::types::*;
use self::vector_apply::*;
