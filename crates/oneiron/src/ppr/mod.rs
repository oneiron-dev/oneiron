mod cache_store;
mod community;
mod policy;
mod query;
mod walk;

pub(crate) use self::cache_store::{
    MAX_PPR_SEEDS, cleanup_ppr_cache, drop_rebuildable_ppr_cache, flush_deferred_ppr_cache_writes,
    increment_graph_version, invalidate_ppr_for_delete, invalidate_ppr_for_edge,
    read_graph_version,
};
#[cfg(test)]
use self::community::ppr_expand_in_txn_with_community_deferred_cache;
pub(crate) use self::community::{
    CommunityPprDiversity, CommunityPprRequest, ppr_expand_in_txn_with_community_diagnostics,
    ppr_query_in_txn_with_community_deferred_cache,
};
#[cfg(test)]
pub(crate) use self::policy::lambda_for_kind;
pub(crate) use self::policy::{SeedWeighting, canonical_vad_alpha};
pub(crate) use self::query::{
    DeferredPprCacheWrite, ppr_query_in_txn_with_diagnostics,
    ppr_query_in_txn_with_vad_deferred_cache, ppr_query_scoped_in_txn,
    ppr_query_scoped_in_txn_with_diagnostics,
};
#[cfg(test)]
use self::query::{ppr_query, ppr_query_in_txn};
pub(crate) use self::walk::PprNodeVisibility;
#[cfg(test)]
pub(crate) use self::walk::{ppr_compute, ppr_compute_weighted};

use std::cell::{Cell, RefCell};
use std::rc::Rc;

thread_local! {
    static VAD_PROPAGATION_EVIDENCE: RefCell<Option<Rc<Cell<bool>>>> = const { RefCell::new(None) };
}

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::{cache_store::*, community::*, policy::*, query::*, walk::*};
#[cfg(test)]
use crate::config::VaultConfig;
#[cfg(test)]
use crate::edge::{EDGE_VALUE_STRUCTURAL_LEN, EdgeConfirmationStatus};
#[cfg(test)]
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::pipeline::ScoredEntity;
#[cfg(test)]
use crate::retrieval_quality::PprCacheOutcome;
#[cfg(test)]
use crate::store::{GRAPH_VERSION_KEY, Store};
#[cfg(test)]
use heed::RoTxn;
#[cfg(test)]
use std::collections::{HashMap, HashSet};
#[cfg(test)]
use xxhash_rust::xxh3::xxh3_128;
