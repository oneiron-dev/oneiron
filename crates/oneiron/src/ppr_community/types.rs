//! Community constants, error, ids, config and shared shells.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::edge::{DecodedEdgeValue, EdgeKind};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::pipeline::ScoredEntity;

pub const PPR_COMMUNITY_SCHEMA_VERSION: u8 = 0;

pub use oneiron_base::config::ppr_community::PPR_COMMUNITY_CPM_GAMMA;

pub use oneiron_base::config::ppr_community::PPR_COMMUNITY_BETA_DEFAULT;

pub const PPR_COMMUNITY_BETA_EXPERIMENT: f32 = 0.2;

pub use oneiron_base::config::ppr_community::PPR_COMMUNITY_MULTIPLIER_CAP;

pub use oneiron_base::config::ppr_community::PPR_COMMUNITY_MAX_GRAPH_FRACTION;

pub use oneiron_base::config::ppr_community::PPR_COMMUNITY_MAX_TOP_K_FRACTION;

pub const PPR_COMMUNITY_REFRESH_CHURN_FRACTION: f32 = 0.05;

pub const PPR_COMMUNITY_USAGE_DECAY: f32 = 0.10;

pub const PPR_COMMUNITY_DETERMINISTIC_SEED: u64 = 0x4f4e455f313837;

pub const PPR_COMMUNITY_CACHE_PREFIX: &str = "ppr_community_cache:v0:";

pub(super) const META_KEY: &str = "ppr_community_cache:v0:meta";

pub(super) type Result<T> = std::result::Result<T, CommunityError>;

pub use oneiron_base::config::ppr_community::CommunityError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommunityId(pub(super) [u8; 16]);

impl CommunityId {
    /// Domain-separated BLAKE3-128 of the sorted, unique member IDs.
    pub fn from_members(members: &[EntityId]) -> Result<Self> {
        let sorted: BTreeSet<_> = members.iter().copied().collect();
        if sorted.is_empty() {
            return Err(CommunityError::Cache);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:ppr_community:v0:members\0");
        for id in sorted {
            hasher.update(id.as_bytes());
        }
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    pub fn to_hex(self) -> String {
        bytes_to_hex_lower(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommunityMembership {
    pub fine: CommunityId,
    pub coarse: CommunityId,
}

pub use oneiron_base::config::ppr_community::PprCommunityConfig;

#[derive(Debug, Clone, Copy)]
pub struct CommunityEdge {
    pub source: EntityId,
    pub target: EntityId,
    pub kind: EdgeKind,
    pub value: DecodedEdgeValue,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityProjection {
    pub entities: Vec<EntityId>,
    /// Canonical undirected pairs, in integer tenths of pinned family weight.
    pub edges: BTreeMap<(EntityId, EntityId), u64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CommunityCacheMeta {
    pub schema: u8,
    pub graph_version: u64,
    pub gamma: f32,
    pub generated_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommunityRefreshReport {
    pub full_recompute: bool,
    pub changed_entities: usize,
    pub recomputed_entities: usize,
}

pub struct CommunityGraphInput<'a> {
    pub entities: &'a [EntityId],
    pub edges: &'a [CommunityEdge],
    pub changed: &'a [EntityId],
    pub graph_version: u64,
}

/// Owned, transaction-local selection. Only the Store's indexed validator or a
/// fully validated snapshot may construct this view. It is never a full family
/// and must not be published or passed to full-snapshot validation.
#[derive(Debug, Clone)]
pub(crate) struct CommunityQueryView {
    pub(crate) nodes: BTreeMap<EntityId, CommunityMembership>,
    pub(crate) sizes: BTreeMap<CommunityId, usize>,
    pub(crate) graph_size: usize,
}

/// A validated read view. Version must come from the same graph read transaction.
pub struct PprCommunityCache<'a> {
    pub(super) nodes: &'a BTreeMap<EntityId, CommunityMembership>,
    pub(super) sizes: BTreeMap<CommunityId, usize>,
    pub(super) graph_size: usize,
}

pub struct CommunityBoostContext<'a> {
    pub ordered_seeds: &'a [ScoredEntity],
    pub result_limit: usize,
    pub session_usage: &'a HashMap<CommunityId, u32>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CommunityBoostReport {
    pub activated_communities: usize,
    pub boosted_candidates: usize,
    pub fine_entropy_bits: f64,
    pub coarse_entropy_bits: f64,
}

#[derive(Clone, Copy)]
pub(super) struct Ranked {
    pub(super) entity: ScoredEntity,
    pub(super) membership: Option<CommunityMembership>,
    pub(super) boosted: bool,
}

#[derive(Clone, Copy)]
pub(super) struct DiversityHead {
    pub(super) row: Ranked,
    pub(super) group: usize,
    pub(super) fine: usize,
    pub(super) coarse: usize,
}

/// Fine groups occupy leaves, contiguous within each coarse community. A coarse
/// increment is uniform over its range, so it cannot change an internal winner.
/// Lazy range updates and point replacements each take O(log(groups)) work.
pub(super) struct DiversityTree {
    pub(super) size: usize,
    pub(super) best: Vec<Option<DiversityHead>>,
    pub(super) lazy: Vec<usize>,
}
