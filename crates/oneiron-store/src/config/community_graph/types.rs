//! Community constants, error, ids, config and shared shells.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use oneiron_base::edge::{DecodedEdgeValue, EdgeKind};
use oneiron_contracts::entity_id::{EntityId, bytes_to_hex_lower};

pub use oneiron_base::config::ppr_community::{
    CommunityError, PPR_COMMUNITY_BETA_DEFAULT, PPR_COMMUNITY_CPM_GAMMA,
    PPR_COMMUNITY_MAX_GRAPH_FRACTION, PPR_COMMUNITY_MAX_TOP_K_FRACTION,
    PPR_COMMUNITY_MULTIPLIER_CAP, PprCommunityConfig,
};

pub const PPR_COMMUNITY_SCHEMA_VERSION: u8 = 0;

pub const PPR_COMMUNITY_BETA_EXPERIMENT: f32 = 0.2;

pub const PPR_COMMUNITY_REFRESH_CHURN_FRACTION: f32 = 0.05;

pub const PPR_COMMUNITY_USAGE_DECAY: f32 = 0.10;

pub const PPR_COMMUNITY_DETERMINISTIC_SEED: u64 = 0x4f4e455f313837;

pub const PPR_COMMUNITY_CACHE_PREFIX: &str = "ppr_community_cache:v0:";

pub const META_KEY: &str = "ppr_community_cache:v0:meta";

pub type Result<T> = std::result::Result<T, CommunityError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommunityId(pub [u8; 16]);

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
pub struct CommunityQueryView {
    pub nodes: BTreeMap<EntityId, CommunityMembership>,
    pub sizes: BTreeMap<CommunityId, usize>,
    pub graph_size: usize,
}

/// A validated read view. Version must come from the same graph read transaction.
pub struct PprCommunityCache<'a> {
    pub nodes: &'a BTreeMap<EntityId, CommunityMembership>,
    pub sizes: BTreeMap<CommunityId, usize>,
    pub graph_size: usize,
}
