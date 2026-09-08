//! Deterministic community projection, cache, and bounded retrieval prior.
//! The Store adapter supplies one consistent, canonical live-entity snapshot, decoded
//! outgoing edges (not both indexes), and every changed edge endpoint, including
//! deletions. Publish all returned rows atomically in `vault_meta`, never a new DB.
//! CPM uses integer tenths at gamma 1.0. Distinct directed relations add evidence;
//! duplicate records do not. Fine is the first Leiden refinement; coarse is its
//! mass-preserving multilevel partition. Both may coincide (no forced clustering).

mod bridge;
mod codec;
mod detection;
mod refresh;
mod scoring;
mod types;

pub use self::bridge::{expand_ppr, ordered_seed_evidence, refresh_communities};
pub use self::codec::CommunitySnapshot;
pub use self::detection::{project_graph, projection_weight};
pub use self::refresh::compute_communities;
pub use self::scoring::{
    activated_communities, apply_community_prior, community_cache_identity, community_multiplier,
};
pub use self::types::{
    CommunityBoostContext, CommunityBoostReport, CommunityCacheMeta, CommunityEdge, CommunityError,
    CommunityGraphInput, CommunityId, CommunityMembership, CommunityProjection,
    CommunityRefreshReport, PPR_COMMUNITY_BETA_DEFAULT, PPR_COMMUNITY_BETA_EXPERIMENT,
    PPR_COMMUNITY_CACHE_PREFIX, PPR_COMMUNITY_CPM_GAMMA, PPR_COMMUNITY_DETERMINISTIC_SEED,
    PPR_COMMUNITY_MAX_GRAPH_FRACTION, PPR_COMMUNITY_MAX_TOP_K_FRACTION,
    PPR_COMMUNITY_MULTIPLIER_CAP, PPR_COMMUNITY_REFRESH_CHURN_FRACTION,
    PPR_COMMUNITY_SCHEMA_VERSION, PPR_COMMUNITY_USAGE_DECAY, PprCommunityCache, PprCommunityConfig,
};

pub(crate) use self::codec::decode_community_members;
pub(crate) use self::scoring::{apply_community_diversity, boost_community_scores};
pub(crate) use self::types::CommunityQueryView;

#[cfg(test)]
mod tests;

// Test-only diversity work counter. It lives here rather than in `scoring`
// (where the plan's neighbours sit) because the sibling test module names it
// bare through `use super::*`, which cannot see a private item of another
// child; a child module does see its parent's private items.
#[cfg(test)]
thread_local! {
    static DIVERSITY_SELECTION_WORK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

// The flat ppr_community.rs module used to provide these names to the sibling test
// module through `use super::*`: every ppr_community-internal item the tests name
// bare. After the directory split the seam re-imports them so `tests.rs` resolves
// exactly as it did before. Only the children whose items are not already kept on
// the public seam (`pub use` above) need a glob here; the rest would warn unused.
#[cfg(test)]
use self::{detection::*, scoring::*, types::*};
#[cfg(test)]
use crate::edge::{DecodedEdgeValue, EdgeConfirmationStatus, EdgeKind};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::pipeline::ScoredEntity;
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet, HashMap};
