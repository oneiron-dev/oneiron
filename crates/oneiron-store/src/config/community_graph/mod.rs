//! Pure community graph projection, snapshot codecs and configuration.

pub mod codec;
pub mod detection;
pub mod refresh;
pub mod types;

pub use codec::CommunitySnapshot;
pub use codec::decode_community_members;
pub use detection::{project_graph, projection_weight};
pub use refresh::compute_communities;
pub use types::CommunityQueryView;
pub use types::{
    CommunityCacheMeta, CommunityEdge, CommunityError, CommunityGraphInput, CommunityId,
    CommunityMembership, CommunityProjection, CommunityRefreshReport, PPR_COMMUNITY_BETA_DEFAULT,
    PPR_COMMUNITY_BETA_EXPERIMENT, PPR_COMMUNITY_CACHE_PREFIX, PPR_COMMUNITY_CPM_GAMMA,
    PPR_COMMUNITY_DETERMINISTIC_SEED, PPR_COMMUNITY_MAX_GRAPH_FRACTION,
    PPR_COMMUNITY_MAX_TOP_K_FRACTION, PPR_COMMUNITY_MULTIPLIER_CAP,
    PPR_COMMUNITY_REFRESH_CHURN_FRACTION, PPR_COMMUNITY_SCHEMA_VERSION, PPR_COMMUNITY_USAGE_DECAY,
    PprCommunityCache, PprCommunityConfig,
};
