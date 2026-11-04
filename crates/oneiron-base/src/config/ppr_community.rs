//! Portable PPR community prior: the config closure moved down from the engine crate.

pub const PPR_COMMUNITY_CPM_GAMMA: f32 = 1.0;

pub const PPR_COMMUNITY_BETA_DEFAULT: f32 = 0.0;

pub const PPR_COMMUNITY_MULTIPLIER_CAP: f32 = 1.5;

pub const PPR_COMMUNITY_MAX_GRAPH_FRACTION: f32 = 0.10;

pub const PPR_COMMUNITY_MAX_TOP_K_FRACTION: f32 = 0.70;

type Result<T> = std::result::Result<T, CommunityError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CommunityError {
    #[error("invalid community configuration")]
    Config,
    #[error("invalid community graph or frontier")]
    Graph,
    #[error("corrupt community cache")]
    Cache,
    #[error("stale community graph version")]
    Version,
    #[error("invalid community score evidence")]
    Scores,
}

/// Runtime configuration, also exported from [`crate::config`].
#[derive(Debug, Clone, PartialEq)]
pub struct PprCommunityConfig {
    pub beta: f32,
    pub gamma: f32,
    pub multiplier_cap: f32,
    pub max_graph_fraction: f32,
    pub max_top_k_fraction: f32,
}

impl Default for PprCommunityConfig {
    fn default() -> Self {
        Self {
            beta: PPR_COMMUNITY_BETA_DEFAULT,
            gamma: PPR_COMMUNITY_CPM_GAMMA,
            multiplier_cap: PPR_COMMUNITY_MULTIPLIER_CAP,
            max_graph_fraction: PPR_COMMUNITY_MAX_GRAPH_FRACTION,
            max_top_k_fraction: PPR_COMMUNITY_MAX_TOP_K_FRACTION,
        }
    }
}

impl PprCommunityConfig {
    /// Safety bounds may be tightened, not relaxed. Gamma is pinned in v0.
    pub fn validate(&self) -> Result<()> {
        if !self.beta.is_finite()
            || self.beta < 0.0
            || self.gamma != PPR_COMMUNITY_CPM_GAMMA
            || !(1.0..=PPR_COMMUNITY_MULTIPLIER_CAP).contains(&self.multiplier_cap)
            || !(0.0..=PPR_COMMUNITY_MAX_GRAPH_FRACTION).contains(&self.max_graph_fraction)
            || !(0.0..=PPR_COMMUNITY_MAX_TOP_K_FRACTION).contains(&self.max_top_k_fraction)
        {
            return Err(CommunityError::Config);
        }
        Ok(())
    }
}
