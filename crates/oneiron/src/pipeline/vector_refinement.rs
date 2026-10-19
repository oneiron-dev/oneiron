//! The dimensional space the existing HNSW funnel actually scores in.
use serde::{Deserialize, Serialize};

/// Full-dimensional refinement is exact over the prefix-selected beam only,
/// never a promise of globally exact nearest neighbors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VectorRefinement {
    pub stored_dimensions: usize,
    pub candidate_dimensions: usize,
    pub query_dimensions: usize,
    pub score_dimensions: usize,
    pub full_dimension_rescore: bool,
}

impl VectorRefinement {
    pub(crate) fn for_query(
        config: &crate::VaultConfig,
        query_dimensions: usize,
        skip_rescore: bool,
    ) -> Self {
        let candidate_dimensions = config.fast_dims.map_or(config.dimensions, usize::from);
        let full_dimension_rescore =
            config.fast_dims.is_some() && query_dimensions == config.dimensions && !skip_rescore;
        Self {
            stored_dimensions: config.dimensions,
            candidate_dimensions,
            query_dimensions,
            score_dimensions: if full_dimension_rescore {
                config.dimensions
            } else {
                candidate_dimensions
            },
            full_dimension_rescore,
        }
    }
}
