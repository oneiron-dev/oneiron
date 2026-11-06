//! Community query-scoring shells and the lower graph vocabulary.

pub use crate::config::community_graph::types::*;
use oneiron_retrieval::pipeline::ScoredEntity;
use std::collections::HashMap;

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
