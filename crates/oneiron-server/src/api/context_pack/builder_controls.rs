//! Depth, policy, time and budget resolution for context-pack assembly.

use super::controls::{
    ContextPackBudgetControls, ContextPackDepthControls, ContextPackPolicyControls,
    ContextPackRetrievalBudgetControls, ContextPackTimeControls,
};
use crate::error::ApiError;

pub(crate) fn resolved_context_pack_depth(
    depth: Option<&ContextPackDepthControls>,
    edge_hop: u32,
    max_neighbors: usize,
) -> (u32, &'static str, usize, &'static str) {
    let depth_edge_hop = depth.and_then(|depth| depth.edge_hop);
    let depth_max_neighbors = depth.and_then(|depth| depth.max_neighbors);
    (
        depth_edge_hop.unwrap_or(edge_hop),
        if depth_edge_hop.is_some() {
            "depth.edge_hop"
        } else {
            "edge_hop"
        },
        depth_max_neighbors.unwrap_or(max_neighbors),
        if depth_max_neighbors.is_some() {
            "depth.max_neighbors"
        } else {
            "max_neighbors"
        },
    )
}

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_context_neighbors() -> usize {
    50
}

/// The ranking boosts a request's policy names, checked before any hook
/// runs (FIX 1435) and applied to the pack's builder after.
#[derive(Clone, Copy, Default)]
pub(crate) struct ContextPackRanking {
    recency_half_life_days: Option<f32>,
    salience: bool,
    confidence: bool,
    contiguity: bool,
}

impl ContextPackRanking {
    /// The boosts `policy` names. A recency half-life that is not finite
    /// and positive is refused.
    pub(crate) fn checked(policy: Option<&ContextPackPolicyControls>) -> Result<Self, ApiError> {
        let Some(policy) = policy else {
            return Ok(Self::default());
        };
        if let Some(half_life_days) = policy.boost_recency_days
            && (!half_life_days.is_finite() || half_life_days <= 0.0)
        {
            return Err(ApiError::bad_request(
                "boost_recency_days must be finite and positive",
                Some("policy.boost_recency_days"),
            ));
        }
        Ok(Self {
            recency_half_life_days: policy.boost_recency_days,
            salience: policy.boost_salience.unwrap_or(false),
            confidence: policy.boost_confidence.unwrap_or(false),
            contiguity: policy.boost_contiguity.unwrap_or(false),
        })
    }

    pub(crate) fn applied<'a>(
        self,
        mut builder: oneiron::ContextPackBuilder<'a>,
    ) -> oneiron::ContextPackBuilder<'a> {
        if let Some(half_life_days) = self.recency_half_life_days {
            builder = builder.boost_recency(half_life_days);
        }
        if self.salience {
            builder = builder.boost_salience();
        }
        if self.confidence {
            builder = builder.boost_confidence();
        }
        if self.contiguity {
            builder = builder.boost_contiguity();
        }
        builder
    }
}

/// The time window a request's time controls name, checked before any hook
/// runs (FIX 1435) and applied to the pack's builder after.
#[derive(Clone, Copy, Default)]
pub(crate) struct ContextPackTimeWindow {
    since: Option<u64>,
    occurred: Option<(u64, u64)>,
    learned: Option<(u64, u64)>,
}

impl ContextPackTimeWindow {
    /// The window `time` names. A range given by one end only, or whose
    /// start is after its end, and a `since` after `learned_end`, are
    /// refused.
    pub(crate) fn checked(time: Option<&ContextPackTimeControls>) -> Result<Self, ApiError> {
        let Some(time) = time else {
            return Ok(Self::default());
        };
        let occurred_range = match (time.occurred_start, time.occurred_end) {
            (Some(start), Some(end)) if start <= end => Some((start, end)),
            (Some(_), Some(_)) => {
                return Err(ApiError::bad_request(
                    "occurred_start must be less than or equal to occurred_end",
                    Some("time.occurred_start"),
                ));
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(ApiError::bad_request(
                    "occurred_start and occurred_end must be supplied together",
                    Some("time"),
                ));
            }
            (None, None) => None,
        };
        let learned_range = match (time.learned_start, time.learned_end) {
            (Some(start), Some(end)) if start <= end => Some((start, end)),
            (Some(_), Some(_)) => {
                return Err(ApiError::bad_request(
                    "learned_start must be less than or equal to learned_end",
                    Some("time.learned_start"),
                ));
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(ApiError::bad_request(
                    "learned_start and learned_end must be supplied together",
                    Some("time"),
                ));
            }
            (None, None) => None,
        };
        if let (Some(since), Some((_, learned_end))) = (time.since, learned_range)
            && since > learned_end
        {
            return Err(ApiError::bad_request(
                "since must be less than or equal to learned_end",
                Some("time.since"),
            ));
        }
        Ok(Self {
            since: time.since,
            occurred: occurred_range,
            learned: learned_range,
        })
    }

    pub(crate) fn applied<'a>(
        self,
        mut builder: oneiron::ContextPackBuilder<'a>,
    ) -> oneiron::ContextPackBuilder<'a> {
        if let Some(since) = self.since {
            builder = builder.filter_since(since);
        }
        if let Some((start, end)) = self.occurred {
            builder = builder.filter_occurred_range(start, end);
        }
        if let Some((start, end)) = self.learned {
            builder = builder.filter_learned_range(start, end);
        }
        builder
    }
}

pub(crate) fn apply_context_pack_budget<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    budget: Option<&ContextPackBudgetControls>,
    scoped_candidate_limit: usize,
    result_limit: usize,
    default_selected_edges: usize,
) -> Result<
    (
        oneiron::ContextPackBuilder<'a>,
        oneiron::ContextPackRetrievalBudget,
    ),
    ApiError,
> {
    if let Some(max_item_tokens) = budget.and_then(|budget| budget.max_item_tokens)
        && max_item_tokens > 0
    {
        builder = builder.max_item_tokens(max_item_tokens);
    }
    if let Some(budget) = budget {
        if let Some(token_budget) = budget.token_budget {
            builder = builder.token_budget(token_budget);
        }
        if let Some(max_field_chars) = budget.max_field_chars {
            builder = builder.max_field_chars(max_field_chars);
        }
    }
    let retrieval = budget.and_then(|budget| budget.retrieval.as_ref());
    let (response_budget, internal_budget) = resolve_context_pack_retrieval_budgets(
        retrieval,
        result_limit,
        scoped_candidate_limit,
        default_selected_edges,
    );
    builder = builder.retrieval_budget(internal_budget);
    Ok((builder, response_budget))
}

pub(crate) fn resolve_context_pack_retrieval_budgets(
    retrieval: Option<&ContextPackRetrievalBudgetControls>,
    result_limit: usize,
    scoped_candidate_limit: usize,
    default_selected_edges: usize,
) -> (
    oneiron::ContextPackRetrievalBudget,
    oneiron::ContextPackRetrievalBudget,
) {
    let selected_edges = retrieval
        .and_then(|retrieval| retrieval.selected_edges)
        .unwrap_or(default_selected_edges);
    let mut response_budget = oneiron::ContextPackRetrievalBudget::from_limit(
        result_limit,
        oneiron::TokenAllocation::default(),
        selected_edges,
    );
    if let Some(retrieval) = retrieval {
        if let Some(claims) = retrieval.claims {
            response_budget.claims = claims;
        }
        if let Some(turns) = retrieval.turns {
            response_budget.turns = turns;
        }
        if let Some(summaries) = retrieval.summaries {
            response_budget.summaries = summaries;
        }
        if let Some(facets) = retrieval.facets {
            response_budget.facets = facets;
        }
        if let Some(other) = retrieval.other {
            response_budget.other = other;
        }
    }
    let internal_budget =
        widen_context_pack_retrieval_budget(response_budget, scoped_candidate_limit);
    (response_budget, internal_budget)
}

pub(crate) fn widen_context_pack_retrieval_budget(
    budget: oneiron::ContextPackRetrievalBudget,
    scoped_candidate_limit: usize,
) -> oneiron::ContextPackRetrievalBudget {
    let widen = |bucket: usize| {
        if bucket == 0 {
            0
        } else {
            bucket.max(scoped_candidate_limit)
        }
    };
    oneiron::ContextPackRetrievalBudget::new(
        widen(budget.claims),
        widen(budget.turns),
        widen(budget.summaries),
        widen(budget.facets),
        widen(budget.other),
        budget.selected_edges,
    )
}
