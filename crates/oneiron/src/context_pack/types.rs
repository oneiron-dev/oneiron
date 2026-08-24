//! Public value types of the context pack: the pack itself, its entities, its
//! stats, and its budget/allocation knobs.

use std::collections::HashMap;

use crate::edge::EdgeInfo;
use crate::entity_id::EntityId;
use crate::pipeline::Signal;

use super::empty_pack::EmptyContext;

pub const DEFAULT_MAX_NEIGHBORS: usize = 50;
pub(super) const DEFAULT_TOKEN_BUDGET: usize = 4000;
pub const DEFAULT_MAX_FIELD_CHARS: usize = 500;
pub const MAX_EDGE_HOP: u32 = 5;
pub const MAX_CONTEXT_NEIGHBORS: usize = 1000;

/// Default share of the claim budget that non-base (fictional / dream) worlds
/// may occupy in an `All`-scope pack — fiction takes at most half, so it can
/// never crowd base reality out (ARCH-0004 / ARCH-0022).
pub(super) const DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION: f32 = 0.5;

/// Output serialization format for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum PackFormat {
    #[default]
    Json,
    Yaml,
    Toon,
    Markdown,
    Plaintext,
}

/// Field selection profile for context packing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum FieldProfile {
    Minimal,
    #[default]
    Standard,
    Full,
}

/// Hydrated entity with decoded fields, edges, and provenance.
#[derive(Debug, Clone)]
pub struct ContextEntity {
    pub id: EntityId,
    pub short_id: String,
    pub content_hash: u8,
    pub entity_type: u8,
    pub score: f32,
    pub fields: Option<HashMap<String, serde_json::Value>>,
    pub edges: Option<Vec<EdgeInfo>>,
    pub vector: Option<Vec<f32>>,
}

/// Stats about the context pack query.
#[derive(Debug, Clone)]
pub struct PackStats {
    pub candidates_considered: usize,
    pub signals_used: Vec<Signal>,
    pub query_time_us: u64,
    pub entities_hydrated: usize,
    pub neighbors_hydrated: usize,
    /// Candidates assigned the low gravity signal because they had vector
    /// similarity above the cosine-ghost threshold and no BM25 text channel
    /// presence.
    pub cosine_ghosts_dampened: usize,
    /// CLAIM records silently excluded by the D19 read-path status gate
    /// (ARCH-0003: surface only `appr ∈ {auto, approved}` ∧ `life = active`
    /// ∧ `stale = false`) or by the fail-closed type-0 body decode, across
    /// the pipeline stage and pack hydration (results + neighbors). A claim
    /// suppressed in both stages counts once per stage.
    pub claims_suppressed: usize,
    /// Token accounting populated by serialization/projection paths.
    ///
    /// Raw `ContextPackBuilder::run()` results are not serialized and leave
    /// this as `PackTokenStats::default()`. Use serialized/projection builder
    /// paths when exact output-token accounting is required.
    pub tokens: PackTokenStats,
    pub items_truncated: PackItemAccounting,
    pub items_dropped: PackItemAccounting,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackTokenStats {
    /// Stable tokenizer identifier used for every count in this struct.
    ///
    /// Empty when stats came from an unserialized raw pack.
    pub tokenizer_id: String,
    /// Exact token count of the final serialized context-pack bytes.
    ///
    /// This includes format envelope, separators, and serialized stats when
    /// they are emitted.
    pub total_tokens: usize,
    /// Per-section row-token accounting.
    ///
    /// Section counts are computed from the row-level accounting text used by
    /// budget allocation. They intentionally exclude format envelope and
    /// separators, so their sum is not expected to equal `total_tokens`.
    pub sections: Vec<PackSectionTokenStats>,
    /// Per-item row-token accounting.
    ///
    /// Item counts use the same row-level basis as `sections`, not exact
    /// emitted substrings for each output format.
    pub items: Vec<PackItemTokenStats>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSectionTokenStats {
    /// Logical section name, for example `results`, `neighbors`, or `merged`.
    pub section: String,
    /// Row-level token count for this section.
    pub tokens: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackItemTokenStats {
    /// Logical section containing this item.
    pub section: String,
    /// Serialized short reference for the item, including the content-hash suffix.
    pub id: String,
    /// Entity type byte used for the serialized row group.
    pub entity_type: u8,
    /// Row-level token count for this item.
    pub tokens: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackItemAccountingReason {
    ItemBudget,
    TokenBudget,
}

impl PackItemAccountingReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ItemBudget => "item_budget",
            Self::TokenBudget => "token_budget",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackItemAccounting {
    pub count: usize,
    pub reason: PackItemAccountingReason,
}

impl PackItemAccounting {
    #[must_use]
    pub fn item_budget() -> Self {
        Self {
            count: 0,
            reason: PackItemAccountingReason::ItemBudget,
        }
    }

    #[must_use]
    pub fn token_budget() -> Self {
        Self {
            count: 0,
            reason: PackItemAccountingReason::TokenBudget,
        }
    }
}

/// A fully hydrated context pack ready for serialization or programmatic use.
#[derive(Debug, Clone)]
pub struct ContextPack {
    pub results: Vec<ContextEntity>,
    pub neighbors: Vec<ContextEntity>,
    pub stats: PackStats,
    pub empty: Option<EmptyContext>,
}

/// Token budget allocation across entity types.
#[derive(Debug, Clone, Copy)]
pub struct TokenAllocation {
    pub claims: f32,
    pub turns: f32,
    pub summaries: f32,
    pub other: f32,
}

impl Default for TokenAllocation {
    fn default() -> Self {
        Self {
            claims: 0.45,
            turns: 0.10,
            summaries: 0.25,
            other: 0.20,
        }
    }
}

/// Item budget for context-pack retrieval before the final global truncation.
///
/// Primary entity budgets are enforced per retrieval kind after query filters
/// and before `limit` truncation. `selected_edges` caps edge-walk neighbor
/// selection; it is not an entity type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextPackRetrievalBudget {
    pub claims: usize,
    pub turns: usize,
    pub summaries: usize,
    pub facets: usize,
    pub other: usize,
    pub selected_edges: usize,
}

impl ContextPackRetrievalBudget {
    #[must_use]
    pub const fn new(
        claims: usize,
        turns: usize,
        summaries: usize,
        facets: usize,
        other: usize,
        selected_edges: usize,
    ) -> Self {
        Self {
            claims,
            turns,
            summaries,
            facets,
            other,
            selected_edges,
        }
    }

    #[must_use]
    pub fn from_limit(
        result_limit: usize,
        allocation: TokenAllocation,
        selected_edges: usize,
    ) -> Self {
        let split_other = allocation.other / 2.0;
        let weights = [
            allocation.claims,
            allocation.turns,
            allocation.summaries,
            split_other,
            split_other,
        ];
        let mut budgets = allocate_context_pack_item_budgets(result_limit, weights);
        if result_limit > 0 {
            for (budget, weight) in budgets.iter_mut().zip(weights) {
                if *budget == 0 && weight.is_finite() && weight > 0.0 {
                    *budget = 1;
                }
            }
        }
        Self {
            claims: budgets[0],
            turns: budgets[1],
            summaries: budgets[2],
            facets: budgets[3],
            other: budgets[4],
            selected_edges,
        }
    }
}

fn allocate_context_pack_item_budgets(limit: usize, weights: [f32; 5]) -> [usize; 5] {
    if limit == 0 {
        return [0; 5];
    }

    let mut sanitized = [0.0_f32; 5];
    for (index, weight) in weights.into_iter().enumerate() {
        if weight.is_finite() && weight > 0.0 {
            sanitized[index] = weight;
        }
    }

    let total_weight: f32 = sanitized.iter().sum();
    if total_weight <= 0.0 {
        let base = limit / sanitized.len();
        let mut budgets = [base; 5];
        for budget in budgets.iter_mut().take(limit % sanitized.len()) {
            *budget = budget.saturating_add(1);
        }
        return budgets;
    }

    let mut budgets = [0_usize; 5];
    let mut remainders = [(0_usize, 0.0_f32); 5];
    let mut allocated = 0_usize;
    for (index, weight) in sanitized.iter().copied().enumerate() {
        if weight <= 0.0 {
            continue;
        }
        let exact = (limit as f32) * (weight / total_weight);
        let whole = exact.floor() as usize;
        budgets[index] = whole;
        remainders[index] = (index, exact - whole as f32);
        allocated = allocated.saturating_add(whole);
    }

    let mut leftover = limit.saturating_sub(allocated);
    remainders.sort_unstable_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (index, _) in remainders {
        if leftover == 0 {
            break;
        }
        if sanitized[index] > 0.0 {
            budgets[index] = budgets[index].saturating_add(1);
            leftover -= 1;
        }
    }
    budgets
}
