//! Residence-operation budgets as editable policy (FIX 8750, FIX 8783).
//!
//! A manifest row names a subset of the budget fields for the vault and,
//! optionally, for the holder. The shipped defaults fill only the fields no
//! trusted vault row names: an authored vault value replaces its default, and
//! several authored vault rows meet one another. A holder row narrows only
//! the fields it names, so it never widens the vault's value.

use crate::gate::{
    ResidenceOperationBudgetLimits, ResidenceOperationBudgetPrecedence, ResidenceOperationBudgetRow,
};

/// Calls `$each!(field)` for every residence budget field.
macro_rules! each_budget_field {
    ($each:ident) => {
        $each!(rpc_timeout_ms);
        $each!(index_page_limit);
        $each!(max_index_pages);
        $each!(current_window_count);
        $each!(title_max_chars);
        $each!(search_limit);
        $each!(search_query_max_bytes);
        $each!(offline_candidate_multiplier);
        $each!(ack_timeout_ms);
        $each!(index_cache_bytes);
    };
}

/// The budget fields one manifest map names; `None` names nothing, never a
/// shipped default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ResidenceBudgetPatch {
    pub(crate) rpc_timeout_ms: Option<u64>,
    pub(crate) index_page_limit: Option<usize>,
    pub(crate) max_index_pages: Option<usize>,
    pub(crate) current_window_count: Option<usize>,
    pub(crate) title_max_chars: Option<usize>,
    pub(crate) search_limit: Option<usize>,
    pub(crate) search_query_max_bytes: Option<usize>,
    pub(crate) offline_candidate_multiplier: Option<usize>,
    pub(crate) ack_timeout_ms: Option<u64>,
    pub(crate) index_cache_bytes: Option<usize>,
}

impl ResidenceBudgetPatch {
    /// Meets `other` field by field: a field both name takes the smaller
    /// value, a field one names takes that one.
    fn meet(&mut self, other: &Self) {
        let this = self;
        macro_rules! meet {
            ($field:ident) => {
                this.$field = match (this.$field, other.$field) {
                    (Some(mine), Some(theirs)) => Some(mine.min(theirs)),
                    (mine, theirs) => mine.or(theirs),
                };
            };
        }
        each_budget_field!(meet);
    }

    /// Replaces each field of `limits` this patch names.
    fn replace(&self, limits: &mut ResidenceOperationBudgetLimits) {
        let this = self;
        macro_rules! replace {
            ($field:ident) => {
                if let Some(value) = this.$field {
                    limits.$field = value;
                }
            };
        }
        each_budget_field!(replace);
    }

    /// Narrows each field of `limits` this patch names to its value.
    fn narrow(&self, limits: &mut ResidenceOperationBudgetLimits) {
        let this = self;
        macro_rules! narrow {
            ($field:ident) => {
                if let Some(value) = this.$field {
                    limits.$field = limits.$field.min(value);
                }
            };
        }
        each_budget_field!(narrow);
    }
}

/// The trusted residence rows a policy fold has met so far: the authored
/// vault values and the holder's narrowing, apart.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ResidenceBudgetFold {
    vault: ResidenceBudgetPatch,
    holder: ResidenceBudgetPatch,
}

impl ResidenceBudgetFold {
    /// Adds one trusted manifest's row.
    pub(crate) fn add(&mut self, row: &ResidenceOperationBudgetRow) {
        match row.precedence {
            ResidenceOperationBudgetPrecedence::NestedNarrowing => {
                self.vault.meet(&row.vault);
                if let Some(holder) = &row.holder {
                    self.holder.meet(holder);
                }
            }
        }
    }

    /// The effective budgets: the shipped defaults with every authored vault
    /// value in their place, then each holder value as a narrowing.
    pub(crate) fn resolve(&self) -> ResidenceOperationBudgetLimits {
        let mut limits = ResidenceOperationBudgetLimits::default();
        self.vault.replace(&mut limits);
        self.holder.narrow(&mut limits);
        limits
    }
}
