//! Critical-first row selection under a pack's existing budgets, and the
//! critical accounting a pack reports (FIX 9760).

use std::collections::BTreeSet;

use super::super::types::{ContextEntity, PackCriticalAccounting, PackStats};

/// Keeps the rows of `rows` that `admit` takes. `admit` is offered every
/// critical row first and then every other row, each class in its existing
/// order, so critical rows fill the caller's budget first and nothing widens
/// it; the kept rows keep their existing order. Returns the critical rows
/// left out.
pub fn select_critical_pack_rows<T>(
    rows: &mut Vec<T>,
    is_critical: impl Fn(&T) -> bool,
    mut admit: impl FnMut(&T) -> bool,
) -> Vec<T> {
    let mut picked = vec![false; rows.len()];
    for critical_pass in [true, false] {
        for (row, picked) in rows.iter().zip(picked.iter_mut()) {
            if is_critical(row) == critical_pass && admit(row) {
                *picked = true;
            }
        }
    }
    let mut cut_critical = Vec::new();
    let mut kept = Vec::with_capacity(rows.len());
    for (row, picked) in std::mem::take(rows).into_iter().zip(picked) {
        if picked {
            kept.push(row);
        } else if is_critical(&row) {
            cut_critical.push(row);
        }
    }
    *rows = kept;
    cut_critical
}

impl PackCriticalAccounting {
    /// Adds the ids `other` found: a run's neighbors beside its results.
    pub(crate) fn extend(&mut self, other: Self) {
        self.eligible_ids.extend(other.eligible_ids);
        self.budget_omitted_ids.extend(other.budget_omitted_ids);
    }

    /// Settles the accounting against the rows a pack carries. A critical row
    /// it carries is eligible and not omitted; an eligible id it neither
    /// carries nor lost to a budget was refused by a gate after selection,
    /// and no longer counts. Every omitted id stays eligible.
    pub(crate) fn settle<'r>(&mut self, rows: impl IntoIterator<Item = &'r ContextEntity>) {
        let mut carried = BTreeSet::new();
        let mut carried_critical = BTreeSet::new();
        for row in rows {
            carried.insert(row.id);
            if row.critical {
                carried_critical.insert(row.id);
            }
        }
        self.budget_omitted_ids.retain(|id| !carried.contains(id));
        let omitted = &self.budget_omitted_ids;
        self.eligible_ids
            .retain(|id| carried_critical.contains(id) || omitted.contains(id));
        self.eligible_ids.extend(carried_critical);
        self.eligible_ids
            .extend(self.budget_omitted_ids.iter().copied());
    }

    /// Writes the pre-cut critical count and the overflow warning to `stats`.
    pub(crate) fn report(&self, stats: &mut PackStats) {
        stats.critical_count = self.eligible_ids.len();
        stats.critical_over_budget = !self.budget_omitted_ids.is_empty();
    }
}
