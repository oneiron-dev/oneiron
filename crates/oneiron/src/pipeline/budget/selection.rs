//! Critical-first selection of a pack run's scored rows under its existing
//! budgets (FIX 9760): every cut is offered the critical claims first, each
//! class in score order, and the rows it keeps keep their score order.

use std::collections::{HashMap, HashSet};

use crate::context_pack::PackCriticalAccounting;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::super::types::ScoredEntity;
use super::{ContextPackBudgetCounts, ContextPackBudgetKind, ShareRole, select_rows};

/// [`select_rows`] with every critical row offered before the rest. The
/// picked rows keep their score order.
pub(super) fn select_rows_critical_first(
    rows: &[(ScoredEntity, ContextPackBudgetKind, ShareRole)],
    critical: &HashSet<EntityId>,
    caps: Option<ContextPackBudgetCounts>,
    limit: usize,
    fraction: f32,
) -> (Vec<ScoredEntity>, bool) {
    if critical.is_empty() {
        return select_rows(rows, caps, limit, fraction);
    }
    let mut offered = rows.to_vec();
    offered.sort_by_key(|(row, ..)| !critical.contains(&row.id));
    let (mut picked, share_held_back) = select_rows(&offered, caps, limit, fraction);
    let rank: HashMap<EntityId, usize> = rows
        .iter()
        .enumerate()
        .map(|(index, (row, ..))| (row.id, index))
        .collect();
    picked.sort_by_key(|row| rank.get(&row.id).copied().unwrap_or(usize::MAX));
    (picked, share_held_back)
}

/// Cuts `scores` to `limit` rows, critical rows first; the kept rows keep
/// their order.
pub(in crate::pipeline) fn truncate_critical_first(
    scores: &mut Vec<ScoredEntity>,
    limit: usize,
    critical: &HashSet<EntityId>,
) {
    let mut taken = 0_usize;
    crate::context_pack::select_critical_pack_rows(
        scores,
        |row| critical.contains(&row.id),
        |_| {
            let fits = taken < limit;
            taken += usize::from(fits);
            fits
        },
    );
}

/// Runs `cut`, a reorder that may also drop rows, then appends each critical
/// row it dropped, in their prior order, so the result-limit cut after it
/// decides them, critical rows first.
pub(in crate::pipeline) fn keep_critical_through(
    scores: &mut Vec<ScoredEntity>,
    critical: &HashSet<EntityId>,
    cut: impl FnOnce(&mut Vec<ScoredEntity>) -> Result<()>,
) -> Result<()> {
    let held: Vec<ScoredEntity> = scores
        .iter()
        .filter(|row| critical.contains(&row.id))
        .copied()
        .collect();
    cut(scores)?;
    let kept: HashSet<EntityId> = scores.iter().map(|row| row.id).collect();
    scores.extend(held.into_iter().filter(|row| !kept.contains(&row.id)));
    Ok(())
}

/// A pack run's critical accounting: `eligible`, its critical candidates
/// before any cut, and those of them the cuts left out of `scores`.
pub(in crate::pipeline) fn pack_critical_accounting(
    eligible: HashSet<EntityId>,
    scores: &[ScoredEntity],
) -> PackCriticalAccounting {
    let kept: HashSet<EntityId> = scores.iter().map(|row| row.id).collect();
    PackCriticalAccounting {
        budget_omitted_ids: eligible
            .iter()
            .filter(|id| !kept.contains(id))
            .copied()
            .collect(),
        eligible_ids: eligible.into_iter().collect(),
    }
}
