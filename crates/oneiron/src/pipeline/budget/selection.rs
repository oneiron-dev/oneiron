//! Critical-first selection of a pack run's scored rows under its existing
//! budgets (FIX 9760): every cut is offered the critical claims first, each
//! class in score order, and the rows it keeps keep their score order.

use std::collections::{HashSet, VecDeque};

use crate::context_pack::{
    ContextEntity, ContextPackRetrievalBudget, PackCriticalAccounting, PackWorldShare,
};
use crate::entity_id::EntityId;
use crate::error::Result;

use super::super::types::ScoredEntity;
use super::{ContextPackBudgetCounts, ContextPackBudgetKind, ShareRole, non_base_claims_fit};

/// The share-aware selection law (ARCH-0004), one offered row at a time: a
/// row enters under per-kind `caps` and a `limit`; a non-base claim enters
/// only while the world share holds, and one held back enters as soon as
/// later base claims make room, so the page goes short, never over the
/// share, when base claims are scarce. Each row is offered once.
struct ShareSelection {
    caps: Option<ContextPackBudgetCounts>,
    limit: usize,
    fraction: f32,
    offered: Vec<bool>,
    picked: Vec<bool>,
    used: ContextPackBudgetCounts,
    total: usize,
    base: usize,
    non_base: usize,
    held: VecDeque<usize>,
}

impl ShareSelection {
    /// A selection over `len` rows that starts from `base` and `non_base`
    /// claims another section of the same pack already emits.
    fn new(
        len: usize,
        caps: Option<ContextPackBudgetCounts>,
        limit: usize,
        fraction: f32,
        (base, non_base): (usize, usize),
    ) -> Self {
        Self {
            caps,
            limit,
            fraction,
            offered: vec![false; len],
            picked: vec![false; len],
            used: ContextPackBudgetCounts::default(),
            total: 0,
            base,
            non_base,
            held: VecDeque::new(),
        }
    }

    fn fits(&self, kind: ContextPackBudgetKind) -> bool {
        self.caps
            .is_none_or(|caps| self.used.get(kind) < caps.get(kind))
    }

    /// Whether one more non-base claim fits beside `base` base claims.
    fn non_base_fits(&self, base: usize) -> bool {
        non_base_claims_fit(base, self.non_base + 1, self.fraction)
    }

    fn pick(&mut self, index: usize, kind: ContextPackBudgetKind) {
        self.picked[index] = true;
        self.used.increment(kind);
        self.total += 1;
    }

    fn offer(&mut self, index: usize, kind: ContextPackBudgetKind, role: ShareRole) {
        if self.total >= self.limit || self.offered[index] {
            return;
        }
        self.offered[index] = true;
        if !self.fits(kind) {
            return;
        }
        if role == ShareRole::NonBaseClaim && !self.non_base_fits(self.base) {
            self.held.push_back(index);
            return;
        }
        self.pick(index, kind);
        match role {
            ShareRole::Free => {}
            ShareRole::NonBaseClaim => self.non_base += 1,
            ShareRole::BaseClaim => {
                self.base += 1;
                while self.total < self.limit && self.fits(kind) && self.non_base_fits(self.base) {
                    let Some(next) = self.held.pop_front() else {
                        break;
                    };
                    self.pick(next, kind);
                    self.non_base += 1;
                }
            }
        }
    }

    /// The fewest of `available` base claims that let one more non-base
    /// claim in, when they and it fit the limit and the claim cap.
    fn support_needed(&self, available: usize) -> Option<usize> {
        let need = (0..=available).find(|&count| self.non_base_fits(self.base + count))?;
        let claims = need + 1;
        let claim_room = self.caps.is_none_or(|caps| {
            self.used.get(ContextPackBudgetKind::Claim) + claims
                <= caps.get(ContextPackBudgetKind::Claim)
        });
        (self.total + claims <= self.limit && claim_room).then_some(need)
    }

    /// Offers `rows`, every critical row first in their order, then the rest
    /// in theirs. Before a critical non-base claim the share would hold, the
    /// fewest next ordinary base claims that let it in beside the critical
    /// base claims still to come are offered, when they and it fit, so its
    /// slot and its support are taken before any ordinary row (FIX 9760).
    fn offer_critical_first(
        &mut self,
        rows: &[(ScoredEntity, ContextPackBudgetKind, ShareRole)],
        critical: &HashSet<EntityId>,
    ) {
        let (mut support, mut critical_bases) = (VecDeque::new(), 0_usize);
        for (index, (row, _, role)) in rows.iter().enumerate() {
            match (*role == ShareRole::BaseClaim, critical.contains(&row.id)) {
                (true, true) => critical_bases += 1,
                (true, false) => support.push_back(index),
                _ => {}
            }
        }
        for (index, &(row, kind, role)) in rows.iter().enumerate() {
            if !critical.contains(&row.id) {
                continue;
            }
            if role == ShareRole::BaseClaim {
                critical_bases -= 1;
            }
            if role == ShareRole::NonBaseClaim
                && !self.non_base_fits(self.base)
                && let Some(need) = self.support_needed(support.len() + critical_bases)
            {
                for base in support.drain(..need.saturating_sub(critical_bases)) {
                    let (_, base_kind, base_role) = rows[base];
                    self.offer(base, base_kind, base_role);
                }
            }
            self.offer(index, kind, role);
        }
        for (index, &(_, kind, role)) in rows.iter().enumerate() {
            self.offer(index, kind, role);
        }
    }
}

/// Picks `rows` in score order under per-kind `caps` and a `limit` by the
/// share-aware selection law, every critical row offered first with the base
/// support it needs. The picked rows keep their score order. Also returns
/// whether the share kept a claim out.
pub(super) fn select_rows_critical_first(
    rows: &[(ScoredEntity, ContextPackBudgetKind, ShareRole)],
    critical: &HashSet<EntityId>,
    caps: Option<ContextPackBudgetCounts>,
    limit: usize,
    fraction: f32,
) -> (Vec<ScoredEntity>, bool) {
    let mut selection = ShareSelection::new(rows.len(), caps, limit, fraction, (0, 0));
    selection.offer_critical_first(rows, critical);
    let picked = rows
        .iter()
        .zip(&selection.picked)
        .filter_map(|(&(scored, ..), &picked)| picked.then_some(scored))
        .collect();
    (picked, !selection.held.is_empty())
}

/// Cuts a context pack's rows after its assembly by the pipeline's selection
/// law (FIX 9759, FIX 9760): `results` to the per-kind `budget` and the first
/// of `limits`, then `neighbors` to the second, critical rows first in each,
/// an `All`-world pack's `share` held over both sections together. The kept
/// rows keep their order. Returns whether a cut left out a critical row.
pub(crate) fn select_context_pack_rows(
    results: &mut Vec<ContextEntity>,
    neighbors: &mut Vec<ContextEntity>,
    budget: ContextPackRetrievalBudget,
    (result_limit, neighbor_limit): (usize, usize),
    share: Option<&PackWorldShare>,
) -> bool {
    let caps = Some(ContextPackBudgetCounts::from_budget(budget));
    let (results_cut, emitted) = select_pack_section(results, caps, result_limit, share, (0, 0));
    let (neighbors_cut, _) = select_pack_section(neighbors, None, neighbor_limit, share, emitted);
    results_cut || neighbors_cut
}

/// One section of [`select_context_pack_rows`], beside the `emitted` base
/// and non-base claims an earlier section kept. Returns whether it left out
/// a critical row, and the claims emitted with it.
fn select_pack_section(
    rows: &mut Vec<ContextEntity>,
    caps: Option<ContextPackBudgetCounts>,
    limit: usize,
    share: Option<&PackWorldShare>,
    emitted: (usize, usize),
) -> (bool, (usize, usize)) {
    let offered: Vec<_> = rows
        .iter()
        .map(|row| {
            let kind = ContextPackBudgetKind::from_entity_type(row.entity_type);
            let role = match share {
                Some(share) if kind == ContextPackBudgetKind::Claim => {
                    if share.non_base_claims.contains(&row.id) {
                        ShareRole::NonBaseClaim
                    } else {
                        ShareRole::BaseClaim
                    }
                }
                _ => ShareRole::Free,
            };
            let scored = ScoredEntity {
                id: row.id,
                score: row.score,
            };
            (scored, kind, role)
        })
        .collect();
    let critical: HashSet<EntityId> = rows
        .iter()
        .filter(|row| row.critical)
        .map(|row| row.id)
        .collect();
    let fraction = share.map_or(1.0, |share| share.fraction);
    let mut selection = ShareSelection::new(offered.len(), caps, limit, fraction, emitted);
    selection.offer_critical_first(&offered, &critical);
    let mut picked = selection.picked.iter();
    let mut cut_critical = false;
    rows.retain(|row| {
        let keep = picked.next().copied().unwrap_or(false);
        cut_critical |= !keep && row.critical;
        keep
    });
    (cut_critical, (selection.base, selection.non_base))
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

/// Runs `cut`, a reorder that may also drop rows, then puts every critical
/// row first, those it kept and those it dropped alike, in their order
/// before it, so the result-limit cut after it takes them by that rank; the
/// other rows it kept follow in its order (FIX 9760).
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
    scores.retain(|row| !critical.contains(&row.id));
    scores.splice(0..0, held);
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
