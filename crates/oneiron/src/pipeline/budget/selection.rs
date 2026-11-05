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
    section_limits: Vec<usize>,
    section_used: Vec<usize>,
    sections: Vec<usize>,
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
            section_limits: vec![limit],
            section_used: vec![0],
            sections: vec![0; len],
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

    /// A combined selection over concatenated sections (FIX 11124): `sections`
    /// tags each row with its section, `section_limits` caps each section, and
    /// `limit` backstops their total. Caps stay results-only (section 0).
    fn new_combined(
        sections: Vec<usize>,
        section_limits: Vec<usize>,
        caps: Option<ContextPackBudgetCounts>,
        limit: usize,
        fraction: f32,
        (base, non_base): (usize, usize),
    ) -> Self {
        let len = sections.len();
        let section_used = vec![0; section_limits.len()];
        Self {
            caps,
            limit,
            section_limits,
            section_used,
            sections,
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

    fn fits(&self, kind: ContextPackBudgetKind, section: usize) -> bool {
        if section != 0 {
            return true;
        }
        self.caps
            .is_none_or(|caps| self.used.get(kind) < caps.get(kind))
    }

    /// Whether one more non-base claim fits beside `base` base claims.
    fn non_base_fits(&self, base: usize) -> bool {
        non_base_claims_fit(base, self.non_base + 1, self.fraction)
    }

    fn pick(&mut self, index: usize, kind: ContextPackBudgetKind) {
        self.picked[index] = true;
        self.total += 1;
        let section = self.sections[index];
        self.section_used[section] += 1;
        if section == 0 {
            self.used.increment(kind);
        }
    }

    fn offer(&mut self, index: usize, kind: ContextPackBudgetKind, role: ShareRole) {
        if self.total >= self.limit || self.offered[index] {
            return;
        }
        self.offered[index] = true;
        let section = self.sections[index];
        if self.section_used[section] >= self.section_limits[section] {
            return;
        }
        if !self.fits(kind, section) {
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
                while self.total < self.limit && self.non_base_fits(self.base) {
                    let mut pick_pos = None;
                    for (pos, &held_index) in self.held.iter().enumerate() {
                        let held_section = self.sections[held_index];
                        if self.section_used[held_section] >= self.section_limits[held_section] {
                            continue;
                        }
                        if !self.fits(ContextPackBudgetKind::Claim, held_section) {
                            continue;
                        }
                        pick_pos = Some(pos);
                        break;
                    }
                    let Some(pos) = pick_pos else {
                        break;
                    };
                    let Some(next) = self.held.remove(pos) else {
                        break;
                    };
                    self.pick(next, ContextPackBudgetKind::Claim);
                    self.non_base += 1;
                }
            }
        }
    }

    /// The fewest of `available` base claims that let one more non-base
    /// claim in, when they and it fit the limit and the claim cap. The cap
    /// counts only section-0 claims (FIX 11124); `support_counts` and
    /// `future_critical` name each candidate's section so the drain that
    /// prefers later sections is priced exactly. Only future critical bases
    /// with remaining section room cover the need; the shortfall drains
    /// eagerly from ordinary support, each section capped by the room left
    /// after reserving the waiting row's own slot and every fit future
    /// base's slot (round-2 blind P1s). `held_cover` names already-held
    /// critical claims that still wait on the same bases: their slots are
    /// reserved first and the need covers them too, so one future base is
    /// never promised to two waiting rows (#4451 round-3 blind P1). Returns
    /// the need, the fit cover, and the per-section drain plan the caller
    /// executes exactly.
    fn support_needed(
        &self,
        available: usize,
        needing_section: usize,
        support_counts: &[usize],
        future_critical: &VecDeque<usize>,
        held_cover: &[usize],
    ) -> Option<(usize, usize, Vec<usize>)> {
        let held_count = held_cover.len();
        let need = (0..=available).find(|&count| {
            non_base_claims_fit(
                self.base + count,
                self.non_base + 1 + held_count,
                self.fraction,
            )
        })?;
        let claims = need + 1 + held_count;
        if self.total + claims > self.limit {
            return None;
        }
        // Future critical bases that can still be picked: each consumes one
        // slot of its section, with one slot of the waiting row's section
        // reserved for the waiting row itself. A future base past its
        // section's remaining room (FIX 11124 review: a neighbour base past
        // the neighbour limit) never covers the share, so the missing
        // ordinary support drains eagerly instead of the critical row dying
        // while ordinary rows fill its section.
        let mut room: Vec<usize> = self
            .section_limits
            .iter()
            .zip(self.section_used.iter())
            .map(|(&limit, &used)| limit.saturating_sub(used))
            .collect();
        if let Some(left) = room.get_mut(needing_section) {
            *left = left.saturating_sub(1);
        }
        for &held in held_cover {
            let section = self.sections[held];
            room[section] = room[section].saturating_sub(1);
        }
        let mut fit = Vec::new();
        for &index in future_critical.iter() {
            let section = self.sections[index];
            if room[section] > 0 {
                room[section] -= 1;
                fit.push(index);
            }
        }
        let fit_future = fit.len();
        let needing_sec0 = usize::from(needing_section == 0);
        let held_sec0 = held_cover
            .iter()
            .filter(|&&held| self.sections[held] == 0)
            .count();
        let (claims_sec0, takes) = if fit_future >= need {
            let mut count = needing_sec0;
            for &index in fit.iter().take(need) {
                count += usize::from(self.sections[index] == 0);
            }
            (count + held_sec0, vec![0_usize; support_counts.len()])
        } else {
            // Filling a section must never cut the row its room was reserved
            // for: the drain takes only from room left after the waiting
            // row's own slot and every fit future base's slot.
            let mut room_after: Vec<usize> = self
                .section_limits
                .iter()
                .zip(self.section_used.iter())
                .map(|(&limit, &used)| limit.saturating_sub(used))
                .collect();
            if let Some(left) = room_after.get_mut(needing_section) {
                *left = left.saturating_sub(1);
            }
            for &held in held_cover {
                let section = self.sections[held];
                room_after[section] = room_after[section].saturating_sub(1);
            }
            for &index in fit.iter() {
                let section = self.sections[index];
                room_after[section] = room_after[section].saturating_sub(1);
            }
            let mut drain = need - fit_future;
            let mut takes = vec![0_usize; support_counts.len()];
            for (section, &support) in support_counts.iter().enumerate().rev() {
                if drain == 0 {
                    break;
                }
                let take = drain.min(support).min(room_after[section]);
                takes[section] = take;
                drain -= take;
            }
            if drain > 0 {
                return None;
            }
            let mut future_sec0 = 0_usize;
            for &index in fit.iter() {
                future_sec0 += usize::from(self.sections[index] == 0);
            }
            let drained_sec0 = takes.first().copied().unwrap_or(0);
            (needing_sec0 + drained_sec0 + future_sec0 + held_sec0, takes)
        };
        let claim_room = self.caps.is_none_or(|caps| {
            self.used.get(ContextPackBudgetKind::Claim) + claims_sec0
                <= caps.get(ContextPackBudgetKind::Claim)
        });
        claim_room.then_some((need, fit_future, takes))
    }

    /// Offers `rows`, every critical row first in their order, then the rest
    /// in theirs. Before a critical non-base claim the share would hold, the
    /// fewest next ordinary base claims that let it in beside the critical
    /// base claims still to come are offered, when they and it fit, so its
    /// slot and its support are taken before any ordinary row (FIX 9760).
    /// Across sections the drain prefers later-section bases, each only while
    /// its section has room, so a held result takes a neighbour base before a
    /// same-section one (FIX 11124).
    fn offer_critical_first(
        &mut self,
        rows: &[(ScoredEntity, ContextPackBudgetKind, ShareRole)],
        critical: &HashSet<EntityId>,
    ) {
        let mut support: Vec<VecDeque<usize>> = (0..self.section_limits.len())
            .map(|_| VecDeque::new())
            .collect();
        let mut future_critical = VecDeque::new();
        for (index, (row, _, role)) in rows.iter().enumerate() {
            match (*role == ShareRole::BaseClaim, critical.contains(&row.id)) {
                (true, true) => future_critical.push_back(index),
                (true, false) => support[self.sections[index]].push_back(index),
                _ => {}
            }
        }
        for (index, &(row, kind, role)) in rows.iter().enumerate() {
            if !critical.contains(&row.id) {
                continue;
            }
            if role == ShareRole::BaseClaim {
                if future_critical.front() == Some(&index) {
                    let _ = future_critical.pop_front();
                } else if let Some(pos) = future_critical.iter().position(|&held| held == index) {
                    let _ = future_critical.remove(pos);
                }
            }
            if role == ShareRole::NonBaseClaim && !self.non_base_fits(self.base) {
                let needing_section = self.sections[index];
                if self.section_used[needing_section] < self.section_limits[needing_section] {
                    let support_total: usize = support.iter().map(VecDeque::len).sum();
                    let support_counts: Vec<usize> = support.iter().map(VecDeque::len).collect();
                    // Round-3 blind P1 (REVIEW-4451.md): already-held critical
                    // claims wait on the same future bases. Reserve the
                    // fittable ones' slots and cover first, so one future
                    // base is never promised to two waiting rows.
                    let held_cover: Vec<usize> = self
                        .held
                        .iter()
                        .copied()
                        .filter(|&held| {
                            let (held_row, held_kind, held_role) = &rows[held];
                            *held_role == ShareRole::NonBaseClaim
                                && critical.contains(&held_row.id)
                                && self.section_used[self.sections[held]]
                                    < self.section_limits[self.sections[held]]
                                && self.fits(*held_kind, self.sections[held])
                        })
                        .collect();
                    if let Some((.., takes)) = self.support_needed(
                        support_total + future_critical.len(),
                        needing_section,
                        &support_counts,
                        &future_critical,
                        &held_cover,
                    ) {
                        // Execute the priced per-section plan exactly: reserved
                        // slots are never taken here either.
                        for (section, &take) in takes.iter().enumerate().rev() {
                            for _ in 0..take {
                                let Some(base) = support[section].pop_front() else {
                                    break;
                                };
                                let (_, base_kind, base_role) = rows[base];
                                self.offer(base, base_kind, base_role);
                            }
                        }
                    }
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
///
/// FIX 11124 runs one `ShareSelection` over both sections together, so a
/// critical non-base result held for lack of base support can take a kept
/// neighbour base as its share support; caps stay results-only and each
/// section keeps its own limit.
pub(crate) fn select_context_pack_rows(
    results: &mut Vec<ContextEntity>,
    neighbors: &mut Vec<ContextEntity>,
    budget: ContextPackRetrievalBudget,
    (result_limit, neighbor_limit): (usize, usize),
    share: Option<&PackWorldShare>,
) -> bool {
    let caps = Some(ContextPackBudgetCounts::from_budget(budget));
    let fraction = share.map_or(1.0, |share| share.fraction);
    let mut offered = Vec::with_capacity(results.len() + neighbors.len());
    let mut sections = Vec::with_capacity(results.len() + neighbors.len());
    let mut critical = HashSet::new();
    for (section, rows) in [(0_usize, &*results), (1_usize, &*neighbors)] {
        for row in rows.iter() {
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
            offered.push((scored, kind, role));
            sections.push(section);
            if row.critical {
                critical.insert(row.id);
            }
        }
    }
    let limit = result_limit.saturating_add(neighbor_limit);
    let mut selection = ShareSelection::new_combined(
        sections,
        vec![result_limit, neighbor_limit],
        caps,
        limit,
        fraction,
        (0, 0),
    );
    selection.offer_critical_first(&offered, &critical);
    let mut picked = selection.picked.iter();
    let mut cut_critical = false;
    for rows in [results, neighbors] {
        rows.retain(|row| {
            let keep = picked.next().copied().unwrap_or(false);
            cut_critical |= !keep && row.critical;
            keep
        });
    }
    cut_critical
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
