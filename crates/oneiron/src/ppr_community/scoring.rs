//! Boost, prior, diversity selection and entropy scoring.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;
use crate::pipeline::ScoredEntity;

#[cfg(test)]
use super::DIVERSITY_SELECTION_WORK;
use super::types::{
    CommunityBoostContext, CommunityBoostReport, CommunityError, CommunityId, DiversityHead,
    DiversityTree, PPR_COMMUNITY_MAX_GRAPH_FRACTION, PPR_COMMUNITY_MAX_TOP_K_FRACTION,
    PPR_COMMUNITY_USAGE_DECAY, PprCommunityCache, PprCommunityConfig, Ranked, Result,
};

/// Exact cache-key bypass at beta zero. Adapter appends this only on Uniform PPR;
/// other config/seed/session inputs must also be accounted for or reranked uncached.
pub fn community_cache_identity(beta: f32, graph_version: u64) -> Result<Option<[u8; 12]>> {
    if beta == 0.0 {
        return Ok(None);
    }
    if !beta.is_finite() || beta < 0.0 {
        return Err(CommunityError::Config);
    }
    let mut bytes = [0; 12];
    bytes[..8].copy_from_slice(&graph_version.to_le_bytes());
    bytes[8..].copy_from_slice(&beta.to_bits().to_le_bytes());
    Ok(Some(bytes))
}

pub fn activated_communities(
    cache: &PprCommunityCache<'_>,
    seeds: &[ScoredEntity],
) -> Result<BTreeSet<CommunityId>> {
    validate_scores(seeds)?;
    if seeds.windows(2).any(|w| w[0].score < w[1].score) {
        return Err(CommunityError::Scores);
    }
    let mut active = BTreeSet::new();
    if seeds.is_empty() {
        return Ok(active);
    }
    let membership = |s: &ScoredEntity| cache.nodes.get(&s.id).map(|m| m.fine);
    if (seeds.len() == 1
        || (seeds[0].score > 0.0 && f64::from(seeds[0].score) >= 1.5 * f64::from(seeds[1].score)))
        && let Some(id) = membership(&seeds[0])
    {
        active.insert(id);
    }
    let mut counts = BTreeMap::new();
    for seed in seeds.iter().take(5) {
        if let Some(id) = membership(seed) {
            *counts.entry(id).or_insert(0) += 1;
        }
    }
    active.extend(
        counts
            .into_iter()
            .filter_map(|(id, count)| (count >= 2).then_some(id)),
    );
    Ok(active)
}

pub(super) fn validate_scores(scores: &[ScoredEntity]) -> Result<()> {
    let mut ids = BTreeSet::new();
    if scores
        .iter()
        .any(|s| !s.score.is_finite() || s.score < 0.0 || !ids.insert(s.id))
    {
        return Err(CommunityError::Scores);
    }
    Ok(())
}

pub fn community_multiplier(
    size: usize,
    graph_size: usize,
    usage: u32,
    config: &PprCommunityConfig,
) -> Result<f32> {
    if config.beta == 0.0 {
        return Ok(1.0);
    }
    config.validate()?;
    let oversized = if config.max_graph_fraction == PPR_COMMUNITY_MAX_GRAPH_FRACTION {
        size as u128 * 10 > graph_size as u128
    } else {
        size as f64 > graph_size as f64 * f64::from(config.max_graph_fraction)
    };
    if size == 0 || graph_size == 0 || oversized {
        return Ok(1.0);
    }
    let bonus = f64::from(config.beta) / (size as f64).ln_1p();
    let decay = (-f64::from(PPR_COMMUNITY_USAGE_DECAY) * f64::from(usage)).exp();
    Ok((1.0 + bonus * decay).min(f64::from(config.multiplier_cap)) as f32)
}

/// Beta zero returns before validation, copying, sorting, truncation or arithmetic.
/// Standalone PPR callers select here; the pipeline defers selection until fusion,
/// admission filters, reranking and budgets have finished.
pub fn apply_community_prior(
    scores: &mut Vec<ScoredEntity>,
    cache: &PprCommunityCache<'_>,
    context: &CommunityBoostContext<'_>,
    config: &PprCommunityConfig,
) -> Result<CommunityBoostReport> {
    let (mut report, boosted) = boost_community_scores(scores, cache, context, config)?;
    if report.activated_communities > 0 {
        let diversity =
            apply_community_diversity(scores, cache, &boosted, context.result_limit, config)?;
        report.fine_entropy_bits = diversity.fine_entropy_bits;
        report.coarse_entropy_bits = diversity.coarse_entropy_bits;
    }
    Ok(report)
}

/// Apply the multiplier once without dropping candidates needed by later filters.
pub(crate) fn boost_community_scores(
    scores: &mut Vec<ScoredEntity>,
    cache: &PprCommunityCache<'_>,
    context: &CommunityBoostContext<'_>,
    config: &PprCommunityConfig,
) -> Result<(CommunityBoostReport, BTreeSet<EntityId>)> {
    let mut boosted_ids = BTreeSet::new();
    if config.beta == 0.0 {
        return Ok((CommunityBoostReport::default(), boosted_ids));
    }
    config.validate()?;
    validate_scores(scores)?;
    let active = activated_communities(cache, context.ordered_seeds)?;
    if active.is_empty() {
        return Ok((CommunityBoostReport::default(), boosted_ids));
    }
    let mut ranked = Vec::with_capacity(scores.len());
    let mut report = CommunityBoostReport {
        activated_communities: active.len(),
        ..Default::default()
    };
    for &candidate in scores.iter() {
        let membership = cache.nodes.get(&candidate.id).copied();
        let mut multiplier = 1.0;
        if let Some(m) = membership.filter(|m| active.contains(&m.fine)) {
            multiplier = community_multiplier(
                cache.sizes[&m.fine],
                cache.graph_size,
                *context.session_usage.get(&m.fine).unwrap_or(&0),
                config,
            )?;
        }
        if multiplier > 1.0 && candidate.score > 0.0 {
            boosted_ids.insert(candidate.id);
        }
        let score = candidate.score * multiplier;
        if !score.is_finite() {
            return Err(CommunityError::Scores);
        }
        ranked.push(ScoredEntity { score, ..candidate });
    }
    report.boosted_candidates = boosted_ids.len();
    ranked.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    *scores = ranked;
    Ok((report, boosted_ids))
}

/// Select only from admitted final candidates. Never expand membership into rows,
/// reapply the prior, or truncate a PPR channel before fusion and filtering.
pub(crate) fn apply_community_diversity(
    scores: &mut Vec<ScoredEntity>,
    cache: &PprCommunityCache<'_>,
    boosted: &BTreeSet<EntityId>,
    limit: usize,
    config: &PprCommunityConfig,
) -> Result<CommunityBoostReport> {
    if config.beta == 0.0 {
        return Ok(CommunityBoostReport::default());
    }
    config.validate()?;
    validate_scores(scores)?;
    let ranked = scores
        .iter()
        .map(|&entity| Ranked {
            entity,
            membership: cache.nodes.get(&entity.id).copied(),
            boosted: boosted.contains(&entity.id),
        })
        .collect();
    let selected = diversify(ranked, limit, config.max_top_k_fraction);
    let report = CommunityBoostReport {
        fine_entropy_bits: entropy(&selected, false),
        coarse_entropy_bits: entropy(&selected, true),
        ..Default::default()
    };
    *scores = selected.into_iter().map(|r| r.entity).collect();
    Ok(report)
}

impl DiversityHead {
    fn before(self, other: Self) -> bool {
        diversity_selection_work();
        other
            .row
            .entity
            .score
            .total_cmp(&self.row.entity.score)
            .then_with(|| self.fine.cmp(&other.fine))
            .then_with(|| self.coarse.cmp(&other.coarse))
            .then_with(|| self.row.entity.id.cmp(&other.row.entity.id))
            .is_lt()
    }
}

#[inline]
fn diversity_selection_work() {
    #[cfg(test)]
    DIVERSITY_SELECTION_WORK.with(|count| count.set(count.get() + 1));
}

impl DiversityTree {
    fn new(groups: usize) -> Self {
        let size = groups.max(1).next_power_of_two();
        Self {
            size,
            best: vec![None; size * 2],
            lazy: vec![0; size * 2],
        }
    }

    fn add(&mut self, node: usize, delta: usize) {
        if let Some(head) = &mut self.best[node] {
            head.coarse += delta;
        }
        self.lazy[node] += delta;
    }

    fn push(&mut self, node: usize) {
        let delta = std::mem::take(&mut self.lazy[node]);
        self.add(node * 2, delta);
        self.add(node * 2 + 1, delta);
    }

    fn pull(&mut self, node: usize) {
        self.best[node] = match (self.best[node * 2], self.best[node * 2 + 1]) {
            (Some(a), Some(b)) => Some(if a.before(b) { a } else { b }),
            (a, b) => a.or(b),
        };
    }

    fn set(&mut self, group: usize, head: Option<DiversityHead>) {
        let leaf = self.size + group;
        for shift in (1..=self.size.trailing_zeros()).rev() {
            diversity_selection_work();
            self.push(leaf >> shift);
        }
        self.best[leaf] = head;
        self.lazy[leaf] = 0;
        let mut node = leaf / 2;
        while node > 0 {
            diversity_selection_work();
            self.pull(node);
            node /= 2;
        }
    }

    fn increment(&mut self, start: usize, end: usize) {
        self.increment_range(1, 0, self.size, start, end);
    }

    fn increment_range(
        &mut self,
        node: usize,
        left: usize,
        right: usize,
        start: usize,
        end: usize,
    ) {
        diversity_selection_work();
        if end <= left || right <= start {
            return;
        }
        if start <= left && right <= end {
            self.add(node, 1);
            return;
        }
        self.push(node);
        let middle = left + (right - left) / 2;
        self.increment_range(node * 2, left, middle, start, end);
        self.increment_range(node * 2 + 1, middle, right, start, end);
        self.pull(node);
    }
}

/// Select in O(n log n + k log n) time and O(n) space. The eligible tree
/// enforces the cap while any alternative remains; the all-rows tree supplies
/// the exact fallback. Both use score, fine novelty, coarse novelty, then ID.
pub(super) fn diversify(mut pool: Vec<Ranked>, limit: usize, fraction: f32) -> Vec<Ranked> {
    let k = limit.min(pool.len());
    if k == 0 {
        return Vec::new();
    }
    // Exact rational default avoids floor(10 * f64::from(0.7_f32)) == 6.
    let cap = if fraction == PPR_COMMUNITY_MAX_TOP_K_FRACTION {
        (k / 10 * 7 + k % 10 * 7 / 10).max(1)
    } else {
        ((k as f64 * f64::from(fraction)).floor() as usize).max(1)
    };
    let protected = pool
        .iter()
        .enumerate()
        .filter(|(_, r)| !r.boosted)
        .min_by(|(_, a), (_, b)| {
            b.entity
                .score
                .total_cmp(&a.entity.score)
                .then_with(|| a.entity.id.cmp(&b.entity.id))
        })
        .map(|(i, _)| i)
        .map(|i| pool.swap_remove(i));
    let mut groups = BTreeMap::<_, Vec<Ranked>>::new();
    for row in pool {
        groups
            .entry(row.membership.map(|m| (m.coarse, m.fine)))
            .or_default()
            .push(row);
    }
    let mut groups: Vec<_> = groups.into_values().collect();
    let mut ranges = BTreeMap::new();
    for (group, rows) in groups.iter_mut().enumerate() {
        // Pop the highest score, then lowest ID, without shifting any rows.
        rows.sort_unstable_by(|a, b| {
            a.entity
                .score
                .total_cmp(&b.entity.score)
                .then_with(|| b.entity.id.cmp(&a.entity.id))
        });
        if let Some(m) = rows[0].membership {
            ranges.entry(m.coarse).or_insert((group, group)).1 = group + 1;
        }
    }
    let mut all = DiversityTree::new(groups.len());
    let mut eligible = DiversityTree::new(groups.len());
    let mut fine = BTreeMap::new();
    let mut coarse = BTreeMap::new();
    if let Some(m) = protected.and_then(|r| r.membership) {
        fine.insert(m.fine, 1usize);
        coarse.insert(m.coarse, 1usize);
    }
    for (group, rows) in groups.iter().enumerate() {
        let row = *rows.last().expect("nonempty fine group");
        let head = DiversityHead {
            row,
            group,
            fine: row
                .membership
                .map_or(0, |m| *fine.get(&m.fine).unwrap_or(&0)),
            coarse: row
                .membership
                .map_or(0, |m| *coarse.get(&m.coarse).unwrap_or(&0)),
        };
        all.set(group, Some(head));
        if row.membership.is_none() || head.fine < cap {
            eligible.set(group, Some(head));
        }
    }
    let mut selected = Vec::with_capacity(k);
    while selected.len() + usize::from(protected.is_some()) < k {
        let Some(head) = eligible.best[1].or(all.best[1]) else {
            break;
        };
        let row = groups[head.group].pop().expect("selected group head");
        if let Some(m) = row.membership {
            *fine.entry(m.fine).or_insert(0) += 1;
            *coarse.entry(m.coarse).or_insert(0) += 1;
            let (start, end) = ranges[&m.coarse];
            all.increment(start, end);
            eligible.increment(start, end);
        }
        let next = groups[head.group].last().map(|&row| DiversityHead {
            row,
            group: head.group,
            fine: row.membership.map_or(0, |m| fine[&m.fine]),
            coarse: row.membership.map_or(0, |m| coarse[&m.coarse]),
        });
        all.set(head.group, next);
        eligible.set(
            head.group,
            next.filter(|h| h.row.membership.is_none() || h.fine < cap),
        );
        selected.push(row);
    }
    if let Some(row) = protected {
        let position = selected
            .iter()
            .position(|r| r.entity.score < row.entity.score)
            .unwrap_or(selected.len());
        selected.insert(position, row);
    }
    selected
}

pub(super) fn entropy(rows: &[Ranked], coarse: bool) -> f64 {
    let mut counts = BTreeMap::new();
    for row in rows {
        // Uncached entities count as separate alternatives, not one fake community.
        let key = row.membership.map_or((None, Some(row.entity.id)), |m| {
            (Some(if coarse { m.coarse } else { m.fine }), None)
        });
        *counts.entry(key).or_insert(0usize) += 1;
    }
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / rows.len() as f64;
            -p * p.log2()
        })
        .sum()
}
