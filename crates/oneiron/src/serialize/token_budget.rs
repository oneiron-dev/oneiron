//! Core half of `serialize::token_budget`: its store-layer items live in `oneiron_store::serialize::token_budget` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::serialize::token_budget::*;

use super::group_labels::known_group_labels;
use super::item_budget::is_critical_predicate_claim;
use super::pack_entry::{
    PreparedEntity, PreparedGroups, PreparedPack, SerializeConfig, serialize_prepared_pack,
};
use super::pack_preparation::{clone_value_with_depth_limit, value_depth_limit_reached};
use super::types::{GROUP_ORDER, GroupKey, ValueDepthLimit};
use crate::context_pack::ContextPack;
use crate::context_pack::PackStats;
use crate::context_pack::{BASE_WORLD_SECTION, WORLD_SECTION_FIELD};
use crate::registry::ENTITY_TYPE_FACET;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::serialize::pack_accounting::PackItemTokenStats;
use crate::serialize::pack_accounting::PackSectionTokenStats;
use crate::serialize::pack_accounting::PackTokenStats;
use crate::serialize::pack_accounting::TokenAllocation;
use crate::serialize::pack_format::PackFormat;
use crate::store::retrieval_signal::Signal;
use crate::tokenizer::PackTokenizer;
use serde_json::{Map, Number, Value};
use std::collections::HashMap;

/// The world section label (`context_pack::WORLD_SECTION_FIELD`) a hydrated
/// row carries, if any.
pub(super) fn world_section_label(fields: Option<&HashMap<String, Value>>) -> Option<&str> {
    fields?.get(WORLD_SECTION_FIELD)?.as_str()
}

/// The section order of a world-partitioned pack's rows (ARCH-0004
/// #world-scope: "the base-reality section first, labeled per-world sections
/// after"). `context_pack`'s partition orders the rows by section and labels
/// each one; a serializer that re-sorts rows by criticality and score sorts by
/// this rank first. Rank 0 is base reality and any row with no label, so an
/// unpartitioned pack sorts as before; each non-base world takes the next rank
/// in the order its first row appears.
#[derive(Debug)]
pub(super) struct WorldSectionOrder {
    ranks: HashMap<String, usize>,
}

impl WorldSectionOrder {
    pub(super) fn of_rows<T>(rows: &[T], label: impl Fn(&T) -> Option<&str>) -> Self {
        let mut ranks = HashMap::new();
        for row in rows {
            let Some(label) = label(row) else {
                continue;
            };
            if label != BASE_WORLD_SECTION && !ranks.contains_key(label) {
                let rank = ranks.len() + 1;
                ranks.insert(label.to_owned(), rank);
            }
        }
        Self { ranks }
    }

    pub(super) fn rank(&self, label: Option<&str>) -> usize {
        label
            .and_then(|label| self.ranks.get(label).copied())
            .unwrap_or(0)
    }
}

pub(super) fn group_entities(
    entities: Vec<PreparedEntity>,
) -> Vec<(GroupKey, Vec<PreparedEntity>)> {
    // Within a record kind, a partitioned pack's rows keep their world
    // sections in the pack's order, base first (ARCH-0004 #world-scope); the
    // rank is 0 for every row of an unpartitioned pack, which sorts as before.
    let sections = WorldSectionOrder::of_rows(&entities, |entity| entity.world_section.as_deref());
    let mut buckets = HashMap::<GroupKey, Vec<PreparedEntity>>::new();
    for entity in entities {
        buckets
            .entry(group_key_of(entity.entity_type))
            .or_default()
            .push(entity);
    }

    for rows in buckets.values_mut() {
        rows.sort_unstable_by(|a, b| {
            sections
                .rank(a.world_section.as_deref())
                .cmp(&sections.rank(b.world_section.as_deref()))
                .then_with(|| b.critical.cmp(&a.critical))
                .then_with(|| b.score.total_cmp(&a.score))
                .then_with(|| a.id.cmp(&b.id))
        });
    }

    let mut out = Vec::new();
    for entity_type in GROUP_ORDER {
        let key = GroupKey::Kind(*entity_type);
        if let Some(rows) = buckets.remove(&key)
            && !rows.is_empty()
        {
            out.push((key, rows));
        }
    }

    let mut rest: Vec<(GroupKey, Vec<PreparedEntity>)> = buckets.into_iter().collect();
    rest.sort_unstable_by_key(|(key, _)| *key);
    for (key, rows) in rest {
        if !rows.is_empty() {
            out.push((key, rows));
        }
    }

    out
}

pub(super) fn token_budget_droppable_count(groups: &[(GroupKey, Vec<PreparedEntity>)]) -> usize {
    groups.iter().flat_map(|(_, rows)| rows.iter()).count()
}

pub(super) fn enforce_token_budget_with_depth_limit(
    groups: &mut Vec<(GroupKey, Vec<PreparedEntity>)>,
    allocation: &TokenAllocation,
    token_budget: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    if token_budget == 0 {
        groups.clear();
        return 0;
    }

    let needs: Vec<usize> = groups
        .iter()
        .map(|(_, rows)| {
            rows.iter()
                .map(|row| {
                    estimate_entity_tokens_with_depth_limit(row, tokenizer, value_depth_limit)
                })
                .sum::<usize>()
        })
        .collect();
    // Groups whose summed need fits keep every row. The per-type split below
    // floors each share, so at a budget equal to the need (what
    // `allocate_section_budgets` hands a section that fits) one type ended a
    // token short and lost its row (FIX [CONTEXT-PACK-GROUP-SPLIT-DROPS-ROW]).
    let total_need = needs
        .iter()
        .fold(0_usize, |total, need| total.saturating_add(*need));
    if total_need <= token_budget {
        groups.retain(|(_, rows)| !rows.is_empty());
        return total_need;
    }

    // Normalize fractions so they sum to 1.0 (multiple "other" types each
    // get allocation.other, so raw sum can exceed 1.0).
    let raw: Vec<f32> = groups
        .iter()
        .map(|(et, _)| type_fraction(*et, allocation))
        .collect();
    let total: f32 = raw.iter().sum();
    let norm = if total > 0.0 { 1.0 / total } else { 0.0 };

    // First pass: compute initial budgets vs actual needs.
    let mut budgets: Vec<usize> = Vec::with_capacity(groups.len());
    let mut surplus: usize = 0;
    let mut hungry_weight: f32 = 0.0;

    for (i, &needed) in needs.iter().enumerate() {
        let frac = raw[i] * norm;
        let budget = (token_budget as f32 * frac) as usize;
        if needed <= budget {
            surplus += budget - needed;
        } else {
            hungry_weight += frac;
        }
        budgets.push(budget);
    }

    // Second pass: redistribute surplus to hungry types, then truncate.
    let mut total_used = 0_usize;
    for (i, (_, rows)) in groups.iter_mut().enumerate() {
        let final_budget = if needs[i] <= budgets[i] {
            // Satisfied — cap at what it needs, release rest.
            needs[i]
        } else if hungry_weight > 0.0 {
            let frac = raw[i] * norm;
            let extra = (surplus as f32 * (frac / hungry_weight)) as usize;
            budgets[i] + extra
        } else {
            budgets[i]
        };

        let mut used = 0_usize;
        let mut kept = Vec::with_capacity(rows.len());
        for row in rows.drain(..) {
            let tokens =
                estimate_entity_tokens_with_depth_limit(&row, tokenizer, value_depth_limit);
            if used.saturating_add(tokens) > final_budget {
                continue;
            }
            used += tokens;
            kept.push(row);
        }
        *rows = kept;
        total_used = total_used.saturating_add(used);
    }

    groups.retain(|(_, rows)| !rows.is_empty());
    total_used
}

pub(super) fn estimate_entity_tokens_with_depth_limit(
    entity: &PreparedEntity,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    tokenizer.count(&entity_token_accounting_text(entity, value_depth_limit))
}

pub(super) fn estimate_groups_tokens_with_depth_limit(
    groups: &[(GroupKey, Vec<PreparedEntity>)],
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    groups
        .iter()
        .flat_map(|(_, rows)| rows.iter())
        .map(|entity| estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit))
        .sum()
}

fn entity_token_accounting_text(
    entity: &PreparedEntity,
    value_depth_limit: ValueDepthLimit,
) -> String {
    let mut row = Map::new();
    row.insert("id".to_owned(), Value::String(entity.id.clone()));
    for (key, value) in &entity.fields {
        row.insert(
            key.clone(),
            clone_value_with_depth_limit(value, value_depth_limit),
        );
    }
    serde_json::to_string(&Value::Object(row))
        .expect("prepared entity token-accounting JSON should serialize")
}

pub(super) fn budget_groups_with_depth_limit(
    source: &[(GroupKey, Vec<PreparedEntity>)],
    allocation: &TokenAllocation,
    token_budget: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> (Vec<(GroupKey, Vec<PreparedEntity>)>, usize) {
    let mut groups = source.to_vec();
    let used = enforce_token_budget_with_depth_limit(
        &mut groups,
        allocation,
        token_budget,
        tokenizer,
        value_depth_limit,
    );
    (groups, used)
}

/// Tokens the estimated batch drops beyond the measured deficit, besides an
/// eighth of the deficit for the spread of the per-row estimates. It covers
/// the stats the batch itself changes: the `dropped` count and reason and
/// `critical_over_budget` take about a dozen tokens in JSON and fewer in the
/// text formats.
const TOKEN_BUDGET_BATCH_MARGIN: usize = 16;

/// One entry of the serialized-output budget's drop order: a row, by its group
/// and index in its section, or the L2 base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenBudgetDrop {
    Neighbor { group: usize, row: usize },
    Result { group: usize, row: usize },
    L2Base,
}

/// Holds a pack measured at `measured` tokens to a nonzero `token_budget`
/// (F21-RULINGS-ENGINE B5, H68): one estimated batch, then the minimal pack if
/// the batch does not fit. That is at most three exact measurements per
/// preparation, `measured` included, where the old loop re-encoded the whole
/// pack once per dropped row. Returns the exact count of the pack left in
/// `prepared`, or `None` once the L2 base is dropped: the caller then prepares
/// the pack again without it, so this preparation's count is not needed.
///
/// Nonzero serialized budgets take precedence over critical-row retention. If
/// the minimal pack (the fixed format envelope, stats and empty scaffolding)
/// still exceeds `token_budget`, the budget is unsatisfiable; callers get that
/// minimal payload and `total_tokens` records the actual emitted count. The
/// fallback can drop more rows than one-at-a-time trimming would have; the
/// ruling accepts that trade.
fn enforce_serialized_token_budget(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: &mut PreparedPack,
    token_budget: usize,
    measured: usize,
    tokenizer: PackTokenizer,
) -> Option<usize> {
    let (order, noncritical_len) = token_budget_drop_order(prepared, tokenizer);
    let minimal = minimal_token_budget_pack(prepared, order.len());
    // The minimal pack is small to encode, and with `measured` it gives what
    // the droppable entries cost together, which scales their estimates.
    let minimal_tokens = serialized_prepared_token_count(pack, config, &minimal, tokenizer);
    let batch_len = if minimal_tokens <= token_budget {
        token_budget_batch_len(&order, measured, minimal_tokens, token_budget)
    } else {
        None
    };
    if let Some(batch_len) = batch_len {
        let batch = &order[..batch_len];
        let drops_base = batch
            .iter()
            .any(|(entry, _)| *entry == TokenBudgetDrop::L2Base);
        drop_token_budget_batch(prepared, batch, batch_len > noncritical_len);
        if drops_base {
            return None;
        }
        let batch_tokens = serialized_prepared_token_count(pack, config, prepared, tokenizer);
        if batch_tokens <= token_budget {
            return Some(batch_tokens);
        }
    }
    let had_base = prepared.l2_base.is_some();
    *prepared = minimal;
    (!had_base).then_some(minimal_tokens)
}

/// The order the serialized-output budget drops in, each entry with its
/// estimated tokens: the non-critical neighbors (none in a merged pack), the
/// non-critical results and the L2 base, then the critical claims in the same
/// section order. Within a section the last group goes first, and within a
/// group the last row. The second value is the length of the non-critical
/// part.
fn token_budget_drop_order(
    prepared: &PreparedPack,
    tokenizer: PackTokenizer,
) -> (Vec<(TokenBudgetDrop, usize)>, usize) {
    let mut order = Vec::new();
    let mut noncritical_len = 0;
    for critical in [false, true] {
        if !prepared.merged {
            push_token_budget_drops(
                &prepared.neighbors,
                critical,
                |group, row| TokenBudgetDrop::Neighbor { group, row },
                tokenizer,
                &mut order,
            );
        }
        push_token_budget_drops(
            &prepared.results,
            critical,
            |group, row| TokenBudgetDrop::Result { group, row },
            tokenizer,
            &mut order,
        );
        if !critical {
            if let Some(summary) = &prepared.l2_base {
                order.push((
                    TokenBudgetDrop::L2Base,
                    l2_base_token_estimate(summary, tokenizer),
                ));
            }
            noncritical_len = order.len();
        }
    }
    (order, noncritical_len)
}

fn push_token_budget_drops(
    groups: &PreparedGroups,
    critical: bool,
    entry: fn(usize, usize) -> TokenBudgetDrop,
    tokenizer: PackTokenizer,
    order: &mut Vec<(TokenBudgetDrop, usize)>,
) {
    for (group, (_, rows)) in groups.iter().enumerate().rev() {
        for (row, entity) in rows.iter().enumerate().rev() {
            if is_critical_predicate_claim(entity) == critical {
                order.push((
                    entry(group, row),
                    estimate_entity_tokens_with_depth_limit(entity, tokenizer, None),
                ));
            }
        }
    }
}

/// The L2 base's tokens as the serialized prefix carries it.
fn l2_base_token_estimate(
    summary: &crate::store::l2_evidence::L2BaseSummary,
    tokenizer: PackTokenizer,
) -> usize {
    serde_json::to_string(summary).map_or(0, |prefix| tokenizer.count(&prefix))
}

/// How many leading entries of `order` the estimated batch drops: the fewest
/// whose estimates cover the deficit plus the margin. Each estimate is scaled
/// by what the droppable entries measure together, `measured` less the
/// minimal pack's `minimal_tokens`. `None` when the whole order does not cover
/// it.
fn token_budget_batch_len(
    order: &[(TokenBudgetDrop, usize)],
    measured: usize,
    minimal_tokens: usize,
    token_budget: usize,
) -> Option<usize> {
    let deficit = measured.saturating_sub(token_budget);
    let target = deficit
        .saturating_add(deficit / 8)
        .saturating_add(TOKEN_BUDGET_BATCH_MARGIN);
    let droppable_tokens = measured.saturating_sub(minimal_tokens) as u128;
    let estimated_tokens: u128 = order.iter().map(|(_, tokens)| *tokens as u128).sum();
    // Covered once sum(estimates) * droppable_tokens / estimated_tokens >= target.
    let needed = (target as u128).saturating_mul(estimated_tokens);
    let mut covered = 0_u128;
    for (index, (_, tokens)) in order.iter().enumerate() {
        covered = covered.saturating_add((*tokens as u128).saturating_mul(droppable_tokens));
        if covered >= needed {
            return Some(index + 1);
        }
    }
    None
}

/// Drops `batch` from `prepared` in one pass per group, and records it.
/// `critical_reached`: the batch reaches past the non-critical rows.
fn drop_token_budget_batch(
    prepared: &mut PreparedPack,
    batch: &[(TokenBudgetDrop, usize)],
    critical_reached: bool,
) {
    let mut neighbors = token_budget_drop_marks(&prepared.neighbors);
    let mut results = token_budget_drop_marks(&prepared.results);
    for (entry, _) in batch {
        match *entry {
            TokenBudgetDrop::Neighbor { group, row } => neighbors[group][row] = true,
            TokenBudgetDrop::Result { group, row } => results[group][row] = true,
            TokenBudgetDrop::L2Base => prepared.l2_base = None,
        }
    }
    retain_unmarked_rows(&mut prepared.neighbors, &neighbors);
    retain_unmarked_rows(&mut prepared.results, &results);
    record_token_budget_drops(&mut prepared.stats, batch.len(), critical_reached);
}

fn token_budget_drop_marks(groups: &PreparedGroups) -> Vec<Vec<bool>> {
    groups
        .iter()
        .map(|(_, rows)| vec![false; rows.len()])
        .collect()
}

fn retain_unmarked_rows(groups: &mut PreparedGroups, marks: &[Vec<bool>]) {
    for ((_, rows), marks) in groups.iter_mut().zip(marks) {
        let mut marks = marks.iter();
        rows.retain(|_| marks.next() == Some(&false));
    }
    groups.retain(|(_, rows)| !rows.is_empty());
}

/// The pack with every droppable row and the L2 base gone. `dropped` is the
/// number of entries that removes.
fn minimal_token_budget_pack(prepared: &PreparedPack, dropped: usize) -> PreparedPack {
    let mut minimal = PreparedPack {
        l2_base: None,
        merged: prepared.merged,
        results: Vec::new(),
        neighbors: Vec::new(),
        stats: prepared.stats.clone(),
    };
    record_token_budget_drops(&mut minimal.stats, dropped, true);
    minimal
}

/// Counts `dropped` entries against the token budget. Once the drops reach
/// past the non-critical rows, a pack that held critical rows is marked
/// `critical_over_budget`.
fn record_token_budget_drops(stats: &mut PackStats, dropped: usize, critical_reached: bool) {
    if dropped > 0 {
        stats.items_dropped.reason =
            crate::serialize::pack_accounting::PackItemAccountingReason::TokenBudget;
        stats.items_dropped.count = stats.items_dropped.count.saturating_add(dropped);
    }
    if critical_reached && stats.critical_count > 0 {
        stats.critical_over_budget = true;
    }
}

fn serialized_prepared_token_count(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: &PreparedPack,
    tokenizer: PackTokenizer,
) -> usize {
    let bytes = serialize_prepared_pack(pack, config, prepared.clone(), tokenizer);
    let text = std::str::from_utf8(&bytes).expect("context-pack serialization should be UTF-8");
    tokenizer.count(text)
}

pub(super) fn finalize_pack_token_stats(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: &mut PreparedPack,
    tokenizer: PackTokenizer,
    token_budget: Option<usize>,
) {
    // The token stats are not in the serialized bytes (`json_stats` and
    // `append_stats_line` print neither), so one exact count of the final pack
    // stamps them.
    let mut total_tokens = serialized_prepared_token_count(pack, config, prepared, tokenizer);
    if let Some(budget) = token_budget
        && total_tokens > budget
    {
        match enforce_serialized_token_budget(
            pack,
            config,
            prepared,
            budget,
            total_tokens,
            tokenizer,
        ) {
            Some(emitted) => total_tokens = emitted,
            // The L2 base is gone: `prepare_pack_with_l2` prepares again
            // without it.
            None => return,
        }
    }
    prepared.stats.tokens = collect_pack_token_stats(prepared, total_tokens, tokenizer);
}

fn collect_pack_token_stats(
    prepared: &PreparedPack,
    total_tokens: usize,
    tokenizer: PackTokenizer,
) -> PackTokenStats {
    let mut sections = Vec::new();
    if let Some(summary) = &prepared.l2_base {
        sections.push(PackSectionTokenStats {
            section: "l2_base".to_owned(),
            tokens: tokenizer.count(&summary.body),
        });
    }
    let mut items = Vec::new();
    if prepared.merged {
        collect_section_token_stats(
            "merged",
            &prepared.results,
            tokenizer,
            &mut sections,
            &mut items,
        );
    } else {
        collect_section_token_stats(
            "results",
            &prepared.results,
            tokenizer,
            &mut sections,
            &mut items,
        );
        collect_section_token_stats(
            "neighbors",
            &prepared.neighbors,
            tokenizer,
            &mut sections,
            &mut items,
        );
    }

    PackTokenStats {
        tokenizer_id: tokenizer.id().to_owned(),
        total_tokens,
        sections,
        items,
    }
}

fn collect_section_token_stats(
    section: &str,
    groups: &[(GroupKey, Vec<PreparedEntity>)],
    tokenizer: PackTokenizer,
    sections: &mut Vec<PackSectionTokenStats>,
    items: &mut Vec<PackItemTokenStats>,
) {
    let mut section_tokens = 0_usize;
    for (_, rows) in groups {
        for row in rows {
            let tokens = estimate_entity_tokens_with_depth_limit(row, tokenizer, None);
            section_tokens = section_tokens.saturating_add(tokens);
            items.push(PackItemTokenStats {
                section: section.to_owned(),
                id: row.id.clone(),
                // The row's OWN byte, not the bucket. Grouping no longer
                // overwrites it with a sentinel, so unlabelled kinds report
                // their real type here instead of 255.
                entity_type: row.entity_type,
                tokens,
            });
        }
    }

    if section_tokens > 0 || !groups.is_empty() {
        sections.push(PackSectionTokenStats {
            section: section.to_owned(),
            tokens: section_tokens,
        });
    }
}

pub(super) fn append_stats_line(out: &mut String, stats: &PackStats, format: PackFormat) {
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }

    let ms = stats.query_time_us as f64 / 1000.0;
    let signals = stats
        .signals_used
        .iter()
        .map(|signal| signal_name(*signal))
        .collect::<Vec<_>>()
        .join(",");

    let mut stats_line = format!(
        "query: {ms:.1}ms | {} candidates | signals: {} | cosine ghosts dampened: {}",
        stats.candidates_considered, signals, stats.cosine_ghosts_dampened
    );
    if stats.items_truncated.count > 0 {
        stats_line.push_str(&format!(
            " | truncated: {} {}",
            stats.items_truncated.count,
            stats.items_truncated.reason.as_str()
        ));
    }
    if stats.items_dropped.count > 0 {
        stats_line.push_str(&format!(
            " | dropped: {} {}",
            stats.items_dropped.count,
            stats.items_dropped.reason.as_str()
        ));
    }
    if stats.deadline_exceeded {
        stats_line.push_str(" | deadline_exceeded: true");
    }
    if stats.critical_over_budget {
        stats_line.push_str(&format!(
            " | critical_over_budget: {}",
            stats.critical_count
        ));
    }
    if format == PackFormat::Yaml {
        out.push_str("# ");
        out.push_str(&stats_line);
        out.push('\n');
    } else {
        out.push_str("---\n");
        out.push_str(&stats_line);
    }
}

pub(super) fn json_stats(pack_stats: &PackStats) -> Value {
    let mut stats = Map::new();
    stats.insert(
        "candidates".to_owned(),
        Value::Number(Number::from(pack_stats.candidates_considered as u64)),
    );
    stats.insert(
        "signals".to_owned(),
        Value::Array(
            pack_stats
                .signals_used
                .iter()
                .map(|signal| Value::String(signal_name(*signal).to_owned()))
                .collect(),
        ),
    );
    stats.insert(
        "query_us".to_owned(),
        Value::Number(Number::from(pack_stats.query_time_us)),
    );
    stats.insert(
        "hydrated".to_owned(),
        Value::Number(Number::from(pack_stats.entities_hydrated as u64)),
    );
    stats.insert(
        "neighbors_hydrated".to_owned(),
        Value::Number(Number::from(pack_stats.neighbors_hydrated as u64)),
    );
    stats.insert(
        "cosine_ghosts_dampened".to_owned(),
        Value::Number(Number::from(pack_stats.cosine_ghosts_dampened as u64)),
    );
    if pack_stats.items_truncated.count > 0 {
        stats.insert(
            "truncated".to_owned(),
            item_accounting_json(pack_stats.items_truncated),
        );
    }
    if pack_stats.items_dropped.count > 0 {
        stats.insert(
            "dropped".to_owned(),
            item_accounting_json(pack_stats.items_dropped),
        );
    }
    stats.insert(
        "deadline_exceeded".to_owned(),
        Value::Bool(pack_stats.deadline_exceeded),
    );
    stats.insert(
        "critical_over_budget".to_owned(),
        Value::Bool(pack_stats.critical_over_budget),
    );
    stats.insert(
        "critical_count".to_owned(),
        Value::from(pack_stats.critical_count),
    );
    Value::Object(stats)
}
