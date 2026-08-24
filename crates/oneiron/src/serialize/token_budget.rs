//! Grouping, section/type token-budget enforcement, size estimation, and
//! pack token-stats collection.
//!
//! Note the deliberate cycle with [`super::pack_entry`]: enforcing the serialized
//! budget and stamping token stats both re-encode the prepared pack through
//! [`super::pack_entry::serialize_prepared_pack`] to measure real output size.
//! Measuring after encoding is the contract, not a layering slip.

use std::collections::HashMap;

use serde_json::{Map, Number, Value};

use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::context_pack::ContextPack;
use crate::context_pack::PackFormat;
use crate::context_pack::PackItemTokenStats;
use crate::context_pack::PackSectionTokenStats;
use crate::context_pack::PackStats;
use crate::context_pack::PackTokenStats;
use crate::context_pack::TokenAllocation;
use crate::pipeline::Signal;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
#[cfg(test)]
use crate::tokenizer::DEFAULT_CONTEXT_PACK_TOKENIZER;
use crate::tokenizer::PackTokenizer;

use super::group_labels::known_group_labels;
use super::item_budget::is_critical_predicate_claim;
use super::pack_entry::{PreparedEntity, PreparedPack, SerializeConfig, serialize_prepared_pack};
use super::pack_preparation::{clone_value_with_depth_limit, value_depth_limit_reached};
use super::types::{GROUP_ORDER, GroupKey, ValueDepthLimit};

pub(super) fn group_entities(
    entities: Vec<PreparedEntity>,
) -> Vec<(GroupKey, Vec<PreparedEntity>)> {
    let mut buckets = HashMap::<GroupKey, Vec<PreparedEntity>>::new();
    for entity in entities {
        buckets
            .entry(group_key_of(entity.entity_type))
            .or_default()
            .push(entity);
    }

    for rows in buckets.values_mut() {
        rows.sort_unstable_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
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
    groups
        .iter()
        .flat_map(|(_, rows)| rows.iter())
        .filter(|row| !is_critical_predicate_claim(row))
        .count()
}

pub(super) fn type_fraction(key: GroupKey, allocation: &TokenAllocation) -> f32 {
    match key {
        GroupKey::Kind(ENTITY_TYPE_CLAIM | ENTITY_TYPE_COMPANION_REGISTER) => allocation.claims,
        GroupKey::Kind(ENTITY_TYPE_TURN) => allocation.turns,
        GroupKey::Kind(ENTITY_TYPE_SUMMARY) => allocation.summaries,
        GroupKey::Kind(_) | GroupKey::Other => allocation.other,
    }
}

pub(super) fn enforce_token_budget_with_depth_limit(
    groups: &mut Vec<(GroupKey, Vec<PreparedEntity>)>,
    allocation: &TokenAllocation,
    token_budget: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    if token_budget == 0 {
        let mut total_used = 0_usize;
        for (_, rows) in groups.iter_mut() {
            let mut used = 0_usize;
            rows.retain(|row| {
                let keep = is_critical_predicate_claim(row);
                if keep {
                    used = used.saturating_add(estimate_entity_tokens_with_depth_limit(
                        row,
                        tokenizer,
                        value_depth_limit,
                    ));
                }
                keep
            });
            total_used = total_used.saturating_add(used);
        }
        groups.retain(|(_, rows)| !rows.is_empty());
        return total_used;
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
    let mut needs: Vec<usize> = Vec::with_capacity(groups.len());
    let mut surplus: usize = 0;
    let mut hungry_weight: f32 = 0.0;

    for (i, (_, rows)) in groups.iter().enumerate() {
        let frac = raw[i] * norm;
        let budget = (token_budget as f32 * frac) as usize;
        let needed: usize = rows
            .iter()
            .map(|row| estimate_entity_tokens_with_depth_limit(row, tokenizer, value_depth_limit))
            .sum();
        if needed <= budget {
            surplus += budget - needed;
        } else {
            hungry_weight += frac;
        }
        budgets.push(budget);
        needs.push(needed);
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
        let mut kept_noncritical = 0_usize;
        let mut noncritical_closed = final_budget == 0;
        for row in rows.drain(..) {
            let tokens =
                estimate_entity_tokens_with_depth_limit(&row, tokenizer, value_depth_limit);
            if is_critical_predicate_claim(&row) {
                used = used.saturating_add(tokens);
                kept.push(row);
                continue;
            }
            if noncritical_closed {
                continue;
            }
            if used.saturating_add(tokens) > final_budget && kept_noncritical > 0 {
                noncritical_closed = true;
                continue;
            }
            kept_noncritical += 1;
            used = used.saturating_add(tokens);
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

#[cfg(test)]
pub(super) fn estimate_entity_chars(entity: &PreparedEntity) -> usize {
    estimate_entity_chars_with_depth_limit(entity, None)
}

// Character estimates below are retained for non-budget tests and truncation
// suffix display only. All pack budget decisions use the tokenizer helpers
// above.
#[cfg(test)]
fn estimate_entity_chars_with_depth_limit(
    entity: &PreparedEntity,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    let mut chars = entity.id.len() + 12;
    for (key, value) in &entity.fields {
        chars += estimate_json_string_chars(key);
        chars += estimate_value_chars_with_depth_limit(value, value_depth_limit);
        chars += 2;
    }
    chars
}

#[cfg(test)]
pub(super) fn budget_groups(
    source: &[(GroupKey, Vec<PreparedEntity>)],
    allocation: &TokenAllocation,
    token_budget: usize,
) -> (Vec<(GroupKey, Vec<PreparedEntity>)>, usize) {
    budget_groups_with_depth_limit(
        source,
        allocation,
        token_budget,
        DEFAULT_CONTEXT_PACK_TOKENIZER,
        None,
    )
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

fn enforce_serialized_token_budget(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: &mut PreparedPack,
    token_budget: usize,
    tokenizer: PackTokenizer,
) {
    // Nonzero serialized budgets take precedence over critical-row retention.
    // If every row has been removed and the fixed format envelope/stats/empty
    // scaffolding alone still exceeds `token_budget`, the budget is
    // unsatisfiable; callers get that minimal payload and `total_tokens`
    // records the actual emitted count.
    let mut may_drop_critical = false;
    while serialized_prepared_token_count(pack, config, prepared, tokenizer) > token_budget {
        if !drop_last_token_budget_item(prepared, may_drop_critical) {
            if may_drop_critical {
                break;
            }
            may_drop_critical = true;
            continue;
        }
        prepared.stats.items_dropped.reason =
            crate::context_pack::PackItemAccountingReason::TokenBudget;
        prepared.stats.items_dropped.count = prepared.stats.items_dropped.count.saturating_add(1);
    }
}

fn drop_last_token_budget_item(prepared: &mut PreparedPack, include_critical: bool) -> bool {
    if !prepared.merged
        && drop_last_token_budget_item_from_groups(&mut prepared.neighbors, include_critical)
    {
        return true;
    }

    drop_last_token_budget_item_from_groups(&mut prepared.results, include_critical)
}

fn drop_last_token_budget_item_from_groups(
    groups: &mut Vec<(GroupKey, Vec<PreparedEntity>)>,
    include_critical: bool,
) -> bool {
    for group_index in (0..groups.len()).rev() {
        let rows = &mut groups[group_index].1;
        let Some(row_index) = rows
            .iter()
            .rposition(|row| include_critical || !is_critical_predicate_claim(row))
        else {
            continue;
        };

        rows.remove(row_index);
        if rows.is_empty() {
            groups.remove(group_index);
        }
        return true;
    }
    false
}

fn serialized_prepared_token_count(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: &PreparedPack,
    tokenizer: PackTokenizer,
) -> usize {
    let bytes = serialize_prepared_pack(pack, config, prepared.clone());
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
    for _ in 0..16 {
        let changed = stamp_pack_token_stats(pack, config, prepared, tokenizer);
        if let Some(budget) = token_budget {
            enforce_serialized_token_budget(pack, config, prepared, budget, tokenizer);
        }

        let total_tokens = serialized_prepared_token_count(pack, config, prepared, tokenizer);
        let next = collect_pack_token_stats(prepared, total_tokens, tokenizer);
        let within_budget = token_budget.is_none_or(|budget| total_tokens <= budget);
        if prepared.stats.tokens == next && within_budget && !changed {
            return;
        }
        prepared.stats.tokens = next;
    }

    if let Some(budget) = token_budget {
        enforce_serialized_token_budget(pack, config, prepared, budget, tokenizer);
    }
    let _ = stamp_pack_token_stats(pack, config, prepared, tokenizer);
}

fn stamp_pack_token_stats(
    pack: &ContextPack,
    config: &SerializeConfig,
    prepared: &mut PreparedPack,
    tokenizer: PackTokenizer,
) -> bool {
    let total_tokens = serialized_prepared_token_count(pack, config, prepared, tokenizer);
    let tokens = collect_pack_token_stats(prepared, total_tokens, tokenizer);
    let changed = prepared.stats.tokens != tokens;
    prepared.stats.tokens = tokens;
    changed
}

fn collect_pack_token_stats(
    prepared: &PreparedPack,
    total_tokens: usize,
    tokenizer: PackTokenizer,
) -> PackTokenStats {
    let mut sections = Vec::new();
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

pub(super) fn allocate_section_budgets(needs: [usize; 2], total_budget: usize) -> [usize; 2] {
    if total_budget == 0 {
        return [0, 0];
    }

    let total_need = needs[0].saturating_add(needs[1]);
    if total_need <= total_budget {
        return needs;
    }
    debug_assert!(total_need > 0);

    let total_budget = total_budget as u128;
    let total_need = total_need as u128;
    let mut budgets = [0_usize, 0_usize];
    let mut remainders = [(0_usize, 0_u128), (1_usize, 0_u128)];
    let mut allocated = 0_usize;

    for (index, need) in needs.into_iter().enumerate() {
        let product = total_budget.saturating_mul(need as u128);
        budgets[index] = (product / total_need) as usize;
        remainders[index] = (index, product % total_need);
        allocated = allocated.saturating_add(budgets[index]);
    }

    let mut leftover = (total_budget as usize).saturating_sub(allocated);
    remainders.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (index, _) in remainders {
        if leftover == 0 {
            break;
        }
        budgets[index] = budgets[index].saturating_add(1);
        leftover -= 1;
    }

    budgets
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
    Value::Object(stats)
}

fn item_accounting_json(accounting: crate::context_pack::PackItemAccounting) -> Value {
    let mut out = Map::new();
    out.insert(
        "count".to_owned(),
        Value::Number(Number::from(accounting.count as u64)),
    );
    out.insert(
        "reason".to_owned(),
        Value::String(accounting.reason.as_str().to_owned()),
    );
    Value::Object(out)
}

fn signal_name(signal: Signal) -> &'static str {
    match signal {
        Signal::Vector => "vector",
        Signal::Text => "text",
        Signal::Phonetic => "phonetic",
        Signal::Temporal => "temporal",
        Signal::Ppr => "ppr",
        Signal::Hyde => "hyde",
    }
}

#[cfg(test)]
pub(super) fn estimate_value_chars(value: &Value) -> usize {
    estimate_value_chars_with_depth_limit(value, None)
}

pub(super) fn estimate_value_chars_with_depth_limit(
    value: &Value,
    value_depth_limit: ValueDepthLimit,
) -> usize {
    estimate_value_chars_at_depth(value, value_depth_limit, 0)
}

fn estimate_value_chars_at_depth(
    value: &Value,
    value_depth_limit: ValueDepthLimit,
    depth: usize,
) -> usize {
    if value_depth_limit_reached(value_depth_limit, depth) {
        return 4;
    }

    match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(number) => number.to_string().len(),
        Value::String(text) => estimate_json_string_chars(text),
        Value::Array(values) => {
            if values.is_empty() {
                2
            } else {
                2 + values
                    .iter()
                    .map(|value| estimate_value_chars_at_depth(value, value_depth_limit, depth + 1))
                    .sum::<usize>()
                    + (values.len() - 1)
            }
        }
        Value::Object(map) => {
            if map.is_empty() {
                2
            } else {
                let pairs_len: usize = map
                    .iter()
                    .map(|(key, value)| {
                        estimate_json_string_chars(key)
                            + 1
                            + estimate_value_chars_at_depth(value, value_depth_limit, depth + 1)
                    })
                    .sum();
                2 + pairs_len + (map.len() - 1)
            }
        }
    }
}

pub(super) fn estimate_json_string_chars(text: &str) -> usize {
    let mut len = 2;
    for ch in text.chars() {
        len += match ch {
            '"' | '\\' | '\n' | '\r' | '\t' => 2,
            '\u{08}' | '\u{0C}' => 2,
            c if (c as u32) <= 0x1F => 6,
            c => c.len_utf8(),
        };
    }
    len
}

fn group_key_of(entity_type: u8) -> GroupKey {
    if known_group_labels(entity_type).is_some() {
        GroupKey::Kind(entity_type)
    } else {
        GroupKey::Other
    }
}
