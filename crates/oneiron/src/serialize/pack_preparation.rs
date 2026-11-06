//! Core half of `serialize::pack_preparation`: its store-layer items live in `oneiron_store::serialize::pack_preparation` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::serialize::pack_preparation::*;

use super::field_profile_table::fields_for_profile;
use super::item_budget::apply_item_budget_with_depth_limit;
use super::pack_entry::{
    PreparedEntity, PreparedEntitySource, PreparedGroups, PreparedPack, SerializeConfig,
};
use super::token_budget::{
    allocate_section_budgets, budget_groups_with_depth_limit,
    enforce_token_budget_with_depth_limit, estimate_groups_tokens_with_depth_limit,
    finalize_pack_token_stats, group_entities, token_budget_droppable_count,
};
use super::types::{TOON_MAX_DEPTH, ValueDepthLimit};
use crate::context_pack::ContextPack;
use crate::context_pack::PackStats;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::serialize::context_entity::ContextEntity;
use crate::serialize::pack_accounting::TokenAllocation;
use crate::serialize::pack_format::FieldProfile;
use crate::serialize::pack_format::PackFormat;
use crate::tokenizer::PackTokenizer;
use serde_json::Value;
use std::collections::HashMap;

pub(super) fn prepare_pack(
    pack: &ContextPack,
    config: &SerializeConfig,
    json_mode: bool,
    tokenizer: PackTokenizer,
) -> PreparedPack {
    prepare_pack_with_l2(pack, config, json_mode, true, false, tokenizer)
}

fn prepare_pack_with_l2(
    pack: &ContextPack,
    config: &SerializeConfig,
    json_mode: bool,
    include_l2: bool,
    omitted_by_token_budget: bool,
    tokenizer: PackTokenizer,
) -> PreparedPack {
    let l2_base = pack.l2_base.clone().filter(|summary| {
        include_l2
            && (config.max_item_tokens == 0
                || tokenizer.count(&summary.body) <= config.max_item_tokens)
            && summary.fits_field_budget(config.max_field_chars)
    });
    let skip_budget = config.budget == 0;
    let value_depth_limit = value_depth_limit_for_format(config.format);
    let mut stats = pack.stats.clone();
    if pack.l2_base.is_some() && l2_base.is_none() {
        stats.items_dropped.reason = if omitted_by_token_budget {
            crate::serialize::pack_accounting::PackItemAccountingReason::TokenBudget
        } else {
            crate::serialize::pack_accounting::PackItemAccountingReason::ItemBudget
        };
        stats.items_dropped.count = stats.items_dropped.count.saturating_add(1);
    }
    // Counts the critical rows preparation sees, to judge its own cuts; the
    // pack's pre-cut count and overflow warning are restored after (FIX 9760).
    stats.critical_count = 0;

    let skip_evidence = l2_base
        .as_ref()
        .map(crate::store::l2_evidence::L2BaseSummary::evidence_ids);
    let had_l2 = l2_base.is_some();
    let mut prepared = if config.merge_neighbors {
        let mut merged = Vec::with_capacity(pack.results.len() + pack.neighbors.len());
        merged.extend(prepare_entities(
            &pack.results,
            PreparedEntitySource::Result,
            skip_evidence,
            config,
            json_mode,
            tokenizer,
            value_depth_limit,
            &mut stats,
        ));
        merged.extend(prepare_entities(
            &pack.neighbors,
            PreparedEntitySource::Neighbor,
            skip_evidence,
            config,
            json_mode,
            tokenizer,
            value_depth_limit,
            &mut stats,
        ));

        let mut groups = group_entities(merged);
        if !skip_budget {
            let before = token_budget_droppable_count(&groups);
            enforce_token_budget_with_depth_limit(
                &mut groups,
                &config.allocation,
                config.budget,
                tokenizer,
                value_depth_limit,
            );
            let after = token_budget_droppable_count(&groups);
            stats.items_dropped.count = stats
                .items_dropped
                .count
                .saturating_add(before.saturating_sub(after));
        }

        PreparedPack {
            l2_base,
            merged: true,
            results: groups,
            neighbors: Vec::new(),
            stats,
        }
    } else {
        let results_source = group_entities(prepare_entities(
            &pack.results,
            PreparedEntitySource::Result,
            skip_evidence,
            config,
            json_mode,
            tokenizer,
            value_depth_limit,
            &mut stats,
        ));
        let neighbors_source = group_entities(prepare_entities(
            &pack.neighbors,
            PreparedEntitySource::Neighbor,
            skip_evidence,
            config,
            json_mode,
            tokenizer,
            value_depth_limit,
            &mut stats,
        ));
        let (results, neighbors) = if skip_budget {
            (results_source, neighbors_source)
        } else {
            let before = token_budget_droppable_count(&results_source)
                .saturating_add(token_budget_droppable_count(&neighbors_source));
            let sections = budget_split_sections_with_depth_limit(
                &results_source,
                &neighbors_source,
                &config.allocation,
                config.budget,
                tokenizer,
                value_depth_limit,
            );
            let after = token_budget_droppable_count(&sections.0)
                .saturating_add(token_budget_droppable_count(&sections.1));
            stats.items_dropped.count = stats
                .items_dropped
                .count
                .saturating_add(before.saturating_sub(after));
            sections
        };

        PreparedPack {
            l2_base,
            merged: false,
            results,
            neighbors,
            stats,
        }
    };

    let kept_critical = prepared
        .results
        .iter()
        .chain(&prepared.neighbors)
        .flat_map(|(_, rows)| rows)
        .filter(|row| row.critical)
        .count();
    if kept_critical < prepared.stats.critical_count {
        prepared.stats.critical_over_budget = true;
    }
    prepared.stats.critical_count = prepared.stats.critical_count.max(pack.stats.critical_count);
    finalize_pack_token_stats(
        pack,
        config,
        &mut prepared,
        tokenizer,
        (!skip_budget).then_some(config.budget),
    );
    // A serialized-token budget can shed the base after initial selection.
    // Rebudget the original ranked rows if the prefix did not survive; typed
    // consumers keep those rows independently of serialized deduplication.
    if had_l2 && prepared.l2_base.is_none() {
        return prepare_pack_with_l2(pack, config, json_mode, false, true, tokenizer);
    }
    prepared
}

fn budget_split_sections_with_depth_limit(
    results_source: &PreparedGroups,
    neighbors_source: &PreparedGroups,
    allocation: &TokenAllocation,
    token_budget: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> (PreparedGroups, PreparedGroups) {
    let results_need =
        estimate_groups_tokens_with_depth_limit(results_source, tokenizer, value_depth_limit);
    let neighbors_need =
        estimate_groups_tokens_with_depth_limit(neighbors_source, tokenizer, value_depth_limit);

    let section_budgets = allocate_section_budgets([results_need, neighbors_need], token_budget);
    let (mut results, results_used) = budget_groups_with_depth_limit(
        results_source,
        allocation,
        section_budgets[0],
        tokenizer,
        value_depth_limit,
    );
    let (mut neighbors, neighbors_used) = budget_groups_with_depth_limit(
        neighbors_source,
        allocation,
        section_budgets[1],
        tokenizer,
        value_depth_limit,
    );

    let leftover = token_budget.saturating_sub(results_used.saturating_add(neighbors_used));
    if leftover == 0 {
        return (results, neighbors);
    }

    let unmet = [
        results_need.saturating_sub(results_used),
        neighbors_need.saturating_sub(neighbors_used),
    ];
    if !unmet.iter().any(|need| *need > 0) {
        return (results, neighbors);
    }

    let extra = allocate_section_budgets(unmet, leftover);
    let final_budgets = [
        results_used.saturating_add(extra[0]),
        neighbors_used.saturating_add(extra[1]),
    ];
    debug_assert!(final_budgets[0].saturating_add(final_budgets[1]) <= token_budget);

    if final_budgets[0] > section_budgets[0] {
        results = budget_groups_with_depth_limit(
            results_source,
            allocation,
            final_budgets[0],
            tokenizer,
            value_depth_limit,
        )
        .0;
    }
    if final_budgets[1] > section_budgets[1] {
        neighbors = budget_groups_with_depth_limit(
            neighbors_source,
            allocation,
            final_budgets[1],
            tokenizer,
            value_depth_limit,
        )
        .0;
    }

    (results, neighbors)
}

fn prepare_entities(
    entities: &[ContextEntity],
    source: PreparedEntitySource,
    skip_evidence: Option<&[EntityId]>,
    config: &SerializeConfig,
    json_mode: bool,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
    stats: &mut PackStats,
) -> Vec<PreparedEntity> {
    let now = crate::unix_seconds_now();
    entities
        .iter()
        .filter(|entity| skip_evidence.is_none_or(|ids| ids.binary_search(&entity.id).is_err()))
        .filter_map(|entity| {
            let mut fields = Vec::new();

            if let Some(map) = entity.fields.as_ref() {
                let field_keys = field_keys(entity.entity_type, config.profile, map);
                for key in field_keys {
                    if crate::batch::secret_scan::scan_file_content("", key.as_bytes()).is_some() {
                        continue;
                    }
                    let Some(value) = map.get(&key) else {
                        continue;
                    };
                    if !should_include_projected_field(entity.entity_type, &key, value) {
                        continue;
                    }
                    let safe_value =
                        super::credential_nulling::null_context_credentials(&key, value);
                    let value = normalize_value(
                        &key,
                        &safe_value,
                        json_mode,
                        now,
                        config.max_field_chars,
                        value_depth_limit,
                    );
                    fields.push((key, value));
                }
            }

            let mut prepared = PreparedEntity {
                entity_type: entity.entity_type,
                score: entity.score,
                critical: entity.critical,
                source,
                source_id: *entity.id.as_bytes(),
                id: format_short_id(entity),
                fields,
            };
            if prepared.critical {
                stats.critical_count += 1;
                if config.max_item_tokens != 0
                    && super::token_budget::estimate_entity_tokens_with_depth_limit(
                        &prepared,
                        tokenizer,
                        value_depth_limit,
                    ) > config.max_item_tokens
                {
                    stats.critical_over_budget = true;
                }
            }
            let kept = apply_item_budget_with_depth_limit(
                &mut prepared,
                config.max_item_tokens,
                stats,
                tokenizer,
                value_depth_limit,
            );
            // Read whole once its fields are final: fields that read as a
            // secret together leave none of them, keys included. They were
            // read in their stored encoding where they were hydrated, so this
            // read takes their text.
            if kept
                && crate::batch::secret_scan::release_reads_json_text(&Value::Object(
                    prepared.fields.iter().cloned().collect(),
                ))
            {
                prepared.fields.clear();
            }
            kept.then_some(prepared)
        })
        .collect()
}
