//! Per-item token-budget enforcement and value truncation.

use serde_json::Value;

use crate::context_pack::PackStats;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::tokenizer::{DEFAULT_CONTEXT_PACK_TOKENIZER, PackTokenizer};

use super::pack_entry::PreparedEntity;
use super::token_budget::{
    estimate_entity_tokens_with_depth_limit, estimate_value_chars_with_depth_limit,
};
use super::types::ValueDepthLimit;

#[cfg(test)]
pub(super) fn apply_item_budget(
    entity: &mut PreparedEntity,
    max_item_tokens: usize,
    stats: &mut PackStats,
) -> bool {
    apply_item_budget_with_depth_limit(entity, max_item_tokens, stats, None)
}

pub(super) fn apply_item_budget_with_depth_limit(
    entity: &mut PreparedEntity,
    max_item_tokens: usize,
    stats: &mut PackStats,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    if max_item_tokens == 0 || is_critical_predicate_claim(entity) {
        return true;
    }

    let tokenizer = DEFAULT_CONTEXT_PACK_TOKENIZER;
    if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        <= max_item_tokens
    {
        return true;
    }

    let truncated = if entity.entity_type == ENTITY_TYPE_CLAIM {
        truncate_claim_value_for_item_budget(entity, max_item_tokens, tokenizer, value_depth_limit)
    } else {
        truncate_non_claim_for_item_budget(entity, max_item_tokens, tokenizer, value_depth_limit)
    };

    if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        <= max_item_tokens
    {
        if truncated {
            stats.items_truncated.count = stats.items_truncated.count.saturating_add(1);
        }
        true
    } else {
        stats.items_dropped.reason = crate::context_pack::PackItemAccountingReason::ItemBudget;
        stats.items_dropped.count = stats.items_dropped.count.saturating_add(1);
        false
    }
}

fn truncate_non_claim_for_item_budget(
    entity: &mut PreparedEntity,
    max_item_tokens: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    let mut truncated = false;
    let mut tried_fields = Vec::new();

    while estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        > max_item_tokens
    {
        let Some(field_index) =
            largest_truncatable_top_level_string_field(entity, tried_fields.as_slice())
        else {
            break;
        };

        tried_fields.push(field_index);
        truncated |= truncate_string_field_to_item_budget(
            entity,
            field_index,
            max_item_tokens,
            tokenizer,
            value_depth_limit,
        );
    }

    if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        <= max_item_tokens
    {
        return truncated;
    }

    truncated | retain_structural_item_budget_fields(entity)
}

fn truncate_claim_value_for_item_budget(
    entity: &mut PreparedEntity,
    max_item_tokens: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    let Some(value_index) = field_index(entity, "val") else {
        return retain_minimal_claim_item_budget_fields(entity, None);
    };

    let original_value = entity.fields[value_index].1.clone();
    let mut truncated = truncate_claim_value_field_for_item_budget(
        entity,
        value_index,
        max_item_tokens,
        tokenizer,
        value_depth_limit,
    );

    if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        <= max_item_tokens
    {
        return truncated;
    }

    truncated |= retain_minimal_claim_item_budget_fields(entity, Some(original_value));
    if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
        <= max_item_tokens
    {
        return truncated;
    }

    let Some(value_index) = field_index(entity, "val") else {
        return truncated;
    };
    truncated
        | truncate_claim_value_field_for_item_budget(
            entity,
            value_index,
            max_item_tokens,
            tokenizer,
            value_depth_limit,
        )
}

fn truncate_claim_value_field_for_item_budget(
    entity: &mut PreparedEntity,
    field_index: usize,
    max_item_tokens: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    let original_value_chars =
        estimate_value_chars_with_depth_limit(&entity.fields[field_index].1, value_depth_limit);

    match &mut entity.fields[field_index].1 {
        Value::String(_) => truncate_string_field_to_item_budget(
            entity,
            field_index,
            max_item_tokens,
            tokenizer,
            value_depth_limit,
        ),
        value => {
            *value = Value::String(truncation_suffix(original_value_chars));
            true
        }
    }
}

fn truncate_string_field_to_item_budget(
    entity: &mut PreparedEntity,
    field_index: usize,
    max_item_tokens: usize,
    tokenizer: PackTokenizer,
    value_depth_limit: ValueDepthLimit,
) -> bool {
    let Value::String(original) = entity.fields[field_index].1.clone() else {
        return false;
    };

    let original_chars = original.chars().count();
    if original_chars == 0 {
        return false;
    }

    let suffix = truncation_suffix(original_chars);
    let mut low = 0_usize;
    let mut high = original_chars.saturating_sub(1);
    let mut best_prefix = None;

    // Character positions are only candidate cut points for preserving UTF-8
    // and human-readable suffixes. Every accepted candidate is checked with
    // the real context-pack tokenizer.
    while low <= high {
        let mid = low + ((high - low) / 2);
        entity.fields[field_index].1 =
            Value::String(truncate_with_suffix_prefix(&original, mid, &suffix));

        if estimate_entity_tokens_with_depth_limit(entity, tokenizer, value_depth_limit)
            <= max_item_tokens
        {
            best_prefix = Some(mid);
            low = mid.saturating_add(1);
        } else if mid == 0 {
            break;
        } else {
            high = mid - 1;
        }
    }

    let prefix_chars = best_prefix.unwrap_or(0);
    entity.fields[field_index].1 = Value::String(truncate_with_suffix_prefix(
        &original,
        prefix_chars,
        &suffix,
    ));
    true
}

fn retain_minimal_claim_item_budget_fields(
    entity: &mut PreparedEntity,
    original_value: Option<Value>,
) -> bool {
    let predicate = entity.fields.iter().find(|(key, _)| key == "pred").cloned();
    let value = original_value.map(|value| ("val".to_owned(), value));

    let mut minimal = Vec::new();
    if let Some(predicate) = predicate {
        minimal.push(predicate);
    }
    if let Some(value) = value {
        minimal.push(value);
    }

    let changed = entity.fields != minimal;
    entity.fields = minimal;
    changed
}

fn retain_structural_item_budget_fields(entity: &mut PreparedEntity) -> bool {
    let structural: Vec<(String, Value)> = entity
        .fields
        .iter()
        .filter(|(key, _)| is_structural_item_budget_field(key))
        .cloned()
        .collect();
    let changed = entity.fields != structural;
    entity.fields = structural;
    changed
}

fn is_structural_item_budget_field(key: &str) -> bool {
    key == "pred"
}

fn field_index(entity: &PreparedEntity, key: &str) -> Option<usize> {
    entity
        .fields
        .iter()
        .position(|(field_key, _)| field_key == key)
}

fn largest_truncatable_top_level_string_field(
    entity: &PreparedEntity,
    excluded: &[usize],
) -> Option<usize> {
    entity
        .fields
        .iter()
        .enumerate()
        .filter_map(|(index, (key, value))| {
            if excluded.contains(&index) || is_structural_item_budget_field(key) {
                return None;
            }

            let Value::String(text) = value else {
                return None;
            };
            Some((index, text.chars().count()))
        })
        .max_by_key(|(_, chars)| *chars)
        .map(|(index, _)| index)
}

fn truncate_with_suffix_prefix(text: &str, prefix_chars: usize, suffix: &str) -> String {
    let prefix: String = text.chars().take(prefix_chars).collect();
    format!("{prefix}{suffix}")
}

fn truncation_suffix(original_chars: usize) -> String {
    format!("...(truncated, {original_chars} chars total)")
}

pub(super) fn is_critical_predicate_claim(entity: &PreparedEntity) -> bool {
    entity.entity_type == ENTITY_TYPE_CLAIM
        && entity
            .fields
            .iter()
            .find_map(|(key, value)| (key == "pred").then_some(value.as_str()).flatten())
            .is_some_and(is_critical_claim_predicate)
}

/// Whether a CLAIM predicate is retained as critical serializer context.
pub(crate) fn is_critical_claim_predicate(predicate: &str) -> bool {
    predicate == crate::commitment::PREDICATE_COMMITMENT_RECORD
        || predicate.starts_with("profile.")
        || predicate.starts_with("preference.")
        || predicate.starts_with("companion.")
}
