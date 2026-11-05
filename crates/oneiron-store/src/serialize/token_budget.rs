//! Grouping, section/type token-budget enforcement, size estimation, and
//! pack token-stats collection.
//!
//! Note the deliberate cycle with [`super::pack_entry`]: enforcing the serialized
//! budget and stamping token stats both re-encode the prepared pack through
//! [`super::pack_entry::serialize_prepared_pack`] to measure real output size.
//! Measuring after encoding is the contract, not a layering slip.

use std::collections::HashMap;

use serde_json::{Map, Number, Value};

use crate::retrieval_signal::Signal;
use crate::serialize::pack_accounting::PackItemTokenStats;
use crate::serialize::pack_accounting::PackSectionTokenStats;
use crate::serialize::pack_accounting::PackTokenStats;
use crate::serialize::pack_accounting::TokenAllocation;
use crate::serialize::pack_format::PackFormat;
use oneiron_base::registry::ENTITY_TYPE_CLAIM;
use oneiron_base::registry::ENTITY_TYPE_FACET;
use oneiron_base::registry::ENTITY_TYPE_SUMMARY;
use oneiron_base::registry::ENTITY_TYPE_TURN;
use oneiron_base::tokenizer::PackTokenizer;

use crate::serialize::group_labels::known_group_labels;
use crate::serialize::pack_preparation::clone_value_with_depth_limit;
use crate::serialize::pack_preparation::value_depth_limit_reached;
use crate::serialize::types::GROUP_ORDER;
use crate::serialize::types::GroupKey;
use crate::serialize::types::ValueDepthLimit;

pub fn type_fraction(key: GroupKey, allocation: &TokenAllocation) -> f32 {
    match key {
        GroupKey::Kind(ENTITY_TYPE_CLAIM | ENTITY_TYPE_FACET) => allocation.claims,
        GroupKey::Kind(ENTITY_TYPE_TURN) => allocation.turns,
        GroupKey::Kind(ENTITY_TYPE_SUMMARY) => allocation.summaries,
        GroupKey::Kind(_) | GroupKey::Other => allocation.other,
    }
}

pub fn allocate_section_budgets(needs: [usize; 2], total_budget: usize) -> [usize; 2] {
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

pub fn item_accounting_json(
    accounting: crate::serialize::pack_accounting::PackItemAccounting,
) -> Value {
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

pub fn signal_name(signal: Signal) -> &'static str {
    match signal {
        Signal::Vector => "vector",
        Signal::Text => "text",
        Signal::Phonetic => "phonetic",
        Signal::Temporal => "temporal",
        Signal::Ppr => "ppr",
        Signal::Hyde => "hyde",
    }
}

pub fn estimate_value_chars_with_depth_limit(
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

pub fn estimate_json_string_chars(text: &str) -> usize {
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

pub fn group_key_of(entity_type: u8) -> GroupKey {
    if known_group_labels(entity_type).is_some() {
        GroupKey::Kind(entity_type)
    } else {
        GroupKey::Other
    }
}
