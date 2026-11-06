//! Per-item token-budget enforcement and value truncation.

use serde_json::Value;

use oneiron_base::registry::ENTITY_TYPE_CLAIM;
use oneiron_base::tokenizer::PackTokenizer;

use crate::serialize::token_budget::estimate_value_chars_with_depth_limit;
use crate::serialize::types::ValueDepthLimit;

pub fn is_structural_item_budget_field(key: &str) -> bool {
    key == "pred"
}

pub fn truncate_with_suffix_prefix(text: &str, prefix_chars: usize, suffix: &str) -> String {
    let prefix: String = text.chars().take(prefix_chars).collect();
    format!("{prefix}{suffix}")
}

pub fn truncation_suffix(original_chars: usize) -> String {
    format!("...(truncated, {original_chars} chars total)")
}
