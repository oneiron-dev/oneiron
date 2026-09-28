//! Closed decoder for the optional residence-operation budget manifest row.

use rmpv::Value;

use crate::gate::{
    ResidenceOperationBudgetLimits, ResidenceOperationBudgetPrecedence, ResidenceOperationBudgetRow,
};

pub(in crate::gate) const POLICY_RESIDENCE_OPERATION_BUDGETS_KEY: &str =
    "residence_operation_budgets";

const PRECEDENCE_KEY: &str = "precedence";
const VAULT_KEY: &str = "vault";
const HOLDER_KEY: &str = "holder";
const NESTED_NARROWING: &str = "nested_narrowing";

/// Parses the closed `{precedence, vault, holder?}` row. Each budget map may
/// name a subset of the shipped fields; omissions retain the shipped value.
pub(in crate::gate) fn parse_residence_operation_budgets(
    value: &Value,
) -> Option<ResidenceOperationBudgetRow> {
    let Value::Map(entries) = value else {
        return None;
    };

    let mut precedence = None;
    let mut vault = None;
    let mut holder = None;
    let mut holder_seen = false;
    for (key, value) in entries {
        match key.as_str()? {
            PRECEDENCE_KEY => {
                if precedence.is_some() || value.as_str()? != NESTED_NARROWING {
                    return None;
                }
                precedence = Some(ResidenceOperationBudgetPrecedence::NestedNarrowing);
            }
            VAULT_KEY => {
                if vault.is_some() {
                    return None;
                }
                vault = Some(parse_budget_map(value)?);
            }
            HOLDER_KEY => {
                if holder_seen {
                    return None;
                }
                holder_seen = true;
                holder = Some(parse_budget_map(value)?);
            }
            _ => return None,
        }
    }

    Some(ResidenceOperationBudgetRow {
        precedence: precedence.unwrap_or_default(),
        vault: vault?,
        holder,
    })
}

fn parse_budget_map(value: &Value) -> Option<ResidenceOperationBudgetLimits> {
    let Value::Map(entries) = value else {
        return None;
    };
    let mut limits = ResidenceOperationBudgetLimits::default();
    let mut seen = [false; 10];

    for (key, value) in entries {
        match key.as_str()? {
            "rpc_timeout_ms" => {
                if mark_seen(&mut seen, 0) {
                    return None;
                }
                limits.rpc_timeout_ms = parse_positive_bounded(
                    value,
                    ResidenceOperationBudgetLimits::MAX_RPC_TIMEOUT_MS,
                )?;
            }
            "index_page_limit" => {
                if mark_seen(&mut seen, 1) {
                    return None;
                }
                limits.index_page_limit = parse_positive_bounded_usize(value, 256)?;
            }
            "max_index_pages" => {
                if mark_seen(&mut seen, 2) {
                    return None;
                }
                limits.max_index_pages = parse_positive_bounded_usize(value, 1024)?;
            }
            "current_window_count" => {
                if mark_seen(&mut seen, 3) {
                    return None;
                }
                limits.current_window_count = parse_positive_bounded_usize(value, 2)?;
            }
            "title_max_chars" => {
                if mark_seen(&mut seen, 4) {
                    return None;
                }
                limits.title_max_chars = parse_positive_bounded_usize(value, 128)?;
            }
            "search_limit" => {
                if mark_seen(&mut seen, 5) {
                    return None;
                }
                limits.search_limit = parse_positive_bounded_usize(value, 100)?;
            }
            "search_query_max_bytes" => {
                if mark_seen(&mut seen, 8) {
                    return None;
                }
                limits.search_query_max_bytes = parse_positive_bounded_usize(value, 4_096)?;
            }
            "offline_candidate_multiplier" => {
                if mark_seen(&mut seen, 9) {
                    return None;
                }
                limits.offline_candidate_multiplier = parse_positive_bounded_usize(value, 10)?;
            }
            "ack_timeout_ms" => {
                if mark_seen(&mut seen, 6) {
                    return None;
                }
                limits.ack_timeout_ms = parse_positive_bounded(value, 30_000)?;
            }
            "index_cache_bytes" => {
                if mark_seen(&mut seen, 7) {
                    return None;
                }
                limits.index_cache_bytes = parse_positive_bounded_usize(
                    value,
                    ResidenceOperationBudgetLimits::MAX_INDEX_CACHE_BYTES,
                )?;
            }
            _ => return None,
        }
    }

    Some(limits)
}

fn mark_seen(seen: &mut [bool; 10], index: usize) -> bool {
    let was_seen = seen[index];
    seen[index] = true;
    was_seen
}

fn parse_positive_bounded(value: &Value, max: u64) -> Option<u64> {
    value.as_u64().filter(|value| *value > 0 && *value <= max)
}

fn parse_positive_bounded_usize(value: &Value, max: usize) -> Option<usize> {
    let value = value.as_u64()?;
    let value = usize::try_from(value).ok()?;
    (value > 0 && value <= max).then_some(value)
}
