//! Closed decoder for the optional residence-operation budget manifest row.

use rmpv::Value;

use crate::gate::residence_budgets::ResidenceBudgetPatch;
use crate::gate::{ResidenceOperationBudgetPrecedence, ResidenceOperationBudgetRow};

pub(in crate::gate) const POLICY_RESIDENCE_OPERATION_BUDGETS_KEY: &str =
    "residence_operation_budgets";

const PRECEDENCE_KEY: &str = "precedence";
const VAULT_KEY: &str = "vault";
const HOLDER_KEY: &str = "holder";
const NESTED_NARROWING: &str = "nested_narrowing";

/// Parses the closed `{precedence, vault, holder?}` row. Each budget map may
/// name a subset of the shipped fields; an omitted vault field keeps the
/// shipped default, and an omitted holder field narrows nothing.
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

fn parse_budget_map(value: &Value) -> Option<ResidenceBudgetPatch> {
    let Value::Map(entries) = value else {
        return None;
    };
    let mut patch = ResidenceBudgetPatch::default();

    // Each named field takes any positive value it can represent: the
    // shipped values are defaults and work slices, never ceilings (FIX 8750).
    for (key, value) in entries {
        match key.as_str()? {
            "rpc_timeout_ms" => set_once(&mut patch.rpc_timeout_ms, parse_positive(value)?)?,
            "index_page_limit" => {
                set_once(&mut patch.index_page_limit, parse_positive_usize(value)?)?;
            }
            "max_index_pages" => {
                set_once(&mut patch.max_index_pages, parse_positive_usize(value)?)?;
            }
            "current_window_count" => {
                set_once(
                    &mut patch.current_window_count,
                    parse_positive_usize(value)?,
                )?;
            }
            "title_max_chars" => {
                set_once(&mut patch.title_max_chars, parse_positive_usize(value)?)?;
            }
            "search_limit" => set_once(&mut patch.search_limit, parse_positive_usize(value)?)?,
            "search_query_max_bytes" => {
                set_once(
                    &mut patch.search_query_max_bytes,
                    parse_positive_usize(value)?,
                )?;
            }
            "offline_candidate_multiplier" => set_once(
                &mut patch.offline_candidate_multiplier,
                parse_positive_usize(value)?,
            )?,
            "ack_timeout_ms" => set_once(&mut patch.ack_timeout_ms, parse_positive(value)?)?,
            "index_cache_bytes" => {
                set_once(&mut patch.index_cache_bytes, parse_positive_usize(value)?)?;
            }
            _ => return None,
        }
    }

    Some(patch)
}

/// Sets a field the map names once; a second naming refuses the row.
fn set_once<T>(field: &mut Option<T>, value: T) -> Option<()> {
    if field.is_some() {
        return None;
    }
    *field = Some(value);
    Some(())
}

fn parse_positive(value: &Value) -> Option<u64> {
    value.as_u64().filter(|value| *value > 0)
}

fn parse_positive_usize(value: &Value) -> Option<usize> {
    usize::try_from(parse_positive(value)?).ok()
}
