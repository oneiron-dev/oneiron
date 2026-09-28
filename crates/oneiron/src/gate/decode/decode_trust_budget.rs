//! Source-trust ceilings and budget-policy parsers.

use rmpv::Value;

use crate::claim::{ClaimSource, sensitivity_band_from_value};
use crate::entity_id::EntityId;
use crate::gate::ceiling::{SourceTrustCeiling, SourceTrustRow};
use crate::gate::constants::{
    ACTOR_REF_KEY, BUDGET_POLICY_ACTOR_KEY, BUDGET_POLICY_CAP_KEY, BUDGET_POLICY_FLOOR_KEY,
    BUDGET_POLICY_PURPOSE_KEY, GATE_RETENTION_HOLDER_OVERRIDE_CEILING_KEY,
    GATE_RETENTION_HORIZON_SECS_KEY, GATE_RETENTION_MAX_SWEEP_ROWS_KEY,
    GATE_RETENTION_PRECEDENCE_KEY, SOURCE_TRUST_AUTO_KEY, SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY,
    SOURCE_TRUST_RECEIPTED_KEY, SOURCE_TRUST_WARNED_KEY,
};
use crate::gate::resolution::{
    GateDecisionRetentionPolicy, GateRetentionOverrideCeiling, GateRetentionPrecedence,
    GateRetentionRow, GateRetentionScope,
};
use crate::llm::{
    BudgetExhaustionPolicy, BudgetPolicyRow, BudgetPolicySelector, BudgetPolicyTable, CallPurpose,
};

use super::decode_map_util::{MapValue, required_value, single_map_value};

pub(super) fn parse_source_trust(value: &Value) -> Option<SourceTrustCeiling> {
    let Value::Map(source_rows) = value else {
        return None;
    };
    let mut ceiling = SourceTrustCeiling::default();
    for (source_key, row_value) in source_rows {
        let source = source_key.as_str().and_then(ClaimSource::parse)?;
        let row = parse_source_trust_row(row_value)?;
        ceiling.set_row(source, row);
    }
    Some(ceiling)
}

pub(super) fn parse_source_trust_row(value: &Value) -> Option<SourceTrustRow> {
    match value {
        // The shorthand row shapes carry no actor binding, so they stay
        // class-wide exactly as before.
        Value::Boolean(false) => Some(SourceTrustRow {
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
            actor_ref: None,
        }),
        Value::Integer(_) | Value::String(_) => Some(SourceTrustRow {
            max_auto_sensitivity: sensitivity_band_from_value(value),
            receipted: false,
            warned: false,
            actor_ref: None,
        }),
        Value::Map(entries) => {
            let mut max_auto_sensitivity = None;
            let mut auto_disabled = false;
            let mut receipted = false;
            let mut warned = false;
            let mut actor_ref = None;

            for (key, value) in entries {
                match key.as_str()? {
                    SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY => {
                        max_auto_sensitivity = Some(sensitivity_band_from_value(value)?);
                    }
                    SOURCE_TRUST_AUTO_KEY => match value {
                        Value::Boolean(false) => auto_disabled = true,
                        Value::Boolean(true) => {}
                        _ => return None,
                    },
                    SOURCE_TRUST_RECEIPTED_KEY => {
                        receipted = value.as_bool()?;
                    }
                    SOURCE_TRUST_WARNED_KEY => {
                        warned = value.as_bool()?;
                    }
                    // An actor binding must decode to a real entity id or the
                    // whole row is malformed: a permit aimed at an unreadable
                    // ref would otherwise silently widen back to class-wide.
                    ACTOR_REF_KEY => {
                        actor_ref = Some(EntityId::from_hex(value.as_str()?).ok()?);
                    }
                    _ => {}
                }
            }

            Some(SourceTrustRow {
                max_auto_sensitivity: if auto_disabled {
                    None
                } else {
                    Some(max_auto_sensitivity?)
                },
                receipted,
                warned,
                actor_ref,
            })
        }
        _ => None,
    }
}

/// Refuse unknown, missing, duplicated, zero, and wrongly typed values. A
/// malformed retention row drops the whole manifest, not merely this option.
pub(super) fn parse_gate_decision_retention(value: &Value) -> Option<GateDecisionRetentionPolicy> {
    let Value::Map(entries) = value else {
        return None;
    };
    for (key, _) in entries {
        if !matches!(
            key.as_str()?,
            GATE_RETENTION_HORIZON_SECS_KEY
                | GATE_RETENTION_MAX_SWEEP_ROWS_KEY
                | GATE_RETENTION_PRECEDENCE_KEY
                | GATE_RETENTION_HOLDER_OVERRIDE_CEILING_KEY
                | "rows"
        ) {
            return None;
        }
    }
    let precedence = match required_value(entries, GATE_RETENTION_PRECEDENCE_KEY)?.as_str()? {
        "nested_narrowing" => GateRetentionPrecedence::NestedNarrowing,
        "most_specific" => GateRetentionPrecedence::MostSpecific,
        _ => return None,
    };
    let holder_override_ceiling =
        match required_value(entries, GATE_RETENTION_HOLDER_OVERRIDE_CEILING_KEY)?.as_str()? {
            "vault" => GateRetentionOverrideCeiling::Vault,
            "parent" => GateRetentionOverrideCeiling::Parent,
            _ => return None,
        };
    let horizon_secs =
        parse_retention_horizon(required_value(entries, GATE_RETENTION_HORIZON_SECS_KEY)?)?;
    let max_sweep_rows =
        usize::try_from(required_value(entries, GATE_RETENTION_MAX_SWEEP_ROWS_KEY)?.as_u64()?)
            .ok()
            .filter(|rows| *rows > 0)?;
    let rows = match single_map_value(entries, "rows") {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(Value::Array(rows)) if rows.len() <= 1024 => {
            let mut parsed: Vec<GateRetentionRow> = Vec::with_capacity(rows.len());
            for row in rows {
                let Value::Map(fields) = row else {
                    return None;
                };
                if fields.len() != 4
                    || fields.iter().any(|(key, _)| {
                        !matches!(
                            key.as_str(),
                            Some("row_ref" | "scope" | "horizon_secs" | "override_parent")
                        )
                    })
                {
                    return None;
                }
                let row_ref = required_value(fields, "row_ref")?.as_str()?;
                if row_ref.is_empty()
                    || row_ref.len() > 96
                    || !row_ref.bytes().all(|b| {
                        b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || matches!(b, b'.' | b'_' | b'-')
                    })
                {
                    return None;
                }
                let scope = parse_retention_scope(required_value(fields, "scope")?)?;
                if scope == GateRetentionScope::Vault
                    || parsed
                        .iter()
                        .any(|prior| prior.scope == scope || prior.row_ref == row_ref)
                {
                    return None;
                }
                parsed.push(GateRetentionRow {
                    row_ref: row_ref.to_owned(),
                    scope,
                    horizon_secs: parse_retention_horizon(required_value(fields, "horizon_secs")?)?,
                    override_parent: match required_value(fields, "override_parent")? {
                        Value::Boolean(value) => *value,
                        _ => return None,
                    },
                });
            }
            parsed
        }
        _ => return None,
    };
    Some(GateDecisionRetentionPolicy {
        horizon_secs,
        max_sweep_rows,
        precedence,
        holder_override_ceiling,
        rows,
    })
}

fn parse_retention_horizon(value: &Value) -> Option<Option<u64>> {
    match value {
        Value::Nil => Some(None),
        value => Some(Some(value.as_u64().filter(|seconds| *seconds > 0)?)),
    }
}

fn parse_retention_scope(value: &Value) -> Option<GateRetentionScope> {
    let Value::Map(entries) = value else {
        return None;
    };
    let level = required_value(entries, "level")?.as_str()?;
    if entries.len() != 2
        || entries
            .iter()
            .any(|(key, _)| !matches!(key.as_str(), Some("level" | "ref")))
    {
        return None;
    }
    let reference = required_value(entries, "ref")?.as_str()?;
    let id = EntityId::from_hex(reference).ok()?;
    if id.to_hex() != reference {
        return None;
    }
    match level {
        "world" => Some(GateRetentionScope::World(id)),
        "project" => Some(GateRetentionScope::Project(id)),
        "sub_project" => Some(GateRetentionScope::SubProject(id)),
        "thread" => Some(GateRetentionScope::Thread(id)),
        _ => None,
    }
}

pub(super) fn parse_budget_exhaustion_policy(value: &Value) -> Option<BudgetExhaustionPolicy> {
    if let Some(policy) = value.as_str().and_then(parse_budget_exhaustion_policy_kind) {
        return Some(policy);
    }

    let Value::Map(entries) = value else {
        return None;
    };

    match single_map_value(entries, "kind") {
        MapValue::Present(kind) => match kind.as_str()? {
            "suspend" => Some(BudgetExhaustionPolicy::Suspend),
            "continue_on_local" => Some(BudgetExhaustionPolicy::ContinueOnLocal),
            "overdraft" => {
                let cap = required_value(entries, "cap")?.as_u64()?;
                Some(BudgetExhaustionPolicy::Overdraft { cap })
            }
            _ => None,
        },
        MapValue::Missing => match single_map_value(entries, "overdraft") {
            MapValue::Missing | MapValue::Duplicate => None,
            MapValue::Present(overdraft) => {
                let Value::Map(overdraft_entries) = overdraft else {
                    return None;
                };
                let cap = required_value(overdraft_entries, "cap")?.as_u64()?;
                Some(BudgetExhaustionPolicy::Overdraft { cap })
            }
        },
        MapValue::Duplicate => None,
    }
}

pub(super) fn parse_budget_exhaustion_policy_kind(kind: &str) -> Option<BudgetExhaustionPolicy> {
    match kind {
        "suspend" => Some(BudgetExhaustionPolicy::Suspend),
        "continue_on_local" => Some(BudgetExhaustionPolicy::ContinueOnLocal),
        _ => None,
    }
}

/// Parses the ordered `budget_policy` row array. Every entry must be a valid
/// row map; any malformed entry rejects the whole table so
/// `decode_policy_manifest` drops the manifest rather than silently widening
/// the policy by ignoring rows.
pub(super) fn parse_budget_policy(value: &Value) -> Option<BudgetPolicyTable> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        parsed.push(parse_budget_policy_row(entries)?);
    }
    Some(BudgetPolicyTable::from_rows(parsed))
}

/// One row is valid only with exactly one of `purpose`/`actor`, at least one
/// of `floor`/`cap`, unsigned 64-bit units (`0` is valid: `cap: 0` denies the
/// row deliberately, `floor: 0` is an explicit no-op reservation), no
/// duplicated key, and no unknown key — unknown keys are never ignored.
pub(super) fn parse_budget_policy_row(entries: &[(Value, Value)]) -> Option<BudgetPolicyRow> {
    let mut purpose = None;
    let mut actor = None;
    let mut floor_units = None;
    let mut cap_units = None;
    let mut purpose_seen = false;
    let mut actor_seen = false;
    let mut floor_seen = false;
    let mut cap_seen = false;

    for (key, value) in entries {
        match key.as_str()? {
            BUDGET_POLICY_PURPOSE_KEY => {
                if purpose_seen {
                    return None;
                }
                purpose_seen = true;
                purpose = Some(parse_budget_purpose(value)?);
            }
            BUDGET_POLICY_ACTOR_KEY => {
                if actor_seen {
                    return None;
                }
                actor_seen = true;
                actor = Some(parse_budget_actor(value)?);
            }
            BUDGET_POLICY_FLOOR_KEY => {
                if floor_seen {
                    return None;
                }
                floor_seen = true;
                floor_units = Some(value.as_u64()?);
            }
            BUDGET_POLICY_CAP_KEY => {
                if cap_seen {
                    return None;
                }
                cap_seen = true;
                cap_units = Some(value.as_u64()?);
            }
            _ => return None,
        }
    }

    let selector = match (purpose, actor) {
        (Some(purpose), None) => BudgetPolicySelector::Purpose(purpose),
        (None, Some(actor)) => BudgetPolicySelector::Actor(actor),
        _ => return None,
    };
    if !floor_seen && !cap_seen {
        return None;
    }
    Some(BudgetPolicyRow::new(selector, floor_units, cap_units))
}

/// Built-in names map to their pinned `CallPurpose` variants; any other
/// non-empty string is an exact-name `Other`. An `Other` name that happens
/// to equal a built-in's snake-case name parses to the built-in variant, so
/// it can never spell a wildcard.
pub(super) fn parse_budget_purpose(value: &Value) -> Option<CallPurpose> {
    let name = value.as_str()?;
    if name.is_empty() {
        return None;
    }
    Some(match name {
        "extraction" => CallPurpose::Extraction,
        "consolidation" => CallPurpose::Consolidation,
        "answer_gen" => CallPurpose::AnswerGen,
        "auto_check" => CallPurpose::AutoCheck,
        "tool_routing" => CallPurpose::ToolRouting,
        "voice" => CallPurpose::Voice,
        "eval" => CallPurpose::Eval,
        _ => CallPurpose::Other {
            name: name.to_owned(),
        },
    })
}

/// Actor rows name the canonical lowercase 32-hex `EntityId` form that
/// `WriteActor::entity_ref().to_hex()` produces; any other spelling (wrong
/// length, non-hex, uppercase) rejects the row.
pub(super) fn parse_budget_actor(value: &Value) -> Option<EntityId> {
    let text = value.as_str()?;
    let id = EntityId::from_hex(text).ok()?;
    if id.to_hex() != text {
        return None;
    }
    Some(id)
}
