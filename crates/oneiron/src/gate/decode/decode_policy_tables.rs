//! Rule, axis, ceiling, grant, and owner-row table parsers.

use rmpv::Value;

use crate::gate::ceiling::{
    ActorCeiling, DelegationGrantRecord, OwnerRowAction, PolicyApprovalCeiling, PolicyAxes,
    PolicyCriticality, PolicyOwnerPatternRow, PolicyOwnerPolicyRow, PolicyRule, PolicySensitivity,
};
use crate::gate::constants::{
    ACTOR_CEILING_KEY, ACTOR_CLASS_KEY, ACTOR_REF_KEY, AXIS_CRITICALITY_KEY, AXIS_SENSITIVITY_KEY,
    GRANT_BUDGET_KEY, GRANT_EFFECTOR_KEY, GRANT_RECEIPT_REQUIRED_KEY, GRANT_SCOPE_KEY,
    POLICY_PATTERN_CATEGORY_KEY, POLICY_PATTERN_ID_KEY, POLICY_PATTERN_PATTERN_KEY,
    POLICY_PATTERN_ROLE_KEY, POLICY_ROW_ACTION_KEY, POLICY_ROW_ACTIVE_KEY, POLICY_ROW_REF_KEY,
    POLICY_ROW_TEXT_KEY, POLICY_ROW_WORLD_REF_KEY, RULE_AXES_KEY, RULE_EXACT_KEY, RULE_PREFIX_KEY,
};
use crate::gate::grants::PolicyScopedGrant;

use super::decode_map_util::{
    MapValue, optional_bool, optional_bool_default, optional_string, optional_value,
    required_nonempty_string, required_string, required_value, single_map_value,
};

/// Parses the `owner_policy_patterns` array. Every entry must be a row map
/// carrying only the four recognized keys — an unknown key rejects the whole
/// table, exactly as [`parse_owner_policy_rows`] does, so a misspelled `role`
/// can never fall through to the permissive default and quietly change what a
/// rule is allowed to do.
pub(super) fn parse_owner_policy_patterns(value: &Value) -> Option<Vec<PolicyOwnerPatternRow>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        for (key, _) in entries {
            match key.as_str()? {
                POLICY_PATTERN_ID_KEY
                | POLICY_PATTERN_PATTERN_KEY
                | POLICY_PATTERN_CATEGORY_KEY
                | POLICY_PATTERN_ROLE_KEY => {}
                _ => return None,
            }
        }
        parsed.push(PolicyOwnerPatternRow {
            id: required_nonempty_string(entries, POLICY_PATTERN_ID_KEY)?,
            pattern: required_nonempty_string(entries, POLICY_PATTERN_PATTERN_KEY)?,
            category: required_nonempty_string(entries, POLICY_PATTERN_CATEGORY_KEY)?,
            role: optional_string(entries, POLICY_PATTERN_ROLE_KEY)?,
        });
    }
    Some(parsed)
}

pub(super) fn parse_rules(value: &Value) -> Option<Vec<PolicyRule>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut rules = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let prefix = required_string(entries, RULE_PREFIX_KEY)?;
        if prefix.is_empty() {
            return None;
        }
        let exact = optional_bool(entries, RULE_EXACT_KEY)?;
        let axes = parse_axes(required_value(entries, RULE_AXES_KEY)?)?;
        rules.push(PolicyRule {
            prefix,
            exact,
            axes,
        });
    }
    Some(rules)
}

pub(super) fn parse_axes(value: &Value) -> Option<PolicyAxes> {
    let Value::Map(entries) = value else {
        return None;
    };
    let mut axes = PolicyAxes::default();
    let mut criticality_seen = false;
    let mut sensitivity_seen = false;

    for (key, value) in entries {
        match key.as_str()? {
            AXIS_CRITICALITY_KEY => {
                if criticality_seen {
                    return None;
                }
                criticality_seen = true;
                axes.criticality = Some(PolicyCriticality::parse(value)?);
            }
            AXIS_SENSITIVITY_KEY => {
                if sensitivity_seen {
                    return None;
                }
                sensitivity_seen = true;
                axes.sensitivity = Some(PolicySensitivity::parse(value)?);
            }
            _ => axes.unknown_axis_seen = true,
        }
    }

    Some(axes)
}

pub(super) fn parse_actor_ceilings(value: &Value) -> Option<Vec<ActorCeiling>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut actor_ceilings = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let actor_class = required_string(entries, ACTOR_CLASS_KEY)?;
        if actor_class.is_empty() {
            return None;
        }
        let actor_ref = optional_string(entries, ACTOR_REF_KEY)?;
        let ceiling = PolicyApprovalCeiling::parse(required_value(entries, ACTOR_CEILING_KEY)?)?;
        actor_ceilings.push(ActorCeiling {
            actor_class,
            actor_ref,
            ceiling,
        });
    }
    Some(actor_ceilings)
}

pub(in crate::gate) fn parse_delegated_grants(value: &Value) -> Option<Vec<DelegationGrantRecord>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut out = Vec::new();
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let op = match (
            single_map_value(entries, "op"),
            single_map_value(entries, "kind"),
        ) {
            (MapValue::Present(v), MapValue::Missing)
            | (MapValue::Missing, MapValue::Present(v)) => v.as_str()?,
            _ => return None,
        };
        let grant_ref = required_nonempty_string(entries, "grant_ref")?;
        for (key, _) in entries {
            let key = key.as_str()?;
            let allowed = match op {
                "revoke_grant" => matches!(key, "op" | "kind" | "grant_ref"),
                "grant" => matches!(
                    key,
                    "op" | "kind"
                        | "grant_ref"
                        | ACTOR_CLASS_KEY
                        | ACTOR_REF_KEY
                        | "parent_grant_ref"
                        | ACTOR_CEILING_KEY
                ),
                _ => false,
            };
            if !allowed {
                return None;
            }
        }
        match op {
            "revoke_grant" => out.push(DelegationGrantRecord::RevokeGrant { grant_ref }),
            "grant" => out.push(DelegationGrantRecord::Grant {
                grant_ref,
                actor_class: required_nonempty_string(entries, ACTOR_CLASS_KEY)?,
                actor_ref: optional_string(entries, ACTOR_REF_KEY)?,
                parent_grant_ref: optional_string(entries, "parent_grant_ref")?,
                ceiling: PolicyApprovalCeiling::parse(required_value(entries, ACTOR_CEILING_KEY)?)?,
            }),
            _ => return None,
        }
    }
    Some(out)
}

pub(super) fn parse_scoped_grants(value: &Value) -> Option<Vec<PolicyScopedGrant>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut grants = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let actor_class = optional_string(entries, ACTOR_CLASS_KEY)?;
        let actor_ref = optional_string(entries, ACTOR_REF_KEY)?;
        let effector = required_string(entries, GRANT_EFFECTOR_KEY)?;
        if effector.is_empty() {
            return None;
        }
        let scope = optional_value(entries, GRANT_SCOPE_KEY)?;
        let budget = optional_value(entries, GRANT_BUDGET_KEY)?;
        let receipt_required = match single_map_value(entries, GRANT_RECEIPT_REQUIRED_KEY) {
            MapValue::Missing => true,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => value.as_bool()?,
        };
        grants.push(PolicyScopedGrant {
            actor_class,
            actor_ref,
            effector,
            scope,
            budget,
            receipt_required,
        });
    }
    Some(grants)
}

/// Parses the `owner_policy_rows` array. Every entry must be a valid row map
/// carrying only the five recognized keys — an unknown key rejects the whole
/// table, exactly as [`parse_budget_policy_row`] does, so a misspelled
/// `action` can never fall through to the gentle `Warn` default and quietly
/// widen the owner's plane.
pub(super) fn parse_owner_policy_rows(value: &Value) -> Option<Vec<PolicyOwnerPolicyRow>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        for (key, _) in entries {
            match key.as_str()? {
                POLICY_ROW_REF_KEY
                | POLICY_ROW_TEXT_KEY
                | POLICY_ROW_ACTIVE_KEY
                | POLICY_ROW_WORLD_REF_KEY
                | POLICY_ROW_ACTION_KEY => {}
                _ => return None,
            }
        }
        let row_ref = required_nonempty_string(entries, POLICY_ROW_REF_KEY)?;
        let text = required_nonempty_string(entries, POLICY_ROW_TEXT_KEY)?;
        let active = optional_bool_default(entries, POLICY_ROW_ACTIVE_KEY, true)?;
        let world_ref = optional_string(entries, POLICY_ROW_WORLD_REF_KEY)?;
        let action = match optional_string(entries, POLICY_ROW_ACTION_KEY)? {
            // A row that names no action only wants to be told about, so the
            // gentlest arm is the default: content still ships unchanged.
            None => OwnerRowAction::Warn,
            Some(action) => parse_owner_row_action(&action)?,
        };
        // `row_ref` is the owner plane's whole vocabulary: it is what the
        // model answers in, what a pattern rule names, and what resolution
        // looks up — and resolution takes the FIRST match, so a duplicate is a
        // rule that can never fire, however strict its action.
        //
        // The key is the PAIR, not the ref alone: one ref written twice under
        // two worlds is the scoped-override shape `active_owner_policy_rows`
        // exists to resolve, and only rows that would land in the same rubric
        // together shadow each other. Refusing them here drops the rows as
        // malformed rather than letting one silently swallow the other.
        if parsed.iter().any(|seen: &PolicyOwnerPolicyRow| {
            seen.row_ref == row_ref && seen.world_ref == world_ref
        }) {
            return None;
        }
        parsed.push(PolicyOwnerPolicyRow {
            row_ref,
            text,
            active,
            world_ref,
            action,
        });
    }
    Some(parsed)
}

pub(super) fn parse_owner_row_action(action: &str) -> Option<OwnerRowAction> {
    match action {
        "warn" => Some(OwnerRowAction::Warn),
        "block" => Some(OwnerRowAction::Block),
        "route_to_help" | "route-to-help" => Some(OwnerRowAction::RouteToHelp),
        _ => None,
    }
}
