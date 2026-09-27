//! Vault-resident policy rows for the skill tradeoff ladder.
//!
//! Trusted POLICY_MANIFEST rows decide the limits. The shipped default row
//! lives in `default_manifest`; this code only checks shape and composes rows.
use super::resolution::resolve_policy_manifest;
use crate::store::Store;
use crate::{
    EntityId,
    error::{Error, Result},
};
use rmpv::Value;

pub(super) const KEY: &str = "skill_tradeoff_limits";
const MODE: &str = "nested_narrowing_holder_override_capped_vault";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SkillTradeoffLimits {
    pub(crate) max_axes: u64,
    pub(crate) max_axis_name_bytes: u64,
    pub(crate) max_authored_rules: u64,
    pub(crate) max_learned_rules: Option<u64>,
}
impl SkillTradeoffLimits {
    fn restrict(self, other: Self) -> Self {
        Self {
            max_axes: self.max_axes.min(other.max_axes),
            max_axis_name_bytes: self.max_axis_name_bytes.min(other.max_axis_name_bytes),
            max_authored_rules: self.max_authored_rules.min(other.max_authored_rules),
            max_learned_rules: match (self.max_learned_rules, other.max_learned_rules) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) | (None, Some(a)) => Some(a),
                (None, None) => None,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkillTradeoffPolicyRow {
    holder: Option<EntityId>,
    limits: SkillTradeoffLimits,
}

pub(super) fn parse_rows(value: &Value) -> Option<Vec<SkillTradeoffPolicyRow>> {
    let Value::Array(rows) = value else {
        return None;
    };
    rows.iter()
        .map(|row| {
            let Value::Map(entries) = row else {
                return None;
            };
            let mut seen = std::collections::BTreeSet::new();
            for (key, _) in entries {
                let name = key.as_str()?;
                if !seen.insert(name)
                    || !matches!(
                        name,
                        "holder"
                            | "max_axes"
                            | "max_axis_name_bytes"
                            | "max_authored_rules"
                            | "max_learned_rules"
                            | "precedence"
                    )
                {
                    return None;
                }
            }
            let get = |name: &str| {
                entries
                    .iter()
                    .find(|(key, _)| key.as_str() == Some(name))
                    .map(|(_, value)| value)
            };
            let holder = match get("holder")?.as_str()? {
                "vault" => None,
                hex => Some(EntityId::from_hex(hex).ok()?),
            };
            if get("precedence")?.as_str()? != MODE {
                return None;
            }
            let limits = SkillTradeoffLimits {
                max_axes: get("max_axes")?.as_u64().filter(|v| *v > 0)?,
                max_axis_name_bytes: get("max_axis_name_bytes")?.as_u64().filter(|v| *v > 0)?,
                max_authored_rules: get("max_authored_rules")?.as_u64()?,
                max_learned_rules: match get("max_learned_rules") {
                    None | Some(Value::Nil) => None,
                    Some(value) => Some(value.as_u64()?),
                },
            };
            Some(SkillTradeoffPolicyRow { holder, limits })
        })
        .collect()
}

/// Nested narrowing across trusted manifests; holder-specific rows may
/// override but never exceed the vault-wide ceiling on any dimension.
pub(crate) fn skill_tradeoff_limits_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<SkillTradeoffLimits> {
    let resolved = resolve_policy_manifest(store, txn)?;
    if resolved.diagnostics.loaded_manifest_forces_fail_closed() {
        return Err(Error::InvalidConfig(
            "malformed tradeoff policy manifest".into(),
        ));
    }
    let mut vault: Option<SkillTradeoffLimits> = None;
    let mut scoped: Option<SkillTradeoffLimits> = None;
    for row in &resolved.skill_tradeoff_rows {
        let target = if row.holder == Some(*holder) {
            &mut scoped
        } else if row.holder.is_none() {
            &mut vault
        } else {
            continue;
        };
        *target = Some(target.map_or(row.limits, |existing| existing.restrict(row.limits)));
    }
    let vault = vault.ok_or(Error::InvalidConfig(
        "missing vault tradeoff policy row".into(),
    ))?;
    Ok(scoped.map_or(vault, |holder| vault.restrict(holder)))
}
