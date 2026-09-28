//! Typed optimizer goal rows authored by trusted policy manifests.
use std::collections::BTreeSet;

use rmpv::Value;
use serde::Serialize;

use crate::skill_optimize::{GoalAxisKind, GoalAxisSpec};

/// Default and narrowing policy for skill edit admission. Precedence and the
/// vault cap are DATA; the engine only validates and composes the rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SkillEditGoalPolicy {
    pub(crate) precedence: String,
    pub(crate) holder_max_scope: String,
    pub(crate) axes: Vec<GoalAxisSpec>,
}

fn unique_field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    if entries.iter().any(|(name, _)| name.as_str().is_none()) {
        return None;
    }
    let mut matches = entries
        .iter()
        .filter(|(name, _)| name.as_str() == Some(key));
    let value = &matches.next()?.1;
    matches.next().is_none().then_some(value)
}

impl SkillEditGoalPolicy {
    pub(crate) fn decode(value: Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        if entries.len() != 3 {
            return None;
        }
        let precedence = unique_field(&entries, "precedence")?.as_str()?;
        let holder_max_scope = unique_field(&entries, "holder_max_scope")?.as_str()?;
        if precedence != "nested_narrowing" || holder_max_scope != "vault" {
            return None;
        }
        let raw_axes = unique_field(&entries, "axes")?.as_array()?;
        if raw_axes.is_empty() || raw_axes.len() > 32 {
            return None;
        }
        let mut names = BTreeSet::new();
        let mut axes = Vec::with_capacity(raw_axes.len());
        for raw_axis in raw_axes {
            let Value::Map(axis_entries) = raw_axis else {
                return None;
            };
            if axis_entries.len() != 2 {
                return None;
            }
            let name = unique_field(axis_entries, "name")?.as_str()?;
            let kind = match unique_field(axis_entries, "kind")?.as_str()? {
                "primary" => GoalAxisKind::Primary,
                "floor" => GoalAxisKind::Floor,
                "cost" => GoalAxisKind::Cost,
                _ => return None,
            };
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
                || !names.insert(name.to_owned())
            {
                return None;
            }
            axes.push(GoalAxisSpec {
                name: name.to_owned(),
                kind,
            });
        }
        Some(Self {
            precedence: precedence.to_owned(),
            holder_max_scope: holder_max_scope.to_owned(),
            axes,
        })
    }
}
