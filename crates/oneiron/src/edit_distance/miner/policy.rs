//! OF-379 proposal routing, driven by validated policy-manifest rows.
use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use super::target::CompilationTarget;
use crate::entity_id::EntityId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Family {
    Ban,
    StyleRule,
    CharterLine,
    BriefUpdate,
}
impl Family {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "ban" => Some(Self::Ban),
            "style_rule" => Some(Self::StyleRule),
            "charter_line" => Some(Self::CharterLine),
            "brief_update" => Some(Self::BriefUpdate),
            _ => None,
        }
    }
    fn target(self, text: &str) -> CompilationTarget {
        match self {
            Self::Ban => CompilationTarget::Ban(text.to_owned()),
            Self::StyleRule => CompilationTarget::StyleRule(text.to_owned()),
            Self::CharterLine => CompilationTarget::CharterLine(text.to_owned()),
            Self::BriefUpdate => CompilationTarget::BriefUpdate(text.to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Route {
    family: Family,
    enabled: bool,
    scope_prefix: String,
    scope_not_prefixes: Vec<String>,
    require_scope_suffix: bool,
    to_prefix: String,
    from_not_prefix: String,
    style_atom: bool,
}
impl Route {
    fn matches(&self, scope: &str, from: &str, to: &str) -> bool {
        self.enabled
            && scope
                .strip_prefix(&self.scope_prefix)
                .is_some_and(|suffix| !self.require_scope_suffix || !suffix.trim().is_empty())
            && !self
                .scope_not_prefixes
                .iter()
                .any(|prefix| scope.starts_with(prefix))
            && to.starts_with(&self.to_prefix)
            && (self.from_not_prefix.is_empty() || !from.starts_with(&self.from_not_prefix))
            && (!self.style_atom || self.family.target(to).validate().is_ok())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    holder: Option<EntityId>,
    parent: Option<EntityId>,
    routes: BTreeMap<Family, Route>,
}

/// A trusted pack contributes one vault row and optional holder rows. Every
/// matching layer must permit a route: holder values cannot widen a vault or
/// their named parent, regardless of selector text or ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompilationPolicy {
    order: Vec<Family>,
    vault: Row,
    holders: BTreeMap<EntityId, Row>,
}

fn field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    let mut matches = map.iter().filter(|(name, _)| name.as_str() == Some(key));
    let value = &matches.next()?.1;
    matches.next().is_none().then_some(value)
}
fn known(map: &[(Value, Value)], keys: &[&str]) -> bool {
    let mut seen = BTreeSet::new();
    map.iter().all(|(key, _)| {
        key.as_str()
            .is_some_and(|key| keys.contains(&key) && seen.insert(key))
    })
}
fn text(map: &[(Value, Value)], key: &str) -> Option<String> {
    let text = field(map, key)?.as_str()?;
    (text.len() <= 256).then(|| text.to_owned())
}
fn id(map: &[(Value, Value)], key: &str) -> Option<EntityId> {
    EntityId::from_hex(field(map, key)?.as_str()?).ok()
}
impl CompilationPolicy {
    /// Decode a closed, bounded table. Invalid rows invalidate the manifest,
    /// never silently turn a bad restriction into a wider one.
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let Value::Map(map) = value else { return None };
        if !known(map, &["precedence", "order", "rows"])
            || field(map, "precedence")?.as_str()? != "nested_narrowing_holder_capped_at_vault"
        {
            return None;
        }
        let Value::Array(order_values) = field(map, "order")? else {
            return None;
        };
        if order_values.len() != 4 {
            return None;
        }
        let order: Vec<_> = order_values
            .iter()
            .map(|v| Family::parse(v.as_str()?))
            .collect::<Option<_>>()?;
        if order.iter().copied().collect::<BTreeSet<_>>().len() != 4 {
            return None;
        }
        let Value::Array(rows) = field(map, "rows")? else {
            return None;
        };
        if rows.is_empty() || rows.len() > 33 {
            return None;
        }
        let mut vault = None;
        let mut holders = BTreeMap::new();
        for value in rows {
            let Value::Map(map) = value else { return None };
            if !known(map, &["holder", "parent", "routes"]) {
                return None;
            }
            let holder = if field(map, "holder").is_some() {
                Some(id(map, "holder")?)
            } else {
                None
            };
            let parent = if field(map, "parent").is_some() {
                Some(id(map, "parent")?)
            } else {
                None
            };
            if holder.is_none() && parent.is_some() {
                return None;
            }
            let Value::Array(routes) = field(map, "routes")? else {
                return None;
            };
            if routes.len() > 4 {
                return None;
            }
            let mut parsed = BTreeMap::new();
            for route in routes {
                let Value::Map(map) = route else { return None };
                if !known(
                    map,
                    &[
                        "family",
                        "enabled",
                        "scope_prefix",
                        "scope_not_prefixes",
                        "require_scope_suffix",
                        "to_prefix",
                        "from_not_prefix",
                        "style_atom",
                    ],
                ) {
                    return None;
                }
                let family = Family::parse(field(map, "family")?.as_str()?)?;
                let row = Route {
                    family,
                    enabled: field(map, "enabled")?.as_bool()?,
                    scope_prefix: text(map, "scope_prefix")?,
                    scope_not_prefixes: {
                        let Value::Array(values) = field(map, "scope_not_prefixes")? else {
                            return None;
                        };
                        if values.len() > 8 {
                            return None;
                        }
                        let mut prefixes = Vec::new();
                        for value in values {
                            let prefix = value.as_str()?;
                            if prefix.is_empty()
                                || prefix.len() > 256
                                || prefixes.iter().any(|seen| seen == prefix)
                            {
                                return None;
                            }
                            prefixes.push(prefix.to_owned());
                        }
                        prefixes
                    },
                    require_scope_suffix: field(map, "require_scope_suffix")?.as_bool()?,
                    to_prefix: text(map, "to_prefix")?,
                    from_not_prefix: text(map, "from_not_prefix")?,
                    style_atom: field(map, "style_atom")?.as_bool()?,
                };
                if parsed.insert(family, row).is_some() {
                    return None;
                }
            }
            let row = Row {
                holder,
                parent,
                routes: parsed,
            };
            if let Some(holder) = holder {
                if holders.insert(holder, row).is_some() {
                    return None;
                }
            } else if vault.replace(row).is_some() {
                return None;
            }
        }
        let vault = vault?;
        // Require every named parent to exist, and every path to terminate at
        // the vault. Never skip a broken ancestry link to accept a wider child.
        for holder in holders.keys() {
            let mut visited = BTreeSet::new();
            let mut current = Some(*holder);
            while let Some(id) = current {
                if !visited.insert(id) {
                    return None;
                }
                current = holders.get(&id)?.parent;
            }
        }
        Some(Self {
            order,
            vault,
            holders,
        })
    }

    fn permits(&self, family: Family, scope: &str, from: &str, to: &str, holder: EntityId) -> bool {
        let allowed = |row: &Row| {
            row.routes
                .get(&family)
                .is_some_and(|route| route.matches(scope, from, to))
        };
        if !allowed(&self.vault) {
            return false;
        }
        let mut next = Some(holder);
        let mut visited = BTreeSet::new();
        while let Some(id) = next {
            if !visited.insert(id) {
                return false;
            }
            let Some(row) = self.holders.get(&id) else {
                break;
            };
            if row.holder != Some(id) || !allowed(row) {
                return false;
            }
            next = row.parent;
        }
        true
    }
}

/// Inference uses only principal-bound corrected runs. Every trusted pack and
/// every applicable holder/parent row must permit the same candidate. Empty
/// policy means no inferred targets, not an engine-owned fallback grammar.
pub(super) fn infer_target(
    policies: &[CompilationPolicy],
    holder: EntityId,
    scope: &str,
    from: &str,
    to: &str,
) -> CompilationTarget {
    if from.is_empty() || to.is_empty() || to.len() > 4096 {
        return CompilationTarget::Fallback;
    }
    let Some(primary) = policies.first() else {
        return CompilationTarget::Fallback;
    };
    if policies.iter().any(|policy| policy.order != primary.order) {
        return CompilationTarget::Fallback;
    }
    for family in &primary.order {
        if policies
            .iter()
            .all(|policy| policy.permits(*family, scope, from, to, holder))
        {
            let target = family.target(to);
            if target.validate().is_ok() {
                return target;
            }
        }
    }
    CompilationTarget::Fallback
}
