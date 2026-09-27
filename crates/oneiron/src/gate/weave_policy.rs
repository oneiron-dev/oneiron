//! Trusted manifest rows for the weave lens: nested narrowing, never read authority.
use crate::EntityId;
use rmpv::Value;
use std::collections::BTreeSet;

pub(crate) const KEY: &str = "weave_report_policy";
/// The precedence order is itself a manifest row.
pub(crate) const PRECEDENCE_KEY: &str = "weave_report_precedence";
pub(crate) const NESTED_NARROWING: &str = "nested_narrowing";

/// Both orders intersect holder ceilings with the vault. `holder_required`
/// additionally refuses readers without a matching holder row.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Precedence {
    #[default]
    NestedNarrowing,
    HolderRequired,
}
impl Precedence {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            NESTED_NARROWING => Some(Self::NestedNarrowing),
            "holder_required" => Some(Self::HolderRequired),
            _ => None,
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NestedNarrowing => NESTED_NARROWING,
            Self::HolderRequired => "holder_required",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub role: String,
    pub holder: Option<EntityId>,
    pub sections: BTreeSet<String>,
    pub max_sections: usize,
    pub max_predicates: usize,
    pub max_edge_kinds: usize,
    pub max_rows: usize,
}

impl Row {
    fn restrict(&mut self, other: &Self) {
        self.sections.retain(|s| other.sections.contains(s));
        self.max_sections = self.max_sections.min(other.max_sections);
        self.max_predicates = self.max_predicates.min(other.max_predicates);
        self.max_edge_kinds = self.max_edge_kinds.min(other.max_edge_kinds);
        self.max_rows = self.max_rows.min(other.max_rows);
    }
}

/// Each trusted vault row constrains the role. Holder rows further narrow its
/// vault row, never replace it. A missing role has no allowed sections.
pub(crate) fn effective(
    rows: &[Row],
    role: &str,
    holder: EntityId,
    precedence: Precedence,
) -> Option<Row> {
    let mut combined: Option<Row> = None;
    for row in rows.iter().filter(|r| r.role == role && r.holder.is_none()) {
        if let Some(current) = &mut combined {
            current.restrict(row);
        } else {
            combined = Some(row.clone());
        }
    }
    let mut combined = combined?;
    let mut holder_found = false;
    for row in rows
        .iter()
        .filter(|r| r.role == role && r.holder == Some(holder))
    {
        holder_found = true;
        combined.restrict(row);
    }
    if precedence == Precedence::HolderRequired && !holder_found {
        return None;
    }
    Some(combined)
}

/// Fresh vaults without a persisted policy manifest use the shipped rows.
/// Existing trusted manifests without this optional key inherit the same
/// defaults. A malformed/unsupported manifest must not invoke this fallback.
pub(crate) fn effective_resolved(
    policy: &crate::gate::PolicyManifestResolution,
    role: &str,
    holder: EntityId,
) -> Option<Row> {
    if policy.diagnostics.loaded_manifest_forces_fail_closed() {
        return None;
    }
    if policy.weave_report_policy_empty {
        return None;
    }
    if policy.weave_report_policy.is_empty() {
        return effective(
            &parse(&default_value())?,
            role,
            holder,
            policy.weave_report_precedence,
        );
    }
    effective(
        &policy.weave_report_policy,
        role,
        holder,
        policy.weave_report_precedence,
    )
}

pub(crate) fn default_value() -> Value {
    Value::Array(
        [
            ("person", &["changes", "projects", "open_asks", "links"][..]),
            (
                "owner",
                &[
                    "links",
                    "conflicts",
                    "exceptions",
                    "admissions",
                    "budgets",
                    "sieve_score",
                ],
            ),
            ("agent", &["digest"]),
        ]
        .into_iter()
        .map(|(role, sections)| {
            Value::Map(vec![
                (Value::from("role"), Value::from(role)),
                (
                    Value::from("sections"),
                    Value::Array(sections.iter().map(|s| Value::from(*s)).collect()),
                ),
                (Value::from("max_sections"), Value::from(16)),
                (Value::from("max_predicates"), Value::from(32)),
                (Value::from("max_edge_kinds"), Value::from(32)),
                (Value::from("max_rows"), Value::from(10_000)),
            ])
        })
        .collect(),
    )
}

const SECTION_NAMES: &[&str] = &[
    "changes",
    "projects",
    "open_asks",
    "links",
    "conflicts",
    "exceptions",
    "admissions",
    "budgets",
    "sieve_score",
    "digest",
];
fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    let mut matching = entries.iter().filter(|(k, _)| k.as_str() == Some(name));
    let value = &matching.next()?.1;
    matching.next().is_none().then_some(value)
}

/// A strict, bounded row grammar. No duplicate or unknown keys/roles, no
/// silent fallback on malformed authority configuration.
pub(crate) fn parse(value: &Value) -> Option<Vec<Row>> {
    let Value::Array(values) = value else {
        return None;
    };
    let mut rows = Vec::with_capacity(values.len());
    for value in values {
        let Value::Map(entries) = value else {
            return None;
        };
        if entries.iter().any(|(k, _)| {
            !matches!(
                k.as_str(),
                Some(
                    "role"
                        | "holder_ref"
                        | "sections"
                        | "max_sections"
                        | "max_predicates"
                        | "max_edge_kinds"
                        | "max_rows"
                )
            )
        }) {
            return None;
        }
        let role = field(entries, "role")?.as_str()?;
        if !matches!(role, "person" | "owner" | "agent") {
            return None;
        }
        let holder = if entries
            .iter()
            .any(|(k, _)| k.as_str() == Some("holder_ref"))
        {
            let text = field(entries, "holder_ref")?.as_str()?;
            let id = EntityId::from_hex(text).ok()?;
            if id.to_hex() != text {
                return None;
            }
            Some(id)
        } else {
            None
        };
        let Value::Array(sections) = field(entries, "sections")? else {
            return None;
        };
        if sections.len() > SECTION_NAMES.len() {
            return None;
        }
        let mut allowed = BTreeSet::new();
        for section in sections {
            let name = section.as_str()?;
            if !SECTION_NAMES.contains(&name) || !allowed.insert(name.to_string()) {
                return None;
            }
        }
        let ceiling = |name| -> Option<usize> {
            let n = usize::try_from(field(entries, name)?.as_u64()?).ok()?;
            (n > 0).then_some(n)
        };
        let row = Row {
            role: role.into(),
            holder,
            sections: allowed,
            max_sections: ceiling("max_sections")?,
            max_predicates: ceiling("max_predicates")?,
            max_edge_kinds: ceiling("max_edge_kinds")?,
            max_rows: ceiling("max_rows")?,
        };
        if rows
            .iter()
            .any(|old: &Row| old.role == row.role && old.holder == row.holder)
        {
            return None;
        }
        rows.push(row);
    }
    Some(rows)
}

#[cfg(test)]
mod tests;
