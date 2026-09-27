//! Typed behaviour values and deterministic, scoped manifest-row selection.

use crate::entity_id::EntityId;
use rmpv::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum PolicyValueKey {
    CommOptOutPosture,
    ProposalCheckThreshold,
    ScopePrecedence,
}
impl PolicyValueKey {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "comm_opt_out_posture" => Some(Self::CommOptOutPosture),
            "proposal_check_threshold" => Some(Self::ProposalCheckThreshold),
            "scope_precedence" => Some(Self::ScopePrecedence),
            _ => None,
        }
    }
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::CommOptOutPosture => "comm_opt_out_posture",
            Self::ProposalCheckThreshold => "proposal_check_threshold",
            Self::ScopePrecedence => "scope_precedence",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PolicyPrecedence {
    NestedNarrowing,
    MostSpecific,
}
impl PolicyPrecedence {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "nested_narrowing" => Some(Self::NestedNarrowing),
            "most_specific" => Some(Self::MostSpecific),
            _ => None,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::NestedNarrowing => "nested_narrowing",
            Self::MostSpecific => "most_specific",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PolicyValue {
    CommOptOutPosture(crate::gate::resolution::CommOptOutPosture),
    ProposalCheckThreshold(u64),
    ScopePrecedence(PolicyPrecedence),
}
impl PolicyValue {
    fn restrict(self, other: Self) -> Self {
        match (self, other) {
            (Self::CommOptOutPosture(a), Self::CommOptOutPosture(b)) => {
                Self::CommOptOutPosture(a.restrict(b))
            }
            (Self::ProposalCheckThreshold(a), Self::ProposalCheckThreshold(b)) => {
                Self::ProposalCheckThreshold(a.min(b))
            }
            _ => unreachable!("policy values for different keys never compose"),
        }
    }

    pub(super) fn as_str(self) -> String {
        match self {
            Self::CommOptOutPosture(value) => value.as_str().to_owned(),
            Self::ProposalCheckThreshold(value) => value.to_string(),
            Self::ScopePrecedence(value) => value.as_str().to_owned(),
        }
    }
}

/// The hierarchy is a precedence rule for policy, not the six-axis authority
/// Scope lattice. The caller's context must come from trusted write facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum PolicyRowScope {
    Vault,
    World(EntityId),
    Project(EntityId),
    SubProject(EntityId),
    Thread(EntityId),
}
impl PolicyRowScope {
    fn rank(self, context: &PolicyEvaluationScope) -> Option<u8> {
        match self {
            Self::Vault => Some(0),
            Self::World(id) if context.world == Some(id) => Some(1),
            Self::Project(id) if context.project == Some(id) => Some(2),
            Self::SubProject(id) if context.subproject == Some(id) && context.project.is_some() => {
                Some(3)
            }
            Self::Thread(id) if context.thread == Some(id) && context.project.is_some() => Some(4),
            _ => None,
        }
    }
    pub(super) fn evaluation_context(self) -> PolicyEvaluationScope {
        match self {
            Self::Vault => PolicyEvaluationScope::default(),
            Self::World(id) => PolicyEvaluationScope {
                world: Some(id),
                ..Default::default()
            },
            Self::Project(id) => PolicyEvaluationScope {
                project: Some(id),
                ..Default::default()
            },
            Self::SubProject(id) => PolicyEvaluationScope {
                subproject: Some(id),
                ..Default::default()
            },
            Self::Thread(id) => PolicyEvaluationScope {
                thread: Some(id),
                ..Default::default()
            },
        }
    }
    pub(super) fn as_str(self) -> String {
        match self {
            Self::Vault => "vault".to_owned(),
            Self::World(id) => format!("world:{}", id.to_hex()),
            Self::Project(id) => format!("project:{}", id.to_hex()),
            Self::SubProject(id) => format!("sub_project:{}", id.to_hex()),
            Self::Thread(id) => format!("thread:{}", id.to_hex()),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicyEvaluationScope {
    pub(crate) world: Option<EntityId>,
    pub(crate) project: Option<EntityId>,
    pub(crate) subproject: Option<EntityId>,
    pub(crate) thread: Option<EntityId>,
    /// The caller has not been authorized to learn this world exists.
    pub(crate) hidden_world: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WhySource {
    Owner,
    Drafted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyWhy {
    pub(crate) text: String,
    pub(crate) source: WhySource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PolicyValueRow {
    pub(super) row_ref: String,
    pub(super) key: PolicyValueKey,
    pub(super) value: PolicyValue,
    pub(super) scope: PolicyRowScope,
    pub(super) why: Option<PolicyWhy>,
    pub(super) override_parent: bool,
}

impl PolicyValueRow {
    /// Model output fills an empty explanation, never an owner-authored one.
    pub(super) fn accept_draft_why(&mut self, text: &str) -> bool {
        if self.why.is_some() || text.trim().is_empty() || text.len() > 4096 {
            return false;
        }
        self.why = Some(PolicyWhy {
            text: text.to_owned(),
            source: WhySource::Drafted,
        });
        true
    }
    pub(super) fn set_owner_why(&mut self, text: &str) -> bool {
        if text.trim().is_empty() || text.len() > 4096 {
            return false;
        }
        self.why = Some(PolicyWhy {
            text: text.to_owned(),
            source: WhySource::Owner,
        });
        true
    }
}

fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    let mut values = entries.iter().filter(|(key, _)| key.as_str() == Some(name));
    let value = &values.next()?.1;
    values.next().is_none().then_some(value)
}

pub(crate) fn parse_optional_why(entries: &[(Value, Value)]) -> Option<Option<PolicyWhy>> {
    match entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("why"))
        .count()
    {
        0 => Some(None),
        1 => {
            let Value::Map(fields) = field(entries, "why")? else {
                return None;
            };
            if fields.len() != 2 {
                return None;
            }
            let text = field(fields, "text")?.as_str()?;
            if text.trim().is_empty() || text.len() > 4096 {
                return None;
            }
            let source = match field(fields, "source")?.as_str()? {
                "owner" => WhySource::Owner,
                "drafted" => WhySource::Drafted,
                _ => return None,
            };
            Some(Some(PolicyWhy {
                text: text.to_owned(),
                source,
            }))
        }
        _ => None,
    }
}

pub(super) fn parse_policy_values(value: &Value) -> Option<Vec<PolicyValueRow>> {
    let Value::Array(rows) = value else {
        return None;
    };
    rows.iter()
        .map(|row| {
            let Value::Map(entries) = row else {
                return None;
            };
            if !(4..=6).contains(&entries.len())
                || entries.iter().any(|(key, _)| {
                    !matches!(
                        key.as_str(),
                        Some("row_ref" | "key" | "value" | "scope" | "why" | "override_parent")
                    )
                })
            {
                return None;
            }
            let row_ref = field(entries, "row_ref")?.as_str()?;
            if row_ref.is_empty()
                || row_ref.len() > 96
                || !row_ref.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
            {
                return None;
            }
            let key = PolicyValueKey::parse(field(entries, "key")?.as_str()?)?;
            let raw = field(entries, "value")?;
            let value = match key {
                PolicyValueKey::CommOptOutPosture => {
                    PolicyValue::CommOptOutPosture(match raw.as_str()? {
                        "escalate" => crate::gate::resolution::CommOptOutPosture::Escalate,
                        "allow_with_receipt" => {
                            crate::gate::resolution::CommOptOutPosture::AllowWithReceipt
                        }
                        _ => return None,
                    })
                }
                PolicyValueKey::ProposalCheckThreshold => {
                    PolicyValue::ProposalCheckThreshold(raw.as_u64().filter(|v| *v > 0)?)
                }
                PolicyValueKey::ScopePrecedence => {
                    PolicyValue::ScopePrecedence(PolicyPrecedence::parse(raw.as_str()?)?)
                }
            };
            let Value::Map(scope_entries) = field(entries, "scope")? else {
                return None;
            };
            let scope = match field(scope_entries, "level")?.as_str()? {
                "vault" if scope_entries.len() == 1 => PolicyRowScope::Vault,
                level @ ("world" | "project" | "sub_project" | "thread")
                    if scope_entries.len() == 2 =>
                {
                    let reference = field(scope_entries, "ref")?.as_str()?;
                    let id = EntityId::from_hex(reference).ok()?;
                    if id.to_hex() != reference {
                        return None;
                    }
                    match level {
                        "world" => PolicyRowScope::World(id),
                        "project" => PolicyRowScope::Project(id),
                        "sub_project" => PolicyRowScope::SubProject(id),
                        _ => PolicyRowScope::Thread(id),
                    }
                }
                _ => return None,
            };
            if key == PolicyValueKey::ScopePrecedence && scope != PolicyRowScope::Vault {
                return None;
            }
            let why = parse_optional_why(entries)?;
            let override_parent = match entries
                .iter()
                .filter(|(k, _)| k.as_str() == Some("override_parent"))
                .count()
            {
                0 => false,
                1 => match field(entries, "override_parent")? {
                    Value::Boolean(value) => *value,
                    _ => return None,
                },
                _ => return None,
            };
            if override_parent
                && (key == PolicyValueKey::ScopePrecedence || scope == PolicyRowScope::Vault)
            {
                return None;
            }
            Some(PolicyValueRow {
                row_ref: row_ref.to_owned(),
                key,
                value,
                scope,
                why,
                override_parent,
            })
        })
        .collect()
}

pub(super) fn resolve_row<'a>(
    rows: &'a [PolicyValueRow],
    key: PolicyValueKey,
    context: &PolicyEvaluationScope,
) -> Option<&'a PolicyValueRow> {
    rows.iter()
        .filter(|row| row.key == key)
        .filter_map(|row| row.scope.rank(context).map(|rank| (rank, row)))
        .max_by_key(|(rank, _)| *rank)
        .map(|(_, row)| row)
}

/// Effective value and the row that actually determined it. A child row that
/// only repeats or relaxes its parent is not the deciding row under narrowing.
pub(super) struct ResolvedPolicyValue<'a> {
    pub(super) value: PolicyValue,
    pub(super) deciding_row: Option<&'a PolicyValueRow>,
}

/// Bootstrap reads shipped DATA, not an engine numeric or branch default.
/// A vault-scoped row is the only row that may select a precedence mode.
pub(super) fn shipped_default_precedence() -> PolicyPrecedence {
    let defaults: serde_json::Value =
        serde_json::from_str(include_str!("policy_value_defaults.json"))
            .expect("valid shipped policy defaults");
    let rows = defaults.as_array().expect("shipped policy rows");
    let value = rows
        .iter()
        .find(|row| row["key"] == "scope_precedence" && row["scope"]["level"] == "vault")
        .and_then(|row| row["value"].as_str())
        .expect("shipped vault-scope precedence row");
    PolicyPrecedence::parse(value).expect("shipped precedence token")
}

pub(super) fn shipped_default_comm_opt_out_posture() -> crate::gate::resolution::CommOptOutPosture {
    let defaults: serde_json::Value =
        serde_json::from_str(include_str!("policy_value_defaults.json"))
            .expect("valid shipped policy defaults");
    let value = defaults
        .as_array()
        .expect("shipped policy rows")
        .iter()
        .find(|row| row["key"] == "comm_opt_out_posture" && row["scope"]["level"] == "vault")
        .and_then(|row| row["value"].as_str())
        .expect("shipped opt-out posture");
    match value {
        "escalate" => crate::gate::resolution::CommOptOutPosture::Escalate,
        "allow_with_receipt" => crate::gate::resolution::CommOptOutPosture::AllowWithReceipt,
        _ => panic!("invalid shipped opt-out posture"),
    }
}

pub(super) fn shipped_default_proposal_check_threshold() -> u64 {
    let defaults: serde_json::Value =
        serde_json::from_str(include_str!("policy_value_defaults.json"))
            .expect("valid shipped policy defaults");
    defaults
        .as_array()
        .expect("shipped policy rows")
        .iter()
        .find(|row| row["key"] == "proposal_check_threshold" && row["scope"]["level"] == "vault")
        .and_then(|row| row["value"].as_u64())
        .filter(|value| *value > 0)
        .expect("shipped proposal check threshold")
}

pub(super) fn precedence_row(rows: &[PolicyValueRow]) -> Option<&PolicyValueRow> {
    rows.iter()
        .find(|row| row.key == PolicyValueKey::ScopePrecedence)
}

pub(super) fn resolve_value<'a>(
    rows: &'a [PolicyValueRow],
    key: PolicyValueKey,
    context: &PolicyEvaluationScope,
    precedence: PolicyPrecedence,
    fallback: PolicyValue,
) -> ResolvedPolicyValue<'a> {
    let mut candidates: Vec<_> = rows
        .iter()
        .filter(|row| row.key == key)
        .filter_map(|row| row.scope.rank(context).map(|rank| (rank, row)))
        .collect();
    candidates.sort_by_key(|(rank, _)| *rank);
    let (vault_value, vault_row) = match candidates.first() {
        Some((0, row)) => (row.value, Some(*row)),
        _ => (fallback, None),
    };
    let (mut value, mut deciding_row) = (vault_value, vault_row);
    match precedence {
        PolicyPrecedence::NestedNarrowing => {
            for (_, row) in candidates {
                let narrowed = if row.override_parent {
                    // A holder may release a parent's narrower bound but can
                    // never exceed the vault's own envelope.
                    row.value.restrict(vault_value)
                } else {
                    value.restrict(row.value)
                };
                if narrowed != value {
                    deciding_row = if row.override_parent && narrowed != row.value {
                        vault_row
                    } else {
                        Some(row)
                    };
                }
                value = narrowed;
            }
        }
        PolicyPrecedence::MostSpecific => {
            if let Some((_, most_specific)) = candidates.last() {
                // A changed precedence rule never bypasses the vault envelope.
                let capped = most_specific.value.restrict(vault_value);
                deciding_row = if capped == most_specific.value {
                    Some(*most_specific)
                } else {
                    vault_row
                };
                value = capped;
            }
        }
    }
    ResolvedPolicyValue {
        value,
        deciding_row,
    }
}

/// Fill the explanation of exactly one row in the current manifest bytes.
/// The owning write door authenticates the caller and rechecks policy power.
pub(crate) fn with_policy_why(
    mut data: &[u8],
    row_ref: &str,
    text: &str,
    drafted: bool,
) -> Option<Vec<u8>> {
    let mut value = rmpv::decode::read_value(&mut data).ok()?;
    let Value::Map(entries) = &mut value else {
        return None;
    };
    let (_, Value::Array(rows)) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("policy_values"))?
    else {
        return None;
    };
    let matches: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| match row {
            Value::Map(fields)
                if field(fields, "row_ref").and_then(Value::as_str) == Some(row_ref) =>
            {
                Some(index)
            }
            _ => None,
        })
        .collect();
    let [index] = matches.as_slice() else {
        return None;
    };
    let Value::Map(fields) = &mut rows[*index] else {
        return None;
    };
    let parsed = parse_policy_values(&Value::Array(vec![Value::Map(fields.clone())]))?;
    let mut row = parsed.into_iter().next()?;
    if drafted {
        if !row.accept_draft_why(text) {
            return None;
        }
    } else if !row.set_owner_why(text) {
        return None;
    }
    fields.retain(|(key, _)| key.as_str() != Some("why"));
    let source = if drafted { "drafted" } else { "owner" };
    fields.push((
        Value::from("why"),
        Value::Map(vec![
            (Value::from("text"), Value::from(text)),
            (Value::from("source"), Value::from(source)),
        ]),
    ));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).ok()?;
    Some(bytes)
}
