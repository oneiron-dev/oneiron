//! Typed manifest work budget for consolidation retries. This selects how
//! much *authorized* evidence to attempt, never whether a read is permitted.
use crate::llm::Scope;
use crate::{EntityId, Error, Result};
use rmpv::Value;
use std::num::NonZeroUsize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetrySelector {
    Vault,
    Holder(EntityId),
    Project(EntityId),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryPrecedence {
    NestedNarrowing,
    HolderOverride,
}
impl RetryPrecedence {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "nested_narrowing" => Some(Self::NestedNarrowing),
            "holder_override" => Some(Self::HolderOverride),
            _ => None,
        }
    }
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NestedNarrowing => "nested_narrowing",
            Self::HolderOverride => "holder_override",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetrySourcePolicyRow {
    pub(crate) selector: RetrySelector,
    pub(crate) max_sources: NonZeroUsize,
    pub(crate) precedence: Option<RetryPrecedence>,
}
impl RetrySourcePolicyRow {
    pub(crate) fn parse(value: &Value) -> Option<Self> {
        let Value::Map(fields) = value else {
            return None;
        };
        let mut selector = None;
        let mut source_id = None;
        let mut max_sources = None;
        let mut precedence = None;
        for (key, value) in fields {
            match key.as_str()? {
                "selector" if selector.is_none() => selector = Some(value.as_str()?.to_owned()),
                "source_id" if source_id.is_none() => {
                    let raw = value.as_str()?;
                    if raw.len() != 32
                        || !raw.bytes().all(|byte| byte.is_ascii_hexdigit())
                        || raw.bytes().any(|byte| byte.is_ascii_uppercase())
                    {
                        return None;
                    }
                    source_id = Some(EntityId::from_hex(raw).ok()?);
                }
                "max_sources" if max_sources.is_none() => {
                    max_sources = Some(NonZeroUsize::new(usize::try_from(value.as_u64()?).ok()?)?);
                }
                "precedence" if precedence.is_none() => {
                    precedence = Some(RetryPrecedence::parse(value.as_str()?)?);
                }
                _ => return None,
            }
        }
        let selector = match (selector?.as_str(), source_id) {
            ("vault", None) => RetrySelector::Vault,
            ("holder", Some(id)) => RetrySelector::Holder(id),
            ("project", Some(id)) => RetrySelector::Project(id),
            _ => return None,
        };
        if !matches!(selector, RetrySelector::Vault) && precedence.is_some() {
            return None;
        }
        Some(Self {
            selector,
            max_sources: max_sources?,
            precedence,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResolvedRetryBudget {
    max_sources: NonZeroUsize,
    pub(crate) precedence: RetryPrecedence,
}
impl ResolvedRetryBudget {
    pub(crate) fn max_sources(self) -> usize {
        self.max_sources.get()
    }
}

pub(crate) fn resolve(
    rows: &[RetrySourcePolicyRow],
    holder: EntityId,
    scope: Option<&Scope>,
) -> Result<ResolvedRetryBudget> {
    let mut vault_cap = None::<NonZeroUsize>;
    let mut holder_cap = None::<NonZeroUsize>;
    let mut scope_cap = None::<NonZeroUsize>;
    let mut holder_override = true;
    for row in rows {
        let slot = match row.selector {
            RetrySelector::Vault => {
                holder_override &= row.precedence.unwrap_or(RetryPrecedence::NestedNarrowing)
                    == RetryPrecedence::HolderOverride;
                &mut vault_cap
            }
            RetrySelector::Holder(id) if id == holder => &mut holder_cap,
            RetrySelector::Project(id) if scope.is_some_and(|scope| scope.project == Some(id)) => {
                &mut scope_cap
            }
            _ => continue,
        };
        *slot = Some(slot.map_or(row.max_sources, |old| old.min(row.max_sources)));
    }
    // A required vault row cannot be invented by a caller or by an accessor.
    let vault_cap = vault_cap.ok_or_else(|| {
        Error::InvalidConfig("missing required Dreamer retry source policy".into())
    })?;
    let selected = if holder_override && let Some(holder_cap) = holder_cap {
        holder_cap
    } else {
        [holder_cap, scope_cap]
            .into_iter()
            .flatten()
            .fold(vault_cap, std::cmp::Ord::min)
    };
    Ok(ResolvedRetryBudget {
        max_sources: selected.min(vault_cap),
        precedence: if holder_override {
            RetryPrecedence::HolderOverride
        } else {
            RetryPrecedence::NestedNarrowing
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_or_missing_required_rows_never_invent_a_budget() {
        let holder = EntityId::from_bytes([0xab; 16]).expect("holder");
        let row = |fields: Vec<(&str, Value)>| {
            Value::Map(
                fields
                    .into_iter()
                    .map(|(key, value)| (Value::from(key), value))
                    .collect(),
            )
        };
        assert!(
            RetrySourcePolicyRow::parse(&row(vec![
                ("selector", "vault".into()),
                ("max_sources", 0_u64.into())
            ]))
            .is_none()
        );
        assert!(
            RetrySourcePolicyRow::parse(&row(vec![
                ("selector", "vault".into()),
                ("max_sources", 1_u64.into()),
                ("max_sources", 2_u64.into())
            ]))
            .is_none()
        );
        assert!(
            RetrySourcePolicyRow::parse(&row(vec![
                ("selector", "holder".into()),
                ("source_id", holder.to_hex().to_uppercase().into()),
                ("max_sources", 2_u64.into())
            ]))
            .is_none()
        );
        assert!(
            RetrySourcePolicyRow::parse(&row(vec![
                ("selector", "project".into()),
                ("max_sources", 2_u64.into())
            ]))
            .is_none()
        );
        assert!(resolve(&[], holder, None).is_err());
        let holder_only = RetrySourcePolicyRow::parse(&row(vec![
            ("selector", "holder".into()),
            ("source_id", holder.to_hex().into()),
            ("max_sources", 2_u64.into()),
        ]))
        .expect("typed holder row");
        assert!(
            resolve(&[holder_only], holder, None).is_err(),
            "a holder never supplies a missing vault policy"
        );
    }
}
