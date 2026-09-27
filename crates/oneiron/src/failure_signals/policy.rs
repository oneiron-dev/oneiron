//! Versioned tier-1 aggregation dials from trusted POLICY_MANIFEST rows.
//! Larger buckets are the privacy-narrowing direction; shorter component
//! limits are the admission-narrowing direction. Both are resolved per write.

use rmpv::Value;

use crate::entity_id::EntityId;

/// Defaults shipped in the engine's seeded POLICY_MANIFEST row.
pub(crate) const POLICY_KEY: &str = "failure_signal_policy";
pub(crate) const DEFAULT_BUCKET_SECONDS: u64 = 3_600;
pub(crate) const DEFAULT_COMPONENT_BYTES: u64 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Precedence {
    NestedNarrowing,
    HolderOverride,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    Default,
    Vault,
    Holder(EntityId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) scope: Scope,
    pub(crate) bucket_seconds: u64,
    pub(crate) max_component_bytes: u64,
    pub(crate) precedence: Precedence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub(crate) bucket_seconds: u64,
    pub(crate) max_component_bytes: u64,
}

impl Default for Resolved {
    fn default() -> Self {
        Self {
            bucket_seconds: DEFAULT_BUCKET_SECONDS,
            max_component_bytes: DEFAULT_COMPONENT_BYTES,
        }
    }
}

impl Resolved {
    fn narrow(self, other: Self) -> Self {
        Self {
            bucket_seconds: self.bucket_seconds.max(other.bucket_seconds),
            max_component_bytes: self.max_component_bytes.min(other.max_component_bytes),
        }
    }
}

/// Strict map grammar; malformed or duplicated policy declarations refuse the
/// entire manifest at the shared decoder, never fall back to a wider default.
pub(crate) fn decode(value: &Value) -> Option<Vec<Row>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut decoded = Vec::new();
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        if entries.len() != 4 && entries.len() != 5 {
            return None;
        }
        let mut scope = None;
        let mut holder_ref = None;
        let mut bucket_seconds = None;
        let mut max_component_bytes = None;
        let mut precedence = None;
        for (key, val) in entries {
            match key.as_str()? {
                "scope" if scope.is_none() => scope = Some(val.as_str()?),
                "holder_ref" if holder_ref.is_none() => {
                    holder_ref = Some(EntityId::from_hex(val.as_str()?).ok()?);
                }
                "bucket_seconds" if bucket_seconds.is_none() => {
                    bucket_seconds =
                        Some(val.as_u64().filter(|n| *n > 0 && *n <= i64::MAX as u64)?);
                }
                "max_component_bytes" if max_component_bytes.is_none() => {
                    max_component_bytes = Some(val.as_u64().filter(|n| *n > 0)?);
                }
                "precedence" if precedence.is_none() => {
                    precedence = Some(match val.as_str()? {
                        "nested_narrowing" => Precedence::NestedNarrowing,
                        "holder_override" => Precedence::HolderOverride,
                        _ => return None,
                    });
                }
                _ => return None,
            }
        }
        let scope = match (scope?, holder_ref) {
            ("default", None) => Scope::Default,
            ("vault", None) => Scope::Vault,
            ("holder", Some(id)) => Scope::Holder(id),
            _ => return None,
        };
        decoded.push(Row {
            scope,
            bucket_seconds: bucket_seconds?,
            max_component_bytes: max_component_bytes?,
            precedence: precedence?,
        });
    }
    Some(decoded)
}

/// Compose trusted rows independent of manifest enumeration order. The
/// holder-override mode takes its holder's values (rather than inherited
/// nested defaults), but the vault ceiling still caps it. No holder row ever
/// widens the explicit vault bounds.
pub(crate) fn resolve(rows: &[Row], holder: Option<EntityId>) -> Resolved {
    let mut baseline = Resolved::default();
    let mut vault = None;
    let mut matched = None;
    let mut precedence = Precedence::NestedNarrowing;
    for row in rows {
        let values = Resolved {
            bucket_seconds: row.bucket_seconds,
            max_component_bytes: row.max_component_bytes,
        };
        match row.scope {
            Scope::Default => baseline = baseline.narrow(values),
            Scope::Vault => {
                vault = Some(vault.unwrap_or(values).narrow(values));
                if row.precedence == Precedence::HolderOverride {
                    precedence = row.precedence;
                }
            }
            Scope::Holder(id) if holder == Some(id) => {
                matched = Some(matched.unwrap_or(values).narrow(values));
            }
            Scope::Holder(_) => {}
        }
    }
    let vault_cap = vault.unwrap_or(baseline);
    match (precedence, matched) {
        (Precedence::NestedNarrowing, Some(holder_row)) => {
            baseline.narrow(vault_cap).narrow(holder_row)
        }
        (Precedence::NestedNarrowing, None) => baseline.narrow(vault_cap),
        (Precedence::HolderOverride, Some(holder_row)) => vault_cap.narrow(holder_row),
        (Precedence::HolderOverride, None) => vault_cap,
    }
}

pub(crate) fn default_row() -> Value {
    Value::Array(vec![Value::Map(vec![
        (Value::from("scope"), Value::from("default")),
        (
            Value::from("bucket_seconds"),
            Value::from(DEFAULT_BUCKET_SECONDS),
        ),
        (
            Value::from("max_component_bytes"),
            Value::from(DEFAULT_COMPONENT_BYTES),
        ),
        (Value::from("precedence"), Value::from("nested_narrowing")),
    ])])
}
