//! Closed PACK.md manifest parser. Requested powers stay data until local admission.
use std::collections::BTreeSet;

use super::invalid;
use crate::error::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackKind {
    Capability,
    Connector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackAdapter {
    Builtin(String),
    Script(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackManifest {
    pub name: String,
    pub description: String,
    pub version: String,
    pub license: Option<String>,
    pub kind: PackKind,
    pub adapter: Option<PackAdapter>,
    /// Predicate declarations are byteless. They never allocate a type byte.
    pub predicates: BTreeSet<String>,
    /// Runtime structural shapes, by global name; handles are local, never in PACK.md.
    pub kinds: BTreeSet<String>,
    pub requested_grants: BTreeSet<String>,
    pub wake_subscriptions: BTreeSet<String>,
}

impl PackManifest {
    pub(super) fn parse(text: &str) -> Result<Self> {
        let front = super::super::folder::source_frontmatter(text)?
            .ok_or_else(|| invalid("PACK.md requires frontmatter"))?;
        let mut fields = std::collections::BTreeMap::new();
        for line in front.lines() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with(char::is_whitespace) {
                return Err(invalid("nested PACK.md YAML requires normalization"));
            }
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| invalid("invalid manifest field"))?;
            if !matches!(
                key,
                "name"
                    | "description"
                    | "version"
                    | "license"
                    | "kind"
                    | "adapter"
                    | "predicates"
                    | "kinds"
                    | "grants"
                    | "wakes"
            ) {
                return Err(invalid("unknown PACK.md field"));
            }
            if fields.insert(key, value.trim()).is_some() {
                return Err(invalid("duplicate PACK.md field"));
            }
        }
        let required = |key| {
            fields
                .get(key)
                .ok_or_else(|| invalid("missing manifest field"))
                .and_then(|value| scalar(value))
        };
        let list = |key| -> Result<BTreeSet<String>> {
            let Some(value) = fields.get(key) else {
                return Ok(BTreeSet::new());
            };
            let entries: Vec<String> = serde_json::from_str(value)
                .map_err(|_| invalid("manifest list must be a JSON string array"))?;
            if entries.len() > 128 {
                return Err(invalid("manifest list too long"));
            }
            let mut set = BTreeSet::new();
            for entry in entries {
                if entry.is_empty()
                    || entry.len() > 256
                    || entry.chars().any(char::is_control)
                    || !set.insert(entry)
                {
                    return Err(invalid("invalid or duplicate manifest list entry"));
                }
            }
            Ok(set)
        };
        let kind = match required("kind")?.as_str() {
            "capability" => PackKind::Capability,
            "connector" => PackKind::Connector,
            _ => return Err(invalid("unsupported pack kind")),
        };
        let adapter = fields
            .get("adapter")
            .map(|value| -> Result<_> {
                let value = scalar(value)?;
                if let Some(name) = value.strip_prefix("built-in:") {
                    if name.is_empty()
                        || name.len() > 256
                        || !name.bytes().all(|b| {
                            b.is_ascii_lowercase()
                                || b.is_ascii_digit()
                                || matches!(b, b'.' | b'_' | b'-')
                        })
                    {
                        return Err(invalid("invalid built-in adapter name"));
                    }
                    Ok(PackAdapter::Builtin(name.to_owned()))
                } else if let Some(path) = value.strip_prefix("script:") {
                    if !path.starts_with("scripts/") {
                        return Err(invalid("adapter script must be under scripts/"));
                    }
                    Ok(PackAdapter::Script(path.to_owned()))
                } else {
                    Err(invalid("adapter must name built-in or script"))
                }
            })
            .transpose()?;
        if kind == PackKind::Connector && adapter.is_none() {
            return Err(invalid("connector pack requires an adapter"));
        }
        let name = required("name")?;
        validate_name(&name)?;
        let predicates = list("predicates")?;
        let kinds = list("kinds")?;
        for declaration in predicates.iter().chain(&kinds) {
            validate_name(declaration)?;
            if !declaration.starts_with(&format!("{name}.")) {
                return Err(invalid("declaration must be in the pack namespace"));
            }
        }
        if predicates.iter().any(|name| kinds.contains(name)) {
            return Err(invalid("predicate and structural names must be disjoint"));
        }
        Ok(Self {
            name,
            description: required("description")?,
            version: required("version")?,
            license: fields.get("license").map(|v| scalar(v)).transpose()?,
            kind,
            adapter,
            predicates,
            kinds,
            requested_grants: list("grants")?,
            wake_subscriptions: list("wakes")?,
        })
    }
}
fn scalar(value: &str) -> Result<String> {
    let text: String = if value.starts_with('"') {
        serde_json::from_str(value).map_err(|_| invalid("invalid quoted scalar"))?
    } else {
        if value
            .chars()
            .any(|c| matches!(c, '\'' | '&' | '*' | '!' | '{' | '[' | '|' | '>' | '#'))
        {
            return Err(invalid("unsupported YAML scalar"));
        }
        value.to_owned()
    };
    if text.is_empty() || text.len() > 4096 || text.chars().any(char::is_control) {
        return Err(invalid("invalid manifest scalar"));
    }
    Ok(text)
}
fn validate_name(name: &str) -> Result<()> {
    if name.len() > 256
        || !name.contains('.')
        || name.split('.').any(|part| {
            part.is_empty()
                || !part.as_bytes()[0].is_ascii_lowercase()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        })
    {
        return Err(invalid(
            "pack identities must be author-scoped lowercase names",
        ));
    }
    Ok(())
}
