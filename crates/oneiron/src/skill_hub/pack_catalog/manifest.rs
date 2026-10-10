//! Closed PACK.md manifest parser. Requested powers stay data until local admission.
use std::collections::{BTreeMap, BTreeSet};

use super::{AgentPackFacets, invalid};
use crate::error::Result;
use crate::saved_query::{PackMigrationMap, PackPredicateRewrite};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackKind {
    Capability,
    Connector,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    /// Named, typed facet paths for the inert agent-pack container.
    pub agent_facets: Option<AgentPackFacets>,
    /// Predicate declarations are byteless. They never allocate a type byte.
    pub predicates: BTreeSet<String>,
    /// Runtime structural shapes, by global name; handles are local, never in PACK.md.
    pub kinds: BTreeSet<String>,
    pub requested_grants: BTreeSet<String>,
    pub wake_subscriptions: BTreeSet<String>,
    /// Predicate migration maps this source ships for moves from earlier
    /// sources of the pack (ARCH-0059 §4, rung 1).
    pub migrations: Vec<PackMigration>,
}

/// One shipped migration map: the rewrites that carry a saved query from an
/// earlier source of this pack to this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMigration {
    /// The version the move starts from.
    pub from: String,
    /// The exact source the move starts from, by content hash. Required
    /// when `from` is this source's own version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Old predicate to its rewrite.
    pub rewrites: BTreeMap<String, PackPredicateRewrite>,
}

impl PackManifest {
    /// The map this source ships for a move from the installed source
    /// `content_hash` of `version`: the entry naming that exact source, else
    /// the one naming its version alone.
    #[must_use]
    pub fn migration_from(&self, version: &str, content_hash: &str) -> Option<PackMigrationMap> {
        let from_version = self.migrations.iter().filter(|entry| entry.from == version);
        from_version
            .clone()
            .find(|entry| entry.source.as_deref() == Some(content_hash))
            .or_else(|| from_version.clone().find(|entry| entry.source.is_none()))
            .map(|entry| PackMigrationMap {
                rewrites: entry.rewrites.clone(),
            })
    }
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
                    | "facets"
                    | "migrations"
            ) {
                return Err(invalid("unknown PACK.md field"));
            }
            if fields.insert(key, value.trim()).is_some() {
                return Err(invalid("duplicate PACK.md field"));
            }
        }
        let required = |key, allow_controls| {
            fields
                .get(key)
                .ok_or_else(|| invalid("missing manifest field"))
                .and_then(|value| scalar(value, allow_controls))
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
        let kind = match required("kind", false)?.as_str() {
            "capability" => PackKind::Capability,
            "connector" => PackKind::Connector,
            "agent" => PackKind::Agent,
            _ => return Err(invalid("unsupported pack kind")),
        };
        let adapter = fields
            .get("adapter")
            .map(|value| -> Result<_> {
                let value = scalar(value, false)?;
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
        let agent_facets = fields
            .get("facets")
            .map(|value| {
                serde_json::from_str::<AgentPackFacets>(value)
                    .map_err(|_| invalid("agent facets must be a typed JSON object"))
            })
            .transpose()?;
        if kind == PackKind::Agent {
            agent_facets
                .as_ref()
                .ok_or_else(|| invalid("agent pack requires a facet map"))?
                .validate_paths()?;
            if adapter.is_some()
                || ["predicates", "kinds", "grants", "wakes", "migrations"]
                    .iter()
                    .any(|key| fields.contains_key(key))
            {
                return Err(invalid("agent pack cannot declare runtime powers"));
            }
        } else if agent_facets.is_some() {
            return Err(invalid("only agent packs declare agent facets"));
        }
        let name = required("name", kind == PackKind::Agent)?;
        if kind == PackKind::Agent {
            validate_agent_text(&name, 256)?;
        } else {
            validate_name(&name)?;
        }
        let description = required("description", kind == PackKind::Agent)?;
        let version = required("version", kind == PackKind::Agent)?;
        if kind == PackKind::Agent {
            validate_agent_text(&description, 4096)?;
            validate_agent_text(&version, 128)?;
        }
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
        let migrations = fields
            .get("migrations")
            .map(|value| {
                serde_json::from_str::<Vec<PackMigration>>(value)
                    .map_err(|_| invalid("migrations must be a JSON array of typed maps"))
            })
            .transpose()?
            .unwrap_or_default();
        validate_migrations(&migrations, &name, &version, &predicates)?;
        Ok(Self {
            name,
            description,
            version,
            license: fields
                .get("license")
                .map(|v| scalar(v, false))
                .transpose()?,
            kind,
            adapter,
            agent_facets,
            predicates,
            kinds,
            requested_grants: list("grants")?,
            wake_subscriptions: list("wakes")?,
            migrations,
        })
    }
}
fn scalar(value: &str, allow_controls: bool) -> Result<String> {
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
    if text.is_empty()
        || text.len() > 4096
        || (!allow_controls && text.chars().any(char::is_control))
    {
        return Err(invalid("invalid manifest scalar"));
    }
    Ok(text)
}
/// A shipped map moves only the pack's own predicates, onto predicates this
/// source declares, and names each starting source once.
fn validate_migrations(
    migrations: &[PackMigration],
    name: &str,
    version: &str,
    predicates: &BTreeSet<String>,
) -> Result<()> {
    if migrations.len() > 32 {
        return Err(invalid("too many shipped migration maps"));
    }
    let mut starts = BTreeSet::new();
    for migration in migrations {
        let source_ok = migration.source.as_deref().is_none_or(|hash| {
            hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        });
        if migration.from.is_empty()
            || migration.from.len() > 128
            || migration.from.chars().any(char::is_control)
            || !source_ok
            || (migration.from == version && migration.source.is_none())
            || !starts.insert((&migration.from, &migration.source))
        {
            return Err(invalid(
                "a migration names a distinct starting version, and the exact source for its own",
            ));
        }
        if migration.rewrites.is_empty() || migration.rewrites.len() > 128 {
            return Err(invalid("a migration map holds 1 to 128 rewrites"));
        }
        for (from, rewrite) in &migration.rewrites {
            let (PackPredicateRewrite::Rename { to }
            | PackPredicateRewrite::Equivalent { to, .. }
            | PackPredicateRewrite::SemanticsChanging { to, .. }) = rewrite;
            let note_ok = match rewrite {
                PackPredicateRewrite::Rename { .. } => true,
                PackPredicateRewrite::Equivalent { note, .. }
                | PackPredicateRewrite::SemanticsChanging { note, .. } => {
                    !note.is_empty() && note.len() <= 1024 && !note.chars().any(char::is_control)
                }
            };
            validate_name(from)?;
            if !from.starts_with(&format!("{name}.")) || !predicates.contains(to) || !note_ok {
                return Err(invalid(
                    "a migration rewrites the pack's own predicates onto ones it declares",
                ));
            }
        }
    }
    Ok(())
}
fn validate_agent_text(value: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(invalid(
            "agent manifest text is blank or exceeds the native bound",
        ));
    }
    Ok(())
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
