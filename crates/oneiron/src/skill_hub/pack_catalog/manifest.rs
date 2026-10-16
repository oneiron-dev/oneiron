//! Closed PACK.md manifest parser. Requested powers stay data until local admission.
use std::collections::{BTreeMap, BTreeSet};

use super::migrations::PackMigration;
use super::setup::PackSetup;
use super::{AgentPackFacets, invalid};
use crate::error::Result;
use crate::saved_query::PackMigrationMap;
use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
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
    /// An address for removal or defect requests (hub folder contract,
    /// 2026-09-22). Display text only; it grants nothing.
    pub contact: Option<String>,
    pub kind: PackKind,
    pub adapter: Option<PackAdapter>,
    /// Named, typed facet paths for the inert agent-pack container.
    pub agent_facets: Option<AgentPackFacets>,
    /// Predicate declarations are byteless. They never allocate a type byte.
    pub predicates: BTreeSet<String>,
    /// Runtime structural shapes, by global name; handles are local, never in PACK.md.
    pub kinds: BTreeSet<String>,
    pub requested_grants: BTreeSet<String>,
    /// Effect classes this pack's actions can fall in, by their engine
    /// action-class names (`browser.send`, `browser.pay`, ...). The vault's
    /// grant for a class sets its press; declaring a class grants nothing.
    pub effects: BTreeSet<String>,
    pub wake_subscriptions: BTreeSet<String>,
    /// Hook folders under `hooks/`, by name (ARCH-0053 §7, PACK-HOOKS = A).
    /// Install binds each one; the runner is L11's.
    pub hooks: BTreeSet<String>,
    /// Organ folders under `organs/`, by name (ARCH-0075 §9, OF-575). Each
    /// pins its builds by platform; the builds travel as blob assets.
    pub organs: BTreeSet<String>,
    /// Predicate migration maps this source ships for moves from earlier
    /// sources of the pack (ARCH-0059 §4, rung 1).
    pub migrations: Vec<PackMigration>,
    /// The accounts, connections, permissions and credential names the
    /// pack's guided setup walks the owner through (OF-378). Declaration
    /// only; it grants nothing.
    pub setup: Option<PackSetup>,
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
        let fields = frontmatter_fields(text)?;
        // The source scans read the raw file, where a JSON escape can hide a
        // credential; every decoded string gets both detectors again. A run
        // is joined text, not a record: both doors' text rules, no structured
        // reading.
        for (_, decoded) in decoded_fields(&fields) {
            for value in &decoded.strings {
                crate::batch::secret_scan::scan_metadata_field(value)?;
                if crate::batch::secret_scan::scan_file_content("PACK.md", value.as_bytes())
                    .is_some()
                {
                    return Err(invalid("pack source contains credential material"));
                }
            }
            if decoded
                .run
                .as_deref()
                .and_then(crate::batch::secret_scan::scan_joined_text)
                .is_some()
            {
                return Err(invalid("pack source contains credential material"));
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
                || [
                    "predicates",
                    "kinds",
                    "grants",
                    "effects",
                    "wakes",
                    "hooks",
                    "organs",
                    "migrations",
                    "setup",
                ]
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
        } else if !(name == super::LOCAL_PACK_NAME && kind == PackKind::Capability) {
            // The vault's own `local` pack is the one unscoped name.
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
        let effects = list("effects")?;
        for effect in &effects {
            validate_name(effect)?;
        }
        let hooks = list("hooks")?;
        for hook in &hooks {
            super::hooks::validate_hook_name(hook)?;
        }
        let organs = list("organs")?;
        if organs.len() > 32 {
            return Err(invalid("too many organs"));
        }
        for organ in &organs {
            super::organs::validate_organ_name(organ)?;
        }
        let migrations = fields
            .get("migrations")
            .map(|line| super::migrations::parse(line, &name, &version, &predicates))
            .transpose()?
            .unwrap_or_default();
        let requested_grants = list("grants")?;
        let setup = fields
            .get("setup")
            .map(|value| PackSetup::parse(value, kind, &requested_grants))
            .transpose()?;
        Ok(Self {
            name,
            description,
            version,
            license: fields
                .get("license")
                .map(|v| scalar(v, false))
                .transpose()?,
            contact: fields.get("contact").map(|v| contact(v)).transpose()?,
            kind,
            adapter,
            agent_facets,
            predicates,
            kinds,
            requested_grants,
            effects,
            wake_subscriptions: list("wakes")?,
            hooks,
            organs,
            migrations,
            setup,
        })
    }
}
/// The frontmatter's fields by key, each named once, with its raw value.
fn frontmatter_fields(text: &str) -> Result<BTreeMap<&str, &str>> {
    let front = super::super::folder::source_frontmatter(text)?
        .ok_or_else(|| invalid("PACK.md requires frontmatter"))?;
    let mut fields = BTreeMap::new();
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
                | "contact"
                | "kind"
                | "adapter"
                | "predicates"
                | "kinds"
                | "grants"
                | "effects"
                | "wakes"
                | "hooks"
                | "organs"
                | "facets"
                | "migrations"
                | "setup"
        ) {
            return Err(invalid("unknown PACK.md field"));
        }
        if fields.insert(key, value.trim()).is_some() {
            return Err(invalid("duplicate PACK.md field"));
        }
    }
    Ok(fields)
}
/// One frontmatter value as decoded, for the scans that must see past JSON
/// escapes.
pub(super) struct Decoded {
    /// Each string a JSON string, list or map holds, map keys and repeated
    /// keys included; any other value as written.
    pub(super) strings: Vec<String>,
    /// Several strings in order, one per line, as the raw file shows an
    /// unescaped list: a recovery phrase can be spread over a list's entries.
    /// Joined text, not a record.
    pub(super) run: Option<String>,
}
/// Every frontmatter field's text as decoded, by key.
pub(super) fn decoded_frontmatter(text: &str) -> Result<Vec<(&str, Decoded)>> {
    Ok(decoded_fields(&frontmatter_fields(text)?))
}
fn decoded_fields<'a>(fields: &BTreeMap<&'a str, &str>) -> Vec<(&'a str, Decoded)> {
    fields
        .iter()
        .map(|(&key, value)| {
            let strings = match serde_json::from_str::<Strings>(value) {
                Ok(Strings(strings)) if value.starts_with(['"', '[', '{']) => strings,
                _ => vec![(*value).to_owned()],
            };
            let run = (strings.len() > 1).then(|| strings.join("\n"));
            (key, Decoded { strings, run })
        })
        .collect()
}
/// Every string a JSON value holds, decoded as serde_json decodes it.
struct Strings(Vec<String>);

impl<'de> Deserialize<'de> for Strings {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Walk;
        impl<'de> Visitor<'de> for Walk {
            type Value = Vec<String>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value")
            }
            fn visit_bool<E>(self, _: bool) -> std::result::Result<Vec<String>, E> {
                Ok(Vec::new())
            }
            fn visit_i64<E>(self, _: i64) -> std::result::Result<Vec<String>, E> {
                Ok(Vec::new())
            }
            fn visit_u64<E>(self, _: u64) -> std::result::Result<Vec<String>, E> {
                Ok(Vec::new())
            }
            fn visit_f64<E>(self, _: f64) -> std::result::Result<Vec<String>, E> {
                Ok(Vec::new())
            }
            fn visit_unit<E>(self) -> std::result::Result<Vec<String>, E> {
                Ok(Vec::new())
            }
            fn visit_str<E>(self, value: &str) -> std::result::Result<Vec<String>, E> {
                Ok(vec![value.to_owned()])
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Vec<String>, A::Error> {
                let mut strings = Vec::new();
                while let Some(Strings(item)) = seq.next_element()? {
                    strings.extend(item);
                }
                Ok(strings)
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Vec<String>, A::Error> {
                let mut strings = Vec::new();
                while let Some(Strings(key)) = map.next_key()? {
                    strings.extend(key);
                    let Strings(value) = map.next_value()?;
                    strings.extend(value);
                }
                Ok(strings)
            }
        }
        deserializer.deserialize_any(Walk).map(Strings)
    }
}
pub(super) fn scalar(value: &str, allow_controls: bool) -> Result<String> {
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
const CONTACT_MAX_BYTES: usize = 512;
fn contact(value: &str) -> Result<String> {
    let text = scalar(value, false)?;
    if text.trim().is_empty() || text.len() > CONTACT_MAX_BYTES {
        return Err(invalid("PACK.md contact is blank or exceeds its bound"));
    }
    Ok(text)
}
fn validate_agent_text(value: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(invalid(
            "agent manifest text is blank or exceeds the native bound",
        ));
    }
    Ok(())
}
pub(super) fn validate_name(name: &str) -> Result<()> {
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
