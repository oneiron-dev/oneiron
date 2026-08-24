//! SECRET-01 (ONE-1919) repo-side secret manifest — declaration + narrow-only
//! validation (ARCH-0069 S2).
//!
//! A repo carries a `SecretManifest` that **declares** which secrets exist,
//! their custody classes, the effector bindings (which effector may use which
//! ref, at what tier ceiling), and the declared secret *paths* (consumed by
//! SECRET-03 for snapshot exclusion). The manifest may only **NARROW**
//! relative to the vault floors: every declared entry must fit inside the
//! [`SecretCustodyFloor`] band for its class, and every binding's tier
//! ceiling must be ≤ the floor's max. A manifest that asks for more exposure
//! than the floor allows fails with
//! [`Error::ManifestWidensFloor`]; a narrower manifest is stored with its
//! narrow binding.
//!
//! The merge rule is `manifest ∧ vault_floor` — most-restrictive wins. At
//! register time the manifest entry is copied onto the record
//! (`manifest_ref`, `declared_paths`, and the floor snapshot) so downstream
//! consumers have a vault-side data source; see
//! [`crate::Vault::register_secret`].

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::secret_custody::{CustodyClass, CustodyTier, SecretBinding, SecretCustodyFloor};

/// The repo-side secret manifest: a schema-versioned list of declared
/// entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretManifest {
    /// Manifest schema version (`SECRET_MANIFEST_SCHEMA_VERSION` at parse).
    pub schema_version: u16,
    /// The declared secret entries.
    pub secrets: Vec<SecretManifestEntry>,
}

/// One declared secret entry: name, custody class, effector bindings, and
/// declared paths (repo paths holding materializable values — SECRET-03
/// excludes these from snapshots).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretManifestEntry {
    /// The secret name (unique within the manifest).
    pub name: String,
    /// Its custody class.
    pub class: CustodyClass,
    /// Effector bindings (which effector may use this ref, at what ceiling).
    pub bindings: Vec<SecretBinding>,
    /// Repo paths holding materializable values; SECRET-03 reads these.
    pub declared_paths: Vec<String>,
}

/// The manifest schema version stamped at parse.
pub const SECRET_MANIFEST_SCHEMA_VERSION: u16 = 1;

/// Parses a `SecretManifest` from its TOML text form.
///
/// The manifest is line-oriented TOML: a top-level `schema_version` integer,
/// then one `[[secrets]]` table array per entry, each with `name`, `class`
/// (the canon kebab-case noun), a `declared_paths` string array, and inline
/// `[[secrets.bindings]]` tables with `effector`, `tier_ceiling` (integer
/// 0..=2), and a `scopes` string array. Unknown keys are ignored so the
/// format can grow. The parser is a deliberately small TOML subset — the
/// engine takes no `toml` crate dependency for this one file.
pub fn parse_secret_manifest(text: &str) -> Result<SecretManifest> {
    // Scratch shape during parse: class stays Option so a missing `class`
    // key is a typed error at finish, not a silent default.
    #[derive(Default)]
    struct ScratchEntry {
        name: String,
        class: Option<CustodyClass>,
        declared_paths: Vec<String>,
        bindings: Vec<ScratchBinding>,
    }
    #[derive(Default)]
    struct ScratchBinding {
        effector: String,
        tier_ceiling: Option<CustodyTier>,
        scopes: Vec<String>,
    }
    // Parser position: which table the next bare `key = value` row binds to.
    enum Scope {
        Root,
        Secrets,
        Binding,
    }

    let mut schema_version = None;
    let mut secrets = Vec::new();
    let mut scope = Scope::Root;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[secrets]]" {
            secrets.push(ScratchEntry::default());
            scope = Scope::Secrets;
            continue;
        }
        if line == "[[secrets.bindings]]" {
            let Some(entry) = secrets.last_mut() else {
                return Err(Error::InvalidSecretCustodyBody(
                    "[[secrets.bindings]] before any [[secrets]]",
                ));
            };
            entry.bindings.push(ScratchBinding::default());
            scope = Scope::Binding;
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(invalid_manifest("expected `key = value`"));
        };
        let key = key.trim();
        let value = value.trim();

        match scope {
            Scope::Root => {
                if key == "schema_version" {
                    schema_version = Some(parse_u16(value)?);
                }
            }
            Scope::Secrets => {
                let Some(entry) = secrets.last_mut() else {
                    return Err(invalid_manifest("row before any [[secrets]]"));
                };
                match key {
                    "name" => entry.name = parse_string(value)?,
                    "class" => {
                        // CustodyClass is canon-wire kebab-case in the manifest text.
                        let class_str = parse_string(value)?;
                        entry.class = Some(CustodyClass::parse(&class_str).ok_or(
                            Error::InvalidSecretCustodyBody("unknown custody class in manifest"),
                        )?);
                    }
                    "declared_paths" => entry.declared_paths = parse_string_array(value)?,
                    _ => {}
                }
            }
            Scope::Binding => {
                let Some(binding) = secrets.last_mut().and_then(|e| e.bindings.last_mut()) else {
                    return Err(invalid_manifest("row before any binding"));
                };
                match key {
                    "effector" => binding.effector = parse_string(value)?,
                    "tier_ceiling" => {
                        let n = parse_u8(value)?;
                        binding.tier_ceiling = Some(CustodyTier::from_u8(n).ok_or(
                            Error::InvalidSecretCustodyBody("unknown tier_ceiling in manifest"),
                        )?);
                    }
                    "scopes" => binding.scopes = parse_string_array(value)?,
                    _ => {}
                }
            }
        }
    }

    let schema_version = schema_version.ok_or(Error::InvalidSecretCustodyBody(
        "manifest missing schema_version",
    ))?;
    if schema_version != SECRET_MANIFEST_SCHEMA_VERSION {
        return Err(Error::InvalidSecretCustodyBody(
            "unsupported secret manifest schema version",
        ));
    }
    let secrets = secrets
        .into_iter()
        .map(|entry| {
            let class = entry.class.ok_or(Error::InvalidSecretCustodyBody(
                "manifest entry missing class",
            ))?;
            let bindings = entry
                .bindings
                .into_iter()
                .map(|b| {
                    Ok(SecretBinding {
                        effector: b.effector,
                        tier_ceiling: b.tier_ceiling.ok_or(Error::InvalidSecretCustodyBody(
                            "manifest binding missing tier_ceiling",
                        ))?,
                        scopes: b.scopes,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(SecretManifestEntry {
                name: entry.name,
                class,
                bindings,
                declared_paths: entry.declared_paths,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(SecretManifest {
        schema_version,
        secrets,
    })
}

fn invalid_manifest(msg: &'static str) -> Error {
    Error::InvalidSecretCustodyBody(msg)
}

fn parse_string(value: &str) -> Result<String> {
    let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
        return Err(invalid_manifest("expected a double-quoted string"));
    };
    Ok(inner.to_owned())
}

fn parse_u16(value: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .map_err(|_| invalid_manifest("expected an unsigned integer"))
}

fn parse_u8(value: &str) -> Result<u8> {
    value
        .parse::<u8>()
        .map_err(|_| invalid_manifest("expected an unsigned tier"))
}

fn parse_string_array(value: &str) -> Result<Vec<String>> {
    let Some(inner) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) else {
        return Err(invalid_manifest("expected an array of strings"));
    };
    inner
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(parse_string)
        .collect()
}

/// Validates a manifest against a resolved vault floor. Narrow-only: every
/// entry's class must admit an allowed band inside the floor's band for that
/// class, and every binding's `tier_ceiling` must not exceed the floor's max
/// for the entry's class. A wider ask fails
/// [`Error::ManifestWidensFloor`]; a narrower ask is accepted (and the narrow
/// binding is what gets stored).
pub fn validate_secret_manifest(m: &SecretManifest, floor: &SecretCustodyFloor) -> Result<()> {
    if m.schema_version != SECRET_MANIFEST_SCHEMA_VERSION {
        return Err(Error::InvalidSecretCustodyBody(
            "unsupported secret manifest schema version",
        ));
    }
    let mut seen_names = std::collections::BTreeSet::new();
    for entry in &m.secrets {
        if entry.name.is_empty() {
            return Err(Error::InvalidSecretCustodyBody(
                "secret manifest entry name must not be empty",
            ));
        }
        if !seen_names.insert(&entry.name) {
            return Err(Error::InvalidSecretCustodyBody(
                "duplicate secret manifest entry name",
            ));
        }
        let band = floor.band_for(entry.class);
        for binding in &entry.bindings {
            if binding.tier_ceiling > band.max {
                return Err(Error::ManifestWidensFloor {
                    secret_ref: entry.name.clone(),
                    class: entry.class,
                    requested: binding.tier_ceiling,
                    floor_max: band.max,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
