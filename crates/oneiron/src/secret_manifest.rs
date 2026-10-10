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
//! [`SecretError::ManifestWidensFloor`]; a narrower manifest is stored with its
//! narrow binding.
//!
//! The merge rule is `manifest ∧ vault_floor` — most-restrictive wins. At
//! register time the manifest entry is copied onto the record
//! (`manifest_ref`, `declared_paths`, and the floor snapshot) so downstream
//! consumers have a vault-side data source; see
//! [`crate::Vault::register_secret_as_owner`], which reads the manifest from a
//! served repository through [`crate::Vault::origin_secret_manifest`].

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result, SecretError};
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
/// format can grow. A key set twice in one table, a key made both a value and
/// a table, or an effector bound twice in one entry, is refused: the manifest
/// would say two things, and keeping either would let a wider value pass for
/// a narrower one. The parser is a deliberately small TOML subset — the
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
    // The keys the current table has set. TOML forbids setting one twice, or
    // making it a value and a table, and keeping the last would let a later,
    // wider tier erase a narrower one.
    let mut seen: Vec<Vec<String>> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[secrets]]" {
            if matches!(scope, Scope::Root) && redefines(&seen, &["secrets".to_owned()]) {
                return Err(invalid_manifest("[[secrets]] redefines a root key"));
            }
            secrets.push(ScratchEntry::default());
            scope = Scope::Secrets;
            seen.clear();
            continue;
        }
        if line == "[[secrets.bindings]]" {
            let Some(entry) = secrets.last_mut() else {
                return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
                    "[[secrets.bindings]] before any [[secrets]]",
                )));
            };
            if matches!(scope, Scope::Secrets) && redefines(&seen, &["bindings".to_owned()]) {
                return Err(invalid_manifest(
                    "[[secrets.bindings]] redefines an entry key",
                ));
            }
            entry.bindings.push(ScratchBinding::default());
            scope = Scope::Binding;
            seen.clear();
            continue;
        }

        let Some(&at) = separators(line, '=').first() else {
            return Err(invalid_manifest("expected `key = value`"));
        };
        let (key, value) = (&line[..at], &line[at + 1..]);
        let path = key_path(key)?;
        let value = value.trim();
        if redefines(&seen, &path) {
            return Err(invalid_manifest(
                "a manifest key is set twice, or as a value and a table",
            ));
        }
        // Only a one-part key can be one this subset reads; a dotted key is an
        // extension, kept apart from them and ignored.
        let key = match path.as_slice() {
            [key] => key.clone(),
            _ => String::new(),
        };
        seen.push(path);
        let key = key.as_str();

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
                            Error::Secret(SecretError::InvalidSecretCustodyBody(
                                "unknown custody class in manifest",
                            )),
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
                            Error::Secret(SecretError::InvalidSecretCustodyBody(
                                "unknown tier_ceiling in manifest",
                            )),
                        )?);
                    }
                    "scopes" => binding.scopes = parse_string_array(value)?,
                    _ => {}
                }
            }
        }
    }

    let schema_version = schema_version.ok_or(Error::Secret(
        SecretError::InvalidSecretCustodyBody("manifest missing schema_version"),
    ))?;
    if schema_version != SECRET_MANIFEST_SCHEMA_VERSION {
        return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
            "unsupported secret manifest schema version",
        )));
    }
    let secrets = secrets
        .into_iter()
        .map(|entry| {
            let class = entry
                .class
                .ok_or(Error::Secret(SecretError::InvalidSecretCustodyBody(
                    "manifest entry missing class",
                )))?;
            let bindings = entry
                .bindings
                .into_iter()
                .map(|b| {
                    Ok(SecretBinding {
                        effector: b.effector,
                        tier_ceiling: b.tier_ceiling.ok_or(Error::Secret(
                            SecretError::InvalidSecretCustodyBody(
                                "manifest binding missing tier_ceiling",
                            ),
                        ))?,
                        scopes: b.scopes,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let mut effectors = std::collections::BTreeSet::new();
            if !bindings
                .iter()
                .all(|binding| effectors.insert(binding.effector.as_str()))
            {
                return Err(invalid_manifest("a manifest entry binds an effector twice"));
            }
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

/// Whether `path` sets a key `seen` already holds, or a key inside one, or a
/// table around one. TOML refuses each: a key is set once, and is a value or
/// a table, never both.
fn redefines(seen: &[Vec<String>], path: &[String]) -> bool {
    seen.iter()
        .any(|prior| prior.starts_with(path) || path.starts_with(prior))
}

fn invalid_manifest(msg: &'static str) -> Error {
    Error::Secret(SecretError::InvalidSecretCustodyBody(msg))
}

/// The byte offsets of `sep` in `text` outside a basic (`"…"`) or literal
/// (`'…'`) string.
fn separators(text: &str, sep: char) -> Vec<usize> {
    let mut found = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    for (at, c) in text.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(open) if c == open => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == sep => found.push(at),
            None => {}
        }
    }
    found
}

/// `text` cut at each `sep` outside a string.
fn split_outside_quotes(text: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    for at in separators(text, sep) {
        parts.push(&text[start..at]);
        start = at + sep.len_utf8();
    }
    parts.push(&text[start..]);
    parts
}

/// A key's parts, unquoted and unescaped. TOML reads `tier_ceiling`,
/// `"tier_ceiling"` and `"\u0074ier_ceiling"` as one key, and
/// `"extension.flag"` (one part) apart from `extension.flag` (two).
fn key_path(key: &str) -> Result<Vec<String>> {
    split_outside_quotes(key, '.')
        .into_iter()
        .map(|part| {
            let part = part.trim();
            if part.is_empty() {
                Err(invalid_manifest("a key has an empty part"))
            } else if part.starts_with(['"', '\'']) {
                parse_string(part)
            } else {
                Ok(part.to_owned())
            }
        })
        .collect()
}

/// A basic (`"…"`, escapes decoded) or literal (`'…'`) string. TOML reads
/// `"deploy"` and `"de\u0070loy"` as one string, so they compare equal here.
fn parse_string(value: &str) -> Result<String> {
    if let Some(inner) = value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        if inner.contains('\'') {
            return Err(invalid_manifest("a literal string holds a quote"));
        }
        return Ok(inner.to_owned());
    }
    let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
        return Err(invalid_manifest("expected a quoted string"));
    };
    let mut text = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Err(invalid_manifest("a basic string holds an unescaped quote")),
            '\\' => text.push(unescape(&mut chars)?),
            c => text.push(c),
        }
    }
    Ok(text)
}

/// The character named by the next `digits` hex digits of an escape.
fn hex_char(chars: &mut std::str::Chars<'_>, digits: usize) -> Result<char> {
    let code: String = chars.take(digits).collect();
    u32::from_str_radix(&code, 16)
        .ok()
        .filter(|_| code.len() == digits)
        .and_then(char::from_u32)
        .ok_or_else(|| invalid_manifest("a string escape names no character"))
}

/// One basic-string escape, read after its backslash.
fn unescape(chars: &mut std::str::Chars<'_>) -> Result<char> {
    match chars.next() {
        Some('b') => Ok('\u{8}'),
        Some('t') => Ok('\t'),
        Some('n') => Ok('\n'),
        Some('f') => Ok('\u{c}'),
        Some('r') => Ok('\r'),
        Some('e') => Ok('\u{1b}'),
        Some('"') => Ok('"'),
        Some('\\') => Ok('\\'),
        Some('x') => hex_char(chars, 2),
        Some('u') => hex_char(chars, 4),
        Some('U') => hex_char(chars, 8),
        _ => Err(invalid_manifest("a string has an unknown escape")),
    }
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
    split_outside_quotes(inner, ',')
        .into_iter()
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(parse_string)
        .collect()
}

/// Validates a manifest against a resolved vault floor. Narrow-only: every
/// entry's class must admit an allowed band inside the floor's band for that
/// class, and every binding's `tier_ceiling` must not exceed the floor's max
/// for the entry's class. A wider ask fails
/// [`SecretError::ManifestWidensFloor`]; a narrower ask is accepted (and the narrow
/// binding is what gets stored).
pub fn validate_secret_manifest(m: &SecretManifest, floor: &SecretCustodyFloor) -> Result<()> {
    if m.schema_version != SECRET_MANIFEST_SCHEMA_VERSION {
        return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
            "unsupported secret manifest schema version",
        )));
    }
    let mut seen_names = std::collections::BTreeSet::new();
    for entry in &m.secrets {
        if entry.name.is_empty() {
            return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
                "secret manifest entry name must not be empty",
            )));
        }
        if !seen_names.insert(&entry.name) {
            return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
                "duplicate secret manifest entry name",
            )));
        }
        let band = floor.band_for(entry.class);
        for binding in &entry.bindings {
            if binding.tier_ceiling > band.max {
                return Err(Error::Secret(SecretError::ManifestWidensFloor {
                    secret_ref: entry.name.clone(),
                    class: entry.class,
                    requested: binding.tier_ceiling,
                    floor_max: band.max,
                }));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
