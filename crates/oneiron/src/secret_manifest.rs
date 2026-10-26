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
    /// The environment variable name a run reads this secret as (FIX 7608
    /// slice 6): a name mapped onto this entry's custody `name`, never a
    /// value. An ordinary secret declares none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_name: Option<String>,
}

/// Whether `name` is an environment variable name a manifest may declare
/// and a dotenv file assigns: a letter or `_`, then letters, digits, `_`,
/// `.` or `-`.
#[must_use]
pub fn is_secret_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// The manifest schema version stamped at parse.
pub const SECRET_MANIFEST_SCHEMA_VERSION: u16 = 1;

/// Parses a `SecretManifest` from its TOML text form.
///
/// The manifest is line-oriented TOML: a top-level `schema_version` integer,
/// then one `[[secrets]]` table array per entry, each with `name`, `class`
/// (the canon kebab-case noun), a `declared_paths` string array, an optional
/// `env_name` string, and inline `[[secrets.bindings]]` tables with
/// `effector`, `tier_ceiling` (integer 0..=2), and a `scopes` string array.
/// Unknown keys are ignored so the format can grow, but each value must
/// still end on its line. A key set twice in one table, a key made both a value and a table, a key under one this
/// subset reads, or an effector bound twice in one entry, is refused: the
/// manifest would say two things, and keeping either would let a wider value
/// pass for a narrower one. The parser is a deliberately small TOML subset —
/// the engine takes no `toml` crate dependency for this one file — and refuses
/// what TOML refuses in the values it reads.
pub fn parse_secret_manifest(text: &str) -> Result<SecretManifest> {
    // Scratch shape during parse: class stays Option so a missing `class`
    // key is a typed error at finish, not a silent default.
    #[derive(Default)]
    struct ScratchEntry {
        name: String,
        class: Option<CustodyClass>,
        declared_paths: Vec<String>,
        env_name: Option<String>,
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
        let line = toml_trim(raw);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.chars().any(is_control) {
            return Err(invalid_manifest(
                "a manifest line holds a control character",
            ));
        }
        // A comment after a header or a value is not part of it.
        let line = match separators(line, b'#').first() {
            Some(&at) => toml_trim(&line[..at]),
            None => line,
        };
        if line == "[[secrets]]" {
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
            entry.bindings.push(ScratchBinding::default());
            scope = Scope::Binding;
            seen.clear();
            continue;
        }

        let Some(&at) = separators(line, b'=').first() else {
            return Err(invalid_manifest("expected `key = value`"));
        };
        let (key, value) = (&line[..at], &line[at + 1..]);
        let path = key_path(key)?;
        let value = toml_trim(value);
        if redefines(&seen, &path) {
            return Err(invalid_manifest(
                "a manifest key is set twice, or as a value and a table",
            ));
        }
        // The keys this subset reads in the current table, and the array of
        // tables beneath it. A dotted key under one of them, or any key under
        // that array, would make it something TOML reads apart from what this
        // parser reads.
        let (reads, beneath): (&[&str], Option<&str>) = match scope {
            Scope::Root => (&["schema_version"], Some("secrets")),
            Scope::Secrets => (
                &["name", "class", "declared_paths", "env_name"],
                Some("bindings"),
            ),
            Scope::Binding => (&["effector", "tier_ceiling", "scopes"], None),
        };
        let head = path.first().map(String::as_str);
        if head
            .is_some_and(|head| beneath == Some(head) || (path.len() > 1 && reads.contains(&head)))
        {
            return Err(invalid_manifest(
                "a manifest key redefines a key or table the manifest reads",
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
                } else {
                    extension_value(value)?;
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
                    "env_name" => entry.env_name = Some(parse_string(value)?),
                    _ => extension_value(value)?,
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
                    _ => extension_value(value)?,
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
                env_name: entry.env_name,
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

/// `text` without TOML whitespace (space and tab) at either end.
fn toml_trim(text: &str) -> &str {
    text.trim_matches([' ', '\t'])
}

/// A character TOML refuses raw outside a comment: a control character other
/// than tab.
fn is_control(c: char) -> bool {
    c != '\t' && (c < ' ' || c == '\u{7f}')
}

/// An extension key's value is not read, but it must end on its line, as
/// every value this subset reads does. A multi-line string or array, or an
/// unterminated one, would make TOML read the lines after it as its text,
/// where this parser would read them as keys and tables. A multi-line string
/// that closes on its opening line ends there.
fn extension_value(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let mut depth = 0_usize;
    let mut at = 0;
    while let Some(&c) = bytes.get(at) {
        match c {
            b'"' | b'\'' => {
                at = string_end(bytes, at, c)
                    .ok_or_else(|| invalid_manifest("a manifest value does not end on its line"))?;
                continue;
            }
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    invalid_manifest("a manifest value closes what it never opened")
                })?;
            }
            _ => {}
        }
        at += 1;
    }
    if toml_trim(value).is_empty() || depth != 0 {
        return Err(invalid_manifest(
            "a manifest value does not end on its line",
        ));
    }
    Ok(())
}

/// The offset just past the string that `quote` opens at `start`, if it
/// closes on the line. A basic string skips what a backslash escapes. A
/// multi-line one (`"""`, `'''`) holds one or two of its quotes, inside or
/// just before its closing three.
fn string_end(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let multi_line = bytes.get(start..)?.starts_with(&[quote; 3]);
    let mut at = start + if multi_line { 3 } else { 1 };
    while let Some(&c) = bytes.get(at) {
        if c == b'\\' && quote == b'"' {
            at += 2;
        } else if c != quote {
            at += 1;
        } else if !multi_line {
            return Some(at + 1);
        } else {
            let run = bytes[at..].iter().take_while(|&&b| b == quote).count();
            if run >= 3 {
                return (run <= 5).then_some(at + run);
            }
            at += run;
        }
    }
    None
}

fn invalid_manifest(msg: &'static str) -> Error {
    Error::Secret(SecretError::InvalidSecretCustodyBody(msg))
}

/// The byte offsets of `sep` in `text` outside a string, in any of TOML's
/// four forms. A string left open runs to the end of the text.
fn separators(text: &str, sep: u8) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(&c) = bytes.get(at) {
        if c == b'"' || c == b'\'' {
            let Some(end) = string_end(bytes, at, c) else {
                break;
            };
            at = end;
        } else {
            if c == sep {
                found.push(at);
            }
            at += 1;
        }
    }
    found
}

/// `text` cut at each `sep` outside a string.
fn split_outside_quotes(text: &str, sep: u8) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    for at in separators(text, sep) {
        parts.push(&text[start..at]);
        start = at + 1;
    }
    parts.push(&text[start..]);
    parts
}

/// A key's parts, unquoted and unescaped. TOML reads `tier_ceiling`,
/// `"tier_ceiling"` and `"\u0074ier_ceiling"` as one key, and
/// `"extension.flag"` (one part) apart from `extension.flag` (two).
fn key_path(key: &str) -> Result<Vec<String>> {
    split_outside_quotes(key, b'.')
        .into_iter()
        .map(|part| {
            let part = toml_trim(part);
            if part.is_empty() {
                Err(invalid_manifest("a key has an empty part"))
            } else if part.starts_with("\"\"\"") || part.starts_with("'''") {
                Err(invalid_manifest("a key is never a multi-line string"))
            } else if part.starts_with(['"', '\'']) {
                parse_string(part)
            } else if part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                Ok(part.to_owned())
            } else {
                Err(invalid_manifest(
                    "a bare key holds a character TOML refuses",
                ))
            }
        })
        .collect()
}

/// A string in one of TOML's four forms, on one line. A basic string
/// (`"…"`) decodes its escapes; a literal one (`'…'`) is its text as written.
/// Their multi-line forms (`"""…"""`, `'''…'''`) may also hold one or two of
/// their quotes in a row. TOML reads `"deploy"`, `"de\u0070loy"` and
/// `"""deploy"""` as one string, so they compare equal here.
fn parse_string(value: &str) -> Result<String> {
    let quoted = |quotes: &str| value.strip_prefix(quotes)?.strip_suffix(quotes);
    let (inner, quote, run_cap) = if let Some(inner) = quoted("'''") {
        (inner, '\'', 2)
    } else if let Some(inner) = quoted("\"\"\"") {
        (inner, '"', 2)
    } else if let Some(inner) = quoted("'") {
        (inner, '\'', 0)
    } else if let Some(inner) = quoted("\"") {
        (inner, '"', 0)
    } else {
        return Err(invalid_manifest("expected a quoted string"));
    };
    let mut text = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    let mut run = 0;
    while let Some(c) = chars.next() {
        run = if c == quote { run + 1 } else { 0 };
        if run > run_cap {
            return Err(invalid_manifest("a string holds its own closing quote"));
        }
        match c {
            '\\' if quote == '"' => text.push(unescape(&mut chars)?),
            c => text.push(c),
        }
    }
    Ok(text)
}

/// The character named by the next `digits` hex digits of an escape.
/// `from_str_radix` alone would take a sign, reading `\u+061` as `a`.
fn hex_char(chars: &mut std::str::Chars<'_>, digits: usize) -> Result<char> {
    let code: String = chars.take(digits).collect();
    Some(&code)
        .filter(|code| code.len() == digits && code.bytes().all(|b| b.is_ascii_hexdigit()))
        .and_then(|code| u32::from_str_radix(code, 16).ok())
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

/// The digits of a TOML decimal integer: an optional `+`, then `0` or digits
/// without a leading zero. TOML refuses `01`, which `str::parse` reads as 1.
fn decimal(value: &str) -> Option<&str> {
    let digits = value.strip_prefix('+').unwrap_or(value);
    let leading = digits.bytes().next()?;
    (digits.bytes().all(|b| b.is_ascii_digit()) && (leading != b'0' || digits == "0"))
        .then_some(digits)
}

fn parse_u16(value: &str) -> Result<u16> {
    decimal(value)
        .and_then(|digits| digits.parse::<u16>().ok())
        .ok_or_else(|| invalid_manifest("expected an unsigned integer"))
}

fn parse_u8(value: &str) -> Result<u8> {
    decimal(value)
        .and_then(|digits| digits.parse::<u8>().ok())
        .ok_or_else(|| invalid_manifest("expected an unsigned tier"))
}

/// A one-line array of strings. TOML takes one trailing comma, and no other
/// empty element.
fn parse_string_array(value: &str) -> Result<Vec<String>> {
    let Some(inner) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) else {
        return Err(invalid_manifest("expected an array of strings"));
    };
    if toml_trim(inner).is_empty() {
        return Ok(Vec::new());
    }
    let mut items = split_outside_quotes(inner, b',');
    if items.last().is_some_and(|item| toml_trim(item).is_empty()) {
        items.pop();
    }
    items
        .into_iter()
        .map(|item| match toml_trim(item) {
            "" => Err(invalid_manifest("an array has an empty element")),
            item => parse_string(item),
        })
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
    let mut seen_env_names = std::collections::BTreeSet::new();
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
        // An env name names one secret: a run reads one value under it.
        if let Some(env_name) = &entry.env_name {
            if !is_secret_env_name(env_name) {
                return Err(invalid_manifest(
                    "secret manifest env_name is not an environment variable name",
                ));
            }
            if !seen_env_names.insert(env_name) {
                return Err(invalid_manifest("duplicate secret manifest env_name"));
            }
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
