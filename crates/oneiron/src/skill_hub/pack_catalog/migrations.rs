//! Predicate migration maps a pack ships in PACK.md (ARCH-0059 §4, rung 1).
//!
//! A shipped map can rewrite an owner's saved queries with no one asked, so
//! its line is read closed: no repeated key at any depth, no field a rewrite
//! kind does not carry, and only the pack's own predicates, outside every
//! engine namespace, onto predicates the new source declares and a Claim can
//! carry.
use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use super::invalid;
use crate::error::Result;
use crate::saved_query::PackPredicateRewrite;

/// One shipped migration map: the rewrites that carry a saved query from an
/// earlier source of this pack to this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackMigration {
    /// The version the move starts from.
    pub from: String,
    /// The exact source the move starts from, by content hash. Required
    /// when `from` is this source's own version.
    pub source: Option<String>,
    /// Old predicate to its rewrite.
    pub rewrites: BTreeMap<String, PackPredicateRewrite>,
}

const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_MAPS: usize = 32;
const MAX_REWRITES: usize = 128;

/// Reads a PACK.md `migrations` line for the pack `name` at `version`, whose
/// source declares `predicates`.
pub(super) fn parse(
    line: &str,
    name: &str,
    version: &str,
    predicates: &BTreeSet<String>,
) -> Result<Vec<PackMigration>> {
    let refused = || invalid("migrations must be a JSON array of closed maps that repeat no key");
    if line.len() > MAX_LINE_BYTES {
        return Err(refused());
    }
    let Ok(DistinctKeys(Value::Array(entries))) = serde_json::from_str(line) else {
        return Err(refused());
    };
    if entries.len() > MAX_MAPS {
        return Err(invalid("too many shipped migration maps"));
    }
    let mut starts = BTreeSet::new();
    let mut migrations = Vec::with_capacity(entries.len());
    for entry in entries {
        let Value::Object(mut fields) = entry else {
            return Err(refused());
        };
        if fields
            .keys()
            .any(|key| !matches!(key.as_str(), "from" | "source" | "rewrites"))
        {
            return Err(refused());
        }
        let (Some(Value::String(from)), source, Some(Value::Object(rewrites))) = (
            fields.remove("from"),
            fields.remove("source"),
            fields.remove("rewrites"),
        ) else {
            return Err(refused());
        };
        let source = match source {
            None => None,
            Some(Value::String(hash))
                if hash.len() == 64
                    && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
            {
                Some(hash)
            }
            Some(_) => return Err(refused()),
        };
        if from.is_empty()
            || from.len() > 128
            || from.chars().any(char::is_control)
            || (from == version && source.is_none())
            || !starts.insert((from.clone(), source.clone()))
        {
            return Err(invalid(
                "a migration names a distinct starting version, and the exact source for its own",
            ));
        }
        if rewrites.is_empty() || rewrites.len() > MAX_REWRITES {
            return Err(invalid("a migration map holds 1 to 128 rewrites"));
        }
        let mut checked = BTreeMap::new();
        for (old, rewrite) in rewrites {
            let rewrite = closed_rewrite(rewrite)?;
            let (PackPredicateRewrite::Rename { to }
            | PackPredicateRewrite::Equivalent { to, .. }
            | PackPredicateRewrite::SemanticsChanging { to, .. }) = &rewrite;
            super::manifest::validate_name(&old)?;
            // The target is where the query reads next, so a Claim must be
            // able to carry it: the D17 grammar, at most 128 bytes.
            if !old.starts_with(&format!("{name}."))
                || !predicates.contains(to)
                || crate::claim::validate_predicate(to, false).is_err()
                || engine_owned(&old)
                || engine_owned(to)
            {
                return Err(invalid(
                    "a migration rewrites the pack's own predicates onto writable ones it declares, outside the engine's namespaces",
                ));
            }
            checked.insert(old, rewrite);
        }
        migrations.push(PackMigration {
            from,
            source,
            rewrites: checked,
        });
    }
    Ok(migrations)
}

/// A rename carries `to`; an equivalent or a semantics-changing rewrite
/// carries `to` and a printable `note`. Nothing else.
fn closed_rewrite(rewrite: Value) -> Result<PackPredicateRewrite> {
    let refused = || invalid("a rewrite is a closed rename, equivalent or semantics_changing");
    let Value::Object(fields) = &rewrite else {
        return Err(refused());
    };
    let allowed: &[&str] = match fields.get("kind").and_then(Value::as_str) {
        Some("rename") => &["kind", "to"],
        Some("equivalent" | "semantics_changing") => &["kind", "to", "note"],
        _ => return Err(refused()),
    };
    if fields.len() != allowed.len() || fields.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(refused());
    }
    let rewrite: PackPredicateRewrite = serde_json::from_value(rewrite).map_err(|_| refused())?;
    if let PackPredicateRewrite::Equivalent { note, .. }
    | PackPredicateRewrite::SemanticsChanging { note, .. } = &rewrite
        && (note.is_empty() || note.len() > 1024 || note.chars().any(char::is_control))
    {
        return Err(refused());
    }
    Ok(rewrite)
}

/// A predicate in a namespace the engine owns: its layers (`core`,
/// `companion`, `persona`, `commitment`) and its reserved doors.
fn engine_owned(predicate: &str) -> bool {
    crate::claim::is_reserved_predicate(predicate)
        || predicate
            .split('.')
            .next()
            .is_some_and(|namespace| crate::claim::PREDICATE_LAYER_NAMESPACES.contains(&namespace))
}

/// A JSON value whose objects repeat no key. serde_json keeps the last of a
/// repeated key, which would let one shipped map say two things.
struct DistinctKeys(Value);

impl<'de> Deserialize<'de> for DistinctKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Walk;
        impl<'de> Visitor<'de> for Walk {
            type Value = Value;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value")
            }
            fn visit_bool<E>(self, value: bool) -> std::result::Result<Value, E> {
                Ok(Value::Bool(value))
            }
            fn visit_i64<E>(self, value: i64) -> std::result::Result<Value, E> {
                Ok(Value::from(value))
            }
            fn visit_u64<E>(self, value: u64) -> std::result::Result<Value, E> {
                Ok(Value::from(value))
            }
            fn visit_f64<E>(self, value: f64) -> std::result::Result<Value, E> {
                Ok(Value::from(value))
            }
            fn visit_str<E>(self, value: &str) -> std::result::Result<Value, E> {
                Ok(Value::String(value.to_owned()))
            }
            fn visit_string<E>(self, value: String) -> std::result::Result<Value, E> {
                Ok(Value::String(value))
            }
            fn visit_unit<E>(self) -> std::result::Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(DistinctKeys(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Value::Array(items))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Value, A::Error> {
                let mut object = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if object.contains_key(&key) {
                        return Err(de::Error::custom("repeated key"));
                    }
                    let DistinctKeys(value) = map.next_value()?;
                    object.insert(key, value);
                }
                Ok(Value::Object(object))
            }
        }
        deserializer.deserialize_any(Walk).map(DistinctKeys)
    }
}
