//! The trace normaliser: one walk over a raw trace that classifies every
//! object key it meets by [`super::manifest::MANIFEST`].
//!
//! - An exact value is kept byte for byte, its object keys sorted.
//! - A ref or opaque value is replaced by a name: a seeded ref by the
//!   scenario name it was bound to ([`Normaliser::bind`]), any other by
//!   `<kind>#<n>`, numbered per kind in first-seen order. Equal raw values
//!   get equal names, so equality and cross-references survive.
//! - A measured value becomes [`MEASURED`], its presence kept.
//! - A container's own keys are classified in turn.
//! - A key the manifest does not name fails the walk with its JSON path:
//!   a new field is classified on purpose, never dropped.
//!
//! A last pass replaces every bound raw ref that still appears inside a
//! string (an error message, a prompt, a serialized JSON field) with its
//! name.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Map, Value};

use super::manifest::{FieldClass, MANIFEST, SCHEMA_VERSION};

/// What a measured reading of real time is replaced with.
pub const MEASURED: &str = "<measured>";

/// The shortest bound raw ref the last pass replaces inside another string.
/// Shorter ones (a short id, a counter) are replaced only where the manifest
/// classifies them.
const MIN_EMBEDDED_REF: usize = 16;

/// How many unknown-key paths the error prints per key.
const PATHS_PER_KEY: usize = 3;

/// Whether a walk names new refs or only masks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Names every unbound ref and records unknown keys.
    Assign,
    /// Writes `?` for an unbound ref and records nothing: the sort key.
    Mask,
}

/// A key the manifest does not classify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKey {
    /// The key.
    pub key: String,
    /// The first few JSON paths it was met at.
    pub paths: Vec<String>,
    /// How many times it was met.
    pub count: usize,
}

/// Why a trace did not normalise.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NormaliseError {
    /// Keys the manifest does not classify, by key.
    pub unknown: Vec<UnknownKey>,
    /// Values whose shape their class does not allow, each with its path.
    pub malformed: Vec<String>,
}

impl fmt::Display for NormaliseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the trace does not normalise under manifest v{SCHEMA_VERSION}: {} unknown key(s), \
             {} malformed value(s). Classify each in src/golden_day/manifest.rs and bump \
             SCHEMA_VERSION.",
            self.unknown.len(),
            self.malformed.len()
        )?;
        for unknown in &self.unknown {
            write!(
                f,
                "\n- unknown key {:?}, met {} time(s), at {}",
                unknown.key,
                unknown.count,
                unknown.paths.join(", ")
            )?;
        }
        for malformed in &self.malformed {
            write!(f, "\n- malformed: {malformed}")?;
        }
        Ok(())
    }
}

impl std::error::Error for NormaliseError {}

/// One normalisation: the names bound so far and what failed. Bind the
/// seeded refs first, in scenario order, then normalise the trace once.
#[derive(Debug)]
pub struct Normaliser {
    classes: BTreeMap<&'static str, FieldClass>,
    names: BTreeMap<String, String>,
    next: BTreeMap<String, usize>,
    unknown: BTreeMap<String, UnknownKey>,
    malformed: Vec<String>,
}

impl Default for Normaliser {
    fn default() -> Self {
        Self::new()
    }
}

impl Normaliser {
    /// A normaliser under [`MANIFEST`]. A key the manifest lists twice is
    /// classified by its first entry.
    #[must_use]
    pub fn new() -> Self {
        let mut classes = BTreeMap::new();
        for (key, class) in MANIFEST {
            classes.entry(*key).or_insert(*class);
        }
        Self {
            classes,
            names: BTreeMap::new(),
            next: BTreeMap::new(),
            unknown: BTreeMap::new(),
            malformed: Vec::new(),
        }
    }

    /// Binds the raw ref `raw` to the scenario name `name`. A raw ref bound
    /// once keeps its first name; an empty one is ignored.
    pub fn bind(&mut self, raw: &str, name: &str) {
        if !raw.is_empty() {
            self.names
                .entry(raw.to_owned())
                .or_insert_with(|| name.to_owned());
        }
    }

    /// The name `raw` is bound to, if any.
    #[must_use]
    pub fn name_of(&self, raw: &str) -> Option<&str> {
        self.names.get(raw).map(String::as_str)
    }

    /// Sorts receipt rows into an order that no run-minted id decides:
    /// oldest `created_at` first, then by the row with every ref not yet
    /// bound masked to `?`. Rows equal under that mask keep their read
    /// order.
    #[must_use]
    pub fn sort_rows(&mut self, rows: Vec<Value>) -> Vec<Value> {
        let mut keys: Vec<(u64, String, usize)> = rows
            .iter()
            .enumerate()
            .map(|(index, row)| {
                let created_at = row.get("created_at").and_then(Value::as_u64).unwrap_or(0);
                let masked = self.walk(row, FieldClass::Container, "$", Mode::Mask);
                let masked = self.substitute(masked);
                (created_at, masked.to_string(), index)
            })
            .collect();
        keys.sort();
        let mut slots: Vec<Option<Value>> = rows.into_iter().map(Some).collect();
        keys.into_iter()
            .filter_map(|(_, _, index)| slots.get_mut(index).and_then(Option::take))
            .collect()
    }

    /// Walks `value`, a container at its root, which the error report names
    /// `path`. It names every ref not yet named, in walk order, and records
    /// every key the manifest does not classify and every malformed value.
    /// Returns the walked value: pass every walked part to [`Self::finish`].
    pub fn name_refs(&mut self, value: &Value, path: &str) -> Value {
        self.walk(value, FieldClass::Container, path, Mode::Assign)
    }

    /// `walked` with every bound raw ref replaced wherever it still appears
    /// inside a string or an object key.
    ///
    /// # Errors
    /// Every key the walks met that the manifest does not classify, and every
    /// value its class does not allow.
    pub fn finish(self, walked: Value) -> Result<Value, NormaliseError> {
        let normalised = self.substitute(walked);
        if self.unknown.is_empty() && self.malformed.is_empty() {
            Ok(normalised)
        } else {
            Err(NormaliseError {
                unknown: self.unknown.into_values().collect(),
                malformed: self.malformed,
            })
        }
    }

    /// Normalises `trace`, a container at the root, in one walk.
    ///
    /// # Errors
    /// As [`Self::finish`].
    pub fn normalise(mut self, trace: &Value) -> Result<Value, NormaliseError> {
        let walked = self.name_refs(trace, "$");
        self.finish(walked)
    }

    fn walk(&mut self, value: &Value, class: FieldClass, path: &str, mode: Mode) -> Value {
        match class {
            FieldClass::Exact => sorted(value),
            FieldClass::Measured => {
                if value.is_null() {
                    Value::Null
                } else {
                    Value::String(MEASURED.to_owned())
                }
            }
            FieldClass::Ref(kind) | FieldClass::Opaque(kind) => self.refs(value, kind, path, mode),
            FieldClass::Container => match value {
                Value::Object(map) => {
                    let mut out = BTreeMap::new();
                    for (key, child) in map {
                        let child_path = format!("{path}.{key}");
                        let walked = if let Some(class) = self.classes.get(key.as_str()).copied() {
                            self.walk(child, class, &child_path, mode)
                        } else {
                            if mode == Mode::Assign {
                                self.record_unknown(key, child_path);
                            }
                            sorted(child)
                        };
                        out.insert(key.clone(), walked);
                    }
                    Value::Object(out.into_iter().collect::<Map<String, Value>>())
                }
                Value::Array(items) => Value::Array(
                    items
                        .iter()
                        .enumerate()
                        .map(|(index, item)| {
                            self.walk(
                                item,
                                FieldClass::Container,
                                &format!("{path}[{index}]"),
                                mode,
                            )
                        })
                        .collect(),
                ),
                scalar => scalar.clone(),
            },
        }
    }

    fn refs(&mut self, value: &Value, kind: &str, path: &str, mode: Mode) -> Value {
        match value {
            Value::Null => Value::Null,
            Value::String(raw) => Value::String(self.name_list(raw, kind, mode)),
            Value::Number(number) => Value::String(self.name(&number.to_string(), kind, mode)),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| self.refs(item, kind, &format!("{path}[{index}]"), mode))
                    .collect(),
            ),
            other => {
                if mode == Mode::Assign {
                    self.malformed
                        .push(format!("{path}: a {kind} ref holds {}", type_name(other)));
                }
                sorted(other)
            }
        }
    }

    /// A ref, or a comma-separated list of refs, named part by part.
    fn name_list(&mut self, raw: &str, kind: &str, mode: Mode) -> String {
        if self.names.contains_key(raw) || !raw.contains(',') {
            return self.name(raw, kind, mode);
        }
        raw.split(',')
            .map(|part| self.name(part.trim(), kind, mode))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn name(&mut self, raw: &str, kind: &str, mode: Mode) -> String {
        if raw.is_empty() {
            return String::new();
        }
        if let Some(name) = self.names.get(raw) {
            return name.clone();
        }
        match mode {
            Mode::Mask => "?".to_owned(),
            Mode::Assign => {
                let count = self.next.entry(kind.to_owned()).or_insert(0);
                *count += 1;
                let name = format!("{kind}#{count}");
                self.names.insert(raw.to_owned(), name.clone());
                name
            }
        }
    }

    fn record_unknown(&mut self, key: &str, path: String) {
        let entry = self
            .unknown
            .entry(key.to_owned())
            .or_insert_with(|| UnknownKey {
                key: key.to_owned(),
                paths: Vec::new(),
                count: 0,
            });
        entry.count += 1;
        if entry.paths.len() < PATHS_PER_KEY {
            entry.paths.push(path);
        }
    }

    /// `value` with every bound raw ref of at least [`MIN_EMBEDDED_REF`]
    /// bytes replaced by its name wherever it appears inside a string or an
    /// object key, longest raw ref first.
    fn substitute(&self, value: Value) -> Value {
        let mut bound: Vec<(&str, &str)> = self
            .names
            .iter()
            .filter(|(raw, _)| raw.len() >= MIN_EMBEDDED_REF)
            .map(|(raw, name)| (raw.as_str(), name.as_str()))
            .collect();
        bound.sort_by_key(|(raw, _)| std::cmp::Reverse(raw.len()));
        replace_within(value, &bound)
    }
}

/// Replaces each of `keys` in each row object with [`MEASURED`], as the
/// [`FieldClass::Measured`] class does: its presence kept, its value not; a
/// null stays null. A row without the key stays without it.
pub fn mask_measured(rows: &mut [Value], keys: &[&str]) {
    for row in rows {
        if let Some(object) = row.as_object_mut() {
            for key in keys {
                if let Some(value) = object.get_mut(*key).filter(|value| !value.is_null()) {
                    *value = Value::String(MEASURED.to_owned());
                }
            }
        }
    }
}

fn replace_within(value: Value, bound: &[(&str, &str)]) -> Value {
    match value {
        Value::String(text) => Value::String(replace_text(text, bound)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| replace_within(item, bound))
                .collect(),
        ),
        Value::Object(map) => {
            let replaced: BTreeMap<String, Value> = map
                .into_iter()
                .map(|(key, child)| (replace_text(key, bound), replace_within(child, bound)))
                .collect();
            Value::Object(replaced.into_iter().collect())
        }
        scalar => scalar,
    }
}

fn replace_text(text: String, bound: &[(&str, &str)]) -> String {
    let mut text = text;
    for (raw, name) in bound {
        if text.contains(raw) {
            text = text.replace(raw, name);
        }
    }
    text
}

/// `value` with every object's keys in sorted order, all the way down.
fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let ordered: BTreeMap<&String, Value> = map
                .iter()
                .map(|(key, child)| (key, sorted(child)))
                .collect();
            Value::Object(
                ordered
                    .into_iter()
                    .map(|(key, child)| (key.clone(), child))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        scalar => scalar.clone(),
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a bool",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// `dump` as the golden file holds it: pretty JSON and one trailing
/// newline.
#[must_use]
pub fn render(dump: &Value) -> String {
    let mut text = serde_json::to_string_pretty(dump).unwrap_or_else(|_| dump.to_string());
    text.push('\n');
    text
}
