//! Python's operations on a verb row, as the Rust emitters perform them (G4a).
//!
//! A row is the JSON object its verb file holds (brief H1b), after the module level's mutations. The emitters read
//! it as Python does: `row[key]` is a `KeyError` when the key is absent, a `str` method on a value that is no `str`
//! is an `AttributeError`, `'text' + value` a `TypeError`, and an f-string interpolates `str(value)`. Each helper
//! raises Python's error at the place Python would.

use super::common::str_receiver;
use crate::error::GenerateError;
use crate::py::json::{DumpOptions, dumps};
use crate::py::text::title;
use crate::py::value::{Dict, Value};

/// `row[key]`.
pub(crate) fn item<'r>(row: &'r Dict, key: &str) -> Result<&'r Value, GenerateError> {
    row.get(key).ok_or_else(|| GenerateError::key(key))
}

/// `row[key]`, a `str` method `method` then called on it.
pub(crate) fn text<'r>(row: &'r Dict, key: &str, method: &str) -> Result<&'r str, GenerateError> {
    str_receiver(item(row, key)?, method)
}

/// `row[key]` in an f-string: `str(row[key])`.
pub(crate) fn shown(row: &Dict, key: &str) -> Result<String, GenerateError> {
    Ok(item(row, key)?.str())
}

/// `json.dumps(value)` with Python's defaults (H1).
pub(crate) fn json(value: &Value) -> String {
    dumps(value, DumpOptions::default())
}

/// `json.dumps(row[key])`.
pub(crate) fn json_item(row: &Dict, key: &str) -> Result<String, GenerateError> {
    Ok(json(item(row, key)?))
}

/// `'...' + value`: Python's `TypeError` when the value is no `str`.
pub(crate) fn concat(value: &Value) -> Result<&str, GenerateError> {
    value.as_str().ok_or_else(|| {
        GenerateError::type_error(format!(
            "can only concatenate str (not \"{}\") to str",
            value.type_name()
        ))
    })
}

/// `bool(row.get(key))`.
pub(crate) fn flag(row: &Dict, key: &str) -> bool {
    row.get(key).is_some_and(Value::truthy)
}

/// `row.get(key) == text` (a missing key is `None`, which equals no `str`).
pub(crate) fn get_is(row: &Dict, key: &str, text: &str) -> bool {
    row.get(key).is_some_and(|value| value.is_str(text))
}

/// `row.get('context', 'memory') == context`.
pub(crate) fn context_is(row: &Dict, context: &str) -> bool {
    row.get("context")
        .map_or(context == "memory", |value| value.is_str(context))
}

/// `row.get(key, {}).get(inner)`: `None` when either is absent; a present value that is no dict meets `.get`.
pub(crate) fn get_in<'r>(
    row: &'r Dict,
    key: &str,
    inner: &str,
) -> Result<Option<&'r Value>, GenerateError> {
    match row.get(key) {
        None => Ok(None),
        Some(value) => value.dict_get(inner),
    }
}

/// `bool(row.get(key, {}).get(inner))`.
pub(crate) fn flag_in(row: &Dict, key: &str, inner: &str) -> Result<bool, GenerateError> {
    Ok(get_in(row, key, inner)?.is_some_and(Value::truthy))
}

/// `row.get('admission', {}).get('validate', '')` in an f-string or before a `str` method: the value's text
/// (`str(value)` for an f-string; `method`'s `AttributeError` for a `str` method on a value that is no `str`).
pub(crate) fn admission_text(
    row: &Dict,
    inner: &str,
    method: Option<&str>,
) -> Result<String, GenerateError> {
    match get_in(row, "admission", inner)? {
        None => Ok(String::new()),
        Some(value) => match method {
            None => Ok(value.str()),
            Some(method) => Ok(str_receiver(value, method)?.to_owned()),
        },
    }
}

/// `list(row.get(key, {}).get(inner, []))`: the items of a list, the keys of a dict, the characters of a `str`.
pub(crate) fn items_in(row: &Dict, key: &str, inner: &str) -> Result<Vec<Value>, GenerateError> {
    match get_in(row, key, inner)? {
        None => Ok(Vec::new()),
        Some(value) => value.iterate(),
    }
}

/// `row.get('binding', {}).get('args', [])`, iterated.
pub(crate) fn binding_args(row: &Dict) -> Result<Vec<Value>, GenerateError> {
    items_in(row, "binding", "args")
}

/// `row['name'].replace('.', '_')`: the row's method name.
pub(crate) fn method_name(row: &Dict) -> Result<String, GenerateError> {
    Ok(text(row, "name", "replace")?.replace('.', "_"))
}

/// `''.join(part.title() for part in name.replace('.', '_').split('_'))`: a row's Rust variant name (H3).
pub(crate) fn variant_name(name: &str) -> String {
    name.replace('.', "_").split('_').map(title).collect()
}

/// A dict built by a comprehension keyed by row name (`{r['name']: ... for r in rows}`): first position, last value.
#[derive(Debug)]
pub(crate) struct ByName<T> {
    entries: Vec<(String, T)>,
}

impl<T> Default for ByName<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T> ByName<T> {
    /// `d[name] = value`.
    pub(crate) fn insert(&mut self, name: &str, value: T) {
        match self.entries.iter_mut().find(|(key, _)| key == name) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((name.to_owned(), value)),
        }
    }

    /// `d[name]`: Python's `KeyError` when absent.
    pub(crate) fn get(&self, name: &str) -> Result<&T, GenerateError> {
        self.entries
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
            .ok_or_else(|| GenerateError::key(name))
    }

    /// `name in d`.
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|(key, _)| key == name)
    }

    /// `d.values()`.
    pub(crate) fn values(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().map(|(_, value)| value)
    }
}

/// `{r['name']: variant(r['name']) for r in rows}` (generate.py:1589, 2462): each row's variant, by name.
pub(crate) fn variants(rows: &[&Dict]) -> Result<ByName<String>, GenerateError> {
    let mut variants = ByName::default();
    for row in rows {
        let name = text(row, "name", "replace")?;
        variants.insert(name, variant_name(name));
    }
    Ok(variants)
}

/// `variants[r['name']]`.
pub(crate) fn variant_of<'v>(
    variants: &'v ByName<String>,
    row: &Dict,
) -> Result<&'v str, GenerateError> {
    let name = item(row, "name")?;
    let name = name
        .as_str()
        .ok_or_else(|| GenerateError::exception("KeyError", name.repr()))?;
    variants.get(name).map(String::as_str)
}

/// Python's `repr` of a list of strings, as an f-string prints `{missing}`.
pub(crate) fn repr_list(items: &[&str]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|item| crate::py::text::repr_str(item))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// `value + '...'` with a `str` on the right: the value's text, or Python's `TypeError` for a value that is no
/// `str` (a list's own concatenation message, any other type's unsupported operand).
pub(crate) fn add_str(value: &Value) -> Result<&str, GenerateError> {
    match value {
        Value::Str(text) => Ok(text),
        Value::List(_) => Err(GenerateError::type_error(
            "can only concatenate list (not \"str\") to list",
        )),
        _ => Err(GenerateError::type_error(format!(
            "unsupported operand type(s) for +: '{}' and 'str'",
            value.type_name()
        ))),
    }
}

/// `value[0]`: a list's first item, a string's first character, or Python's error for an empty one or a dict.
pub(crate) fn first(value: &Value) -> Result<Value, GenerateError> {
    match value {
        Value::List(items) => items
            .first()
            .cloned()
            .ok_or_else(|| GenerateError::index("list index out of range")),
        Value::Str(text) => text
            .chars()
            .next()
            .map(|c| Value::Str(c.to_string()))
            .ok_or_else(|| GenerateError::index("string index out of range")),
        Value::Dict(_) => Err(GenerateError::exception("KeyError", "0")),
        _ => Err(GenerateError::type_error(format!(
            "'{}' object is not subscriptable",
            value.type_name()
        ))),
    }
}
