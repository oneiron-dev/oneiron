//! RFC-6902 JSON Patch for the patch stream profile (FIX 7968): the
//! operation type, its all-or-nothing application over RFC-6901 pointers,
//! and the diff that writes one card's refinement as operations.
//!
//! This is transport vocabulary only. The card-local `$state` patch
//! ([`super::GeneratedUiStatePatch`]) keeps its own add/replace/remove rules,
//! and a patched card is decoded and validated again whole, so a patch can
//! never carry what a complete card could not.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

/// One RFC-6902 operation. Paths and `from` are RFC-6901 JSON Pointers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratedUiJsonPatchOperation {
    Add { path: String, value: Value },
    Remove { path: String },
    Replace { path: String, value: Value },
    Move { from: String, path: String },
    Copy { from: String, path: String },
    Test { path: String, value: Value },
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidConfig(format!("generated-ui card_state_patch: {}", message.into()))
}

/// Applies every operation to `document`, or none: a failing operation
/// leaves `document` as it was.
pub(super) fn apply_json_patch(
    document: &mut Value,
    operations: &[GeneratedUiJsonPatchOperation],
) -> Result<()> {
    let mut patched = document.clone();
    for operation in operations {
        match operation {
            GeneratedUiJsonPatchOperation::Add { path, value } => {
                add(&mut patched, path, value.clone())?;
            }
            GeneratedUiJsonPatchOperation::Remove { path } => {
                remove(&mut patched, path)?;
            }
            GeneratedUiJsonPatchOperation::Replace { path, value } => {
                *target_mut(&mut patched, path)? = value.clone();
            }
            GeneratedUiJsonPatchOperation::Move { from, path } => {
                if path.starts_with(&format!("{from}/")) {
                    return Err(invalid("move may not put a value inside itself"));
                }
                let value = remove(&mut patched, from)?;
                add(&mut patched, path, value)?;
            }
            GeneratedUiJsonPatchOperation::Copy { from, path } => {
                let value = target(&patched, from)?.clone();
                add(&mut patched, path, value)?;
            }
            GeneratedUiJsonPatchOperation::Test { path, value } => {
                if target(&patched, path)? != value {
                    return Err(invalid(format!("test failed at {path}")));
                }
            }
        }
    }
    *document = patched;
    Ok(())
}

/// One RFC-6901 reference token, escaped.
pub(super) fn pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn tokens(pointer: &str) -> Result<Vec<String>> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let Some(rest) = pointer.strip_prefix('/') else {
        return Err(invalid(format!("pointer {pointer:?} must start with '/'")));
    };
    rest.split('/')
        .map(|token| {
            if token.contains('~')
                && token
                    .split('~')
                    .skip(1)
                    .any(|after| !after.starts_with('0') && !after.starts_with('1'))
            {
                return Err(invalid(format!("pointer {pointer:?} has a bad '~' escape")));
            }
            Ok(token.replace("~1", "/").replace("~0", "~"))
        })
        .collect()
}

fn array_index(token: &str, len: usize, allow_end: bool) -> Result<usize> {
    if allow_end && token == "-" {
        return Ok(len);
    }
    let numeric = !token.is_empty()
        && token.bytes().all(|byte| byte.is_ascii_digit())
        && (token == "0" || !token.starts_with('0'));
    let index = numeric
        .then(|| token.parse::<usize>().ok())
        .flatten()
        .ok_or_else(|| invalid(format!("{token:?} is not an array index")))?;
    if index > len || (!allow_end && index == len) {
        return Err(invalid(format!("array index {index} is out of range")));
    }
    Ok(index)
}

fn target<'a>(document: &'a Value, pointer: &str) -> Result<&'a Value> {
    let mut current = document;
    for token in tokens(pointer)? {
        current = match current {
            Value::Object(map) => map.get(&token),
            Value::Array(items) => items.get(array_index(&token, items.len(), false)?),
            _ => None,
        }
        .ok_or_else(|| invalid(format!("{pointer} names no value")))?;
    }
    Ok(current)
}

fn target_mut<'a>(document: &'a mut Value, pointer: &str) -> Result<&'a mut Value> {
    let mut current = document;
    for token in tokens(pointer)? {
        current = match current {
            Value::Object(map) => map.get_mut(&token),
            Value::Array(items) => {
                let index = array_index(&token, items.len(), false)?;
                items.get_mut(index)
            }
            _ => None,
        }
        .ok_or_else(|| invalid(format!("{pointer} names no value")))?;
    }
    Ok(current)
}

/// The parent of `pointer` and its last token; `None` for the whole document.
fn split_last(pointer: &str) -> Result<Option<(String, String)>> {
    let mut parts = tokens(pointer)?;
    let Some(last) = parts.pop() else {
        return Ok(None);
    };
    let parent = parts
        .iter()
        .map(|token| format!("/{}", pointer_token(token)))
        .collect::<String>();
    Ok(Some((parent, last)))
}

fn add(document: &mut Value, pointer: &str, value: Value) -> Result<()> {
    let Some((parent, last)) = split_last(pointer)? else {
        *document = value;
        return Ok(());
    };
    match target_mut(document, &parent)? {
        Value::Object(map) => {
            map.insert(last, value);
        }
        Value::Array(items) => {
            let index = array_index(&last, items.len(), true)?;
            items.insert(index, value);
        }
        _ => return Err(invalid(format!("{pointer}'s parent holds no members"))),
    }
    Ok(())
}

fn remove(document: &mut Value, pointer: &str) -> Result<Value> {
    let Some((parent, last)) = split_last(pointer)? else {
        return Err(invalid("remove may not name the whole document"));
    };
    match target_mut(document, &parent)? {
        Value::Object(map) => map
            .remove(&last)
            .ok_or_else(|| invalid(format!("{pointer} names no value"))),
        Value::Array(items) => {
            let index = array_index(&last, items.len(), false)?;
            Ok(items.remove(index))
        }
        _ => Err(invalid(format!("{pointer}'s parent holds no members"))),
    }
}

/// The operations that turn `before` into `after`. The members named in
/// `keyed` are diffed one entry at a time, so a node is addressed by its
/// stable id and a `$state` value by its key; any other member that changed
/// is replaced whole.
pub(super) fn diff_json(
    before: &Value,
    after: &Value,
    keyed: &[&str],
) -> Vec<GeneratedUiJsonPatchOperation> {
    let (Value::Object(before), Value::Object(after)) = (before, after) else {
        return if before == after {
            Vec::new()
        } else {
            vec![GeneratedUiJsonPatchOperation::Replace {
                path: String::new(),
                value: after.clone(),
            }]
        };
    };
    let mut operations = Vec::new();
    let names = before.keys().chain(after.keys()).collect::<BTreeSet<_>>();
    for name in names {
        let path = format!("/{}", pointer_token(name));
        match (before.get(name), after.get(name)) {
            (Some(old), Some(new)) if old == new => {}
            (Some(Value::Object(old)), Some(Value::Object(new))) if keyed.contains(&name.as_str()) => {
                let keys = old.keys().chain(new.keys()).collect::<BTreeSet<_>>();
                for key in keys {
                    let entry = format!("{path}/{}", pointer_token(key));
                    match (old.get(key), new.get(key)) {
                        (Some(a), Some(b)) if a == b => {}
                        (Some(_), Some(b)) => operations.push(GeneratedUiJsonPatchOperation::Replace {
                            path: entry,
                            value: b.clone(),
                        }),
                        (None, Some(b)) => operations.push(GeneratedUiJsonPatchOperation::Add {
                            path: entry,
                            value: b.clone(),
                        }),
                        (Some(_), None) => {
                            operations.push(GeneratedUiJsonPatchOperation::Remove { path: entry });
                        }
                        (None, None) => {}
                    }
                }
            }
            (Some(_), Some(new)) => operations.push(GeneratedUiJsonPatchOperation::Replace {
                path,
                value: new.clone(),
            }),
            (None, Some(new)) => operations.push(GeneratedUiJsonPatchOperation::Add {
                path,
                value: new.clone(),
            }),
            (Some(_), None) => operations.push(GeneratedUiJsonPatchOperation::Remove { path }),
            (None, None) => {}
        }
    }
    operations
}
