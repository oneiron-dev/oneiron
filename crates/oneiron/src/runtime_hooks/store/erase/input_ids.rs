//! The ids a hook run's saved JSON input names, read before the pin bound
//! drops any of it: from a decoded value ([`named_ids`]), from text no
//! value may hold ([`spelled_ids_in`]), and from a verb run's input that
//! does not decode, by its members ([`DeepInput`]), with what an erase does
//! to such an input ([`erase_deep_verb_input`]).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use serde_json::value::RawValue;

use super::{ErasedIds, name_erased_verb_actors};
use crate::EntityId;

/// Adds to `ids` each id `text` names: every run of exactly 32 lowercase
/// hex digits that reads as one, as a record spells an id. A longer run,
/// such as a digest, names none.
fn hex_ids_in(text: &str, ids: &mut BTreeSet<EntityId>) {
    for token in text.split(|digit: char| !matches!(digit, '0'..='9' | 'a'..='f')) {
        if token.len() == 32
            && let Ok(id) = EntityId::from_hex(token)
        {
            ids.insert(id);
        }
    }
}

/// The rows a verb run's caller named in its own args and result, and in
/// the args its landing was judged on ([`named_ids`]), read from the whole
/// input before the pin bound drops any of it (review #6817): a row named
/// there can carry its bytes into the run's outcome. An input that does
/// not decode names them by its members ([`DeepInput::named_rows`]), so its
/// caller, tail and hook ids name no row there either (REVIEW-9897 round
/// 2); text that does not read so names every id it spells.
pub(in crate::runtime_hooks) fn rows_named_by_call(
    input: &str,
    landing_original: Option<&str>,
) -> Vec<EntityId> {
    let mut rows = BTreeSet::new();
    match serde_json::from_str::<Value>(input) {
        Ok(value) => {
            for field in ["args", "result"] {
                if let Some(part) = value.get(field) {
                    named_ids(part, &mut rows);
                }
            }
        }
        Err(_) => match DeepInput::read(input) {
            Some(deep) => deep.named_rows(&mut rows),
            None => spelled_ids_in(input, &mut rows),
        },
    }
    if let Some(args) = landing_original {
        match serde_json::from_str::<Value>(args) {
            Ok(value) => named_ids(&value, &mut rows),
            Err(_) => spelled_ids_in(args, &mut rows),
        }
    }
    rows.into_iter().collect()
}

/// A verb run's saved input that does not decode, read by its top-level
/// members: only its result, a skill answer, can nest past what a value
/// holds (SKILL-ANSWER-DEEP-JSON-STACK-SAFE), so it stays text, read with
/// no recursion, and every other member, the args among them, came from a
/// value and reads as one.
struct DeepInput<'t> {
    /// Every member but `result`, as an object value.
    fields: Value,
    result: Option<&'t RawValue>,
}

impl<'t> DeepInput<'t> {
    /// `input` by its members; `None` when it is no object or a member
    /// other than `result` does not read as a value.
    fn read(input: &'t str) -> Option<Self> {
        let members: BTreeMap<String, &'t RawValue> = serde_json::from_str(input).ok()?;
        let mut fields = serde_json::Map::new();
        let mut result = None;
        for (key, member) in members {
            if key == "result" {
                result = Some(member);
            } else {
                fields.insert(key, serde_json::from_str(member.get()).ok()?);
            }
        }
        Some(Self {
            fields: Value::Object(fields),
            result,
        })
    }

    /// Adds to `rows` each id its args and result name, as a decoded
    /// input's do ([`rows_named_by_call`]): the result's as its text spells
    /// them ([`spelled_ids_in`]).
    fn named_rows(&self, rows: &mut BTreeSet<EntityId>) {
        if let Some(args) = self.fields.get("args") {
            named_ids(args, rows);
        }
        if let Some(result) = self.result {
            spelled_ids_in(result.get(), rows);
        }
    }

    /// The input as JSON text again, its result verbatim.
    fn to_text(&self) -> Option<String> {
        let mut members = BTreeMap::new();
        for (key, field) in self.fields.as_object()? {
            members.insert(key.as_str(), serde_json::value::to_raw_value(field).ok()?);
        }
        if let Some(result) = self.result {
            members.insert("result", result.to_owned());
        }
        serde_json::to_string(&members).ok()
    }
}

/// What an erase does to a verb run's saved input that does not decode
/// ([`erase_deep_verb_input`]).
pub(super) enum DeepInputErase {
    Unchanged,
    /// Its args or result name an erased row.
    Depends,
    /// The input with each erased actor in it named as the marker.
    Renamed(String),
    /// It spells an erased id and does not read by its members, or does
    /// not encode again: it loses its payload.
    Scrubbed,
}

/// [`super::erase_verb_run`] over a saved `input` that does not decode, as over a
/// decoded one (REVIEW-9897 round 2): an erased row its args or result name
/// retires the run; otherwise each erased actor in it (its caller, its
/// tail's actors) names the marker and the rest stays, the result
/// verbatim.
pub(super) fn erase_deep_verb_input(input: &str, erased: &ErasedIds) -> DeepInputErase {
    let Some(mut deep) = DeepInput::read(input) else {
        return if erased.spelled_in(input) {
            DeepInputErase::Scrubbed
        } else {
            DeepInputErase::Unchanged
        };
    };
    let mut named = BTreeSet::new();
    deep.named_rows(&mut named);
    if !named.is_disjoint(&erased.ids) {
        return DeepInputErase::Depends;
    }
    if !name_erased_verb_actors(&mut deep.fields, erased) {
        return DeepInputErase::Unchanged;
    }
    deep.to_text()
        .map_or(DeepInputErase::Scrubbed, DeepInputErase::Renamed)
}

/// Door seam for `test_doors::typed_reply_handle`: what an erase of `ids`
/// does to a verb run whose saved input `input` does not decode.
#[cfg(oneiron_test_support)]
pub(in crate::runtime_hooks) fn erase_deep_input_for_test(
    input: &str,
    ids: &[EntityId],
) -> (&'static str, Option<String>) {
    match erase_deep_verb_input(input, &ErasedIds::new(ids.iter().copied().collect())) {
        DeepInputErase::Unchanged => ("unchanged", None),
        DeepInputErase::Depends => ("depends", None),
        DeepInputErase::Renamed(input) => ("renamed", Some(input)),
        DeepInputErase::Scrubbed => ("scrubbed", None),
    }
}

/// The rows a fact run's whole `input` names anywhere but as the fact's
/// actor (`/fact/actor/principal`), whose erase only renames it: read
/// before the pin bound drops the input, so an erase of one retires the
/// memo even when its input was not kept (FIX 22240). An input that does
/// not decode names every id it can spell.
pub(in crate::runtime_hooks) fn rows_named_by_fact(input: &str) -> Vec<EntityId> {
    let mut rows = BTreeSet::new();
    match serde_json::from_str::<Value>(input) {
        Ok(mut value) => {
            if let Some(actor) = value.pointer_mut("/fact/actor/principal") {
                *actor = Value::Null;
            }
            named_ids(&value, &mut rows);
        }
        Err(_) => spelled_ids_in(input, &mut rows),
    }
    rows.into_iter().collect()
}

/// Adds to `ids` each id the JSON `text` can spell in a string or key once
/// decoded: [`hex_ids_in`] over `text` with its escapes read
/// ([`escapes_read`]), so an id counts however a string spells it, and a
/// longer run, such as a digest, names none, as in the decoded value. Its
/// escapes read, no escape lengthens a run. Flat, so it reads text no value
/// may hold. A superset (a number's digits read too), each one checked
/// before it counts.
pub(super) fn spelled_ids_in(text: &str, ids: &mut BTreeSet<EntityId>) {
    let read = escapes_read(text);
    hex_ids_in(read.as_deref().unwrap_or(text), ids);
}

/// JSON `text` with each escape read for an id scan: a `\u` escape that
/// spells a lowercase hex digit becomes that digit, every other escape a
/// space, so an id a string spells through escapes reads as one run, as it
/// does once decoded. Flat, so it reads text no value may hold (a nesting
/// past serde_json's limit). `None` when `text` holds no escape.
pub(super) fn escapes_read(text: &str) -> Option<String> {
    if !text.contains('\\') {
        return None;
    }
    let mut read = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(next) = chars.next() {
        if next != '\\' {
            read.push(next);
            continue;
        }
        let digit = match chars.next() {
            Some('u') => u32::from_str_radix(&chars.by_ref().take(4).collect::<String>(), 16)
                .ok()
                .and_then(char::from_u32)
                .filter(|digit| matches!(digit, '0'..='9' | 'a'..='f')),
            _ => None,
        };
        read.push(digit.unwrap_or(' '));
    }
    Some(read)
}

/// [`hex_ids_in`] over every string and key of `value`.
pub(super) fn named_ids(value: &Value, ids: &mut BTreeSet<EntityId>) {
    match value {
        Value::String(text) => hex_ids_in(text, ids),
        Value::Array(items) => {
            for item in items {
                named_ids(item, ids);
            }
        }
        Value::Object(fields) => {
            for (key, field) in fields {
                hex_ids_in(key, ids);
                named_ids(field, ids);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}
