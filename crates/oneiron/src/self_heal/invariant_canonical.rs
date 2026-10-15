//! Canonicalization of invariant field values for stable comparison.

use std::collections::BTreeMap;

use rmpv::{Integer, Value};

use super::diagnostic_codec::decode_str;
use super::event::{
    MAX_INVARIANT_DEPTH, MAX_INVARIANT_NODES, MAX_INVARIANT_WIDTH, invalid_diagnostic,
};
use super::untrusted_text::is_forbidden_text_scalar;
use crate::error::Result;

/// Longest string leaf the grammar before the owner ruling of 2026-10-14
/// accepted inside `expected` / `actual` / `delta`.
const EARLIER_INVARIANT_STRING_LEN: usize = 1024;

// ── invariant-value canonicalization ────────────────────────────────────────

/// Node and depth budget for one `expected` / `actual` / `delta` value, and
/// the grammar the walk reads.
#[derive(Default)]
struct InvariantBudget {
    depth: usize,
    nodes: usize,
    /// Also read the strings and string-keyed maps the grammar before the
    /// owner ruling of 2026-10-14 allowed. Only a stored body is read so.
    earlier_grammar: bool,
    /// The walk met a string or a map, even an empty one: a value only that
    /// grammar allows.
    earlier_only: bool,
}

/// Reads one stored invariant input, and requires it to have arrived
/// canonical.
///
/// Decode uses this rather than plain canonicalization: silently normalizing a
/// stored body would let two different byte strings decode to one event, which
/// breaks the content addressing the replay coordinate rests on.
///
/// A body stored before the owner ruling of 2026-10-14 (fix 6) may hold the
/// strings and string-keyed maps its grammar allowed. A value holding one,
/// even an empty map, is checked against that grammar and reads as `None`, so
/// no decoded event carries its text; the write door refuses it.
pub(super) fn stored_invariant_field(value: &Value) -> Result<Option<Value>> {
    let mut budget = InvariantBudget {
        earlier_grammar: true,
        ..InvariantBudget::default()
    };
    let canonical = canonical_invariant_node(value, &mut budget)?;
    if &canonical != value {
        return Err(invalid_diagnostic("invariant value is not canonical"));
    }
    Ok((!budget.earlier_only).then_some(canonical))
}

/// Rebuilds one invariant input into its single canonical spelling.
///
/// The grammar is deliberately narrow: nil, booleans, integers, finite floats
/// and arrays of those. Floats collapse to `f64`; integers are normalized.
/// Strings and maps (whose keys are strings) are refused, as are binary and
/// extension leaves: a diagnostic never carries world text (owner ruling
/// 2026-10-14), and a grammar with no text in it cannot be talked into
/// carrying some. A finding names what it is about through its evidence refs.
pub(super) fn canonical_invariant_value(value: &Value) -> Result<Value> {
    let mut budget = InvariantBudget::default();
    canonical_invariant_node(value, &mut budget)
}

fn canonical_invariant_node(value: &Value, budget: &mut InvariantBudget) -> Result<Value> {
    budget.nodes += 1;
    if budget.nodes > MAX_INVARIANT_NODES {
        return Err(invalid_diagnostic("invariant value has too many nodes"));
    }
    if budget.depth > MAX_INVARIANT_DEPTH {
        return Err(invalid_diagnostic("invariant value nests too deeply"));
    }
    match value {
        Value::Nil => Ok(Value::Nil),
        Value::Boolean(flag) => Ok(Value::Boolean(*flag)),
        Value::Integer(number) => canonical_invariant_integer(*number),
        Value::F32(number) => canonical_invariant_float(f64::from(*number)),
        Value::F64(number) => canonical_invariant_float(*number),
        Value::Array(items) => canonical_invariant_array(items, budget),
        Value::String(_) | Value::Map(_) if !budget.earlier_grammar => {
            Err(invalid_diagnostic("invariant value carries text"))
        }
        Value::String(_) => earlier_invariant_string(value, budget),
        Value::Map(entries) => earlier_invariant_map(entries, budget),
        Value::Binary(_) | Value::Ext(_, _) => Err(invalid_diagnostic("invariant raw byte leaf")),
    }
}

fn canonical_invariant_integer(number: Integer) -> Result<Value> {
    if let Some(unsigned) = number.as_u64() {
        return Ok(Value::Integer(Integer::from(unsigned)));
    }
    if let Some(signed) = number.as_i64() {
        return Ok(Value::Integer(Integer::from(signed)));
    }
    Err(invalid_diagnostic("invariant integer is out of range"))
}

fn canonical_invariant_float(number: f64) -> Result<Value> {
    if number.is_finite() {
        Ok(Value::F64(number))
    } else {
        Err(invalid_diagnostic("invariant float must be finite"))
    }
}

fn canonical_invariant_array(items: &[Value], budget: &mut InvariantBudget) -> Result<Value> {
    if items.len() > MAX_INVARIANT_WIDTH {
        return Err(invalid_diagnostic("invariant array is too wide"));
    }
    budget.depth += 1;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(canonical_invariant_node(item, budget)?);
    }
    budget.depth -= 1;
    Ok(Value::Array(out))
}

fn earlier_invariant_string(value: &Value, budget: &mut InvariantBudget) -> Result<Value> {
    let text = decode_str(value, "invariant string must be valid UTF-8")?;
    earlier_invariant_text(text, budget).map(Value::from)
}

fn earlier_invariant_text<'a>(text: &'a str, budget: &mut InvariantBudget) -> Result<&'a str> {
    if text.len() > EARLIER_INVARIANT_STRING_LEN {
        return Err(invalid_diagnostic("invariant string is too long"));
    }
    if text.chars().any(is_forbidden_text_scalar) {
        return Err(invalid_diagnostic("invariant string carries controls"));
    }
    budget.earlier_only = true;
    Ok(text)
}

fn earlier_invariant_map(
    entries: &[(Value, Value)],
    budget: &mut InvariantBudget,
) -> Result<Value> {
    if entries.len() > MAX_INVARIANT_WIDTH {
        return Err(invalid_diagnostic("invariant map is too wide"));
    }
    budget.earlier_only = true;
    budget.depth += 1;
    // A `BTreeMap` IS the canonicalization: it sorts by key and it refuses a
    // second value for a key that already has one, in one structure.
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    for (key, value) in entries {
        let key = decode_str(key, "invariant map keys must be strings")?;
        if key.is_empty() {
            return Err(invalid_diagnostic("invariant map key is empty"));
        }
        earlier_invariant_text(key, budget)?;
        let value = canonical_invariant_node(value, budget)?;
        if out.insert(key.to_owned(), value).is_some() {
            return Err(invalid_diagnostic("duplicate invariant map key"));
        }
    }
    budget.depth -= 1;
    Ok(Value::Map(
        out.into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    ))
}
