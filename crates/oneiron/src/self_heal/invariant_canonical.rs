//! Canonicalization of invariant field values for stable comparison.

use std::collections::BTreeMap;

use rmpv::{Integer, Value};

use super::diagnostic_codec::decode_str;
use super::event::{
    MAX_INVARIANT_DEPTH, MAX_INVARIANT_NODES, MAX_INVARIANT_STRING_LEN, MAX_INVARIANT_WIDTH,
    invalid_diagnostic,
};
use super::untrusted_text::is_forbidden_text_scalar;
use crate::error::Result;

// ── invariant-value canonicalization ────────────────────────────────────────

/// Node and depth budget for one `expected` / `actual` / `delta` value.
#[derive(Default)]
struct InvariantBudget {
    depth: usize,
    nodes: usize,
}

/// Canonicalizes an invariant input AND requires it to have arrived canonical.
///
/// Decode uses this rather than plain canonicalization: silently normalizing a
/// stored body would let two different byte strings decode to one event, which
/// breaks the content addressing the replay coordinate rests on.
pub(super) fn canonical_invariant_field(value: &Value) -> Result<Value> {
    let canonical = canonical_invariant_value(value)?;
    if &canonical != value {
        return Err(invalid_diagnostic("invariant value is not canonical"));
    }
    Ok(canonical)
}

/// Rebuilds one invariant input into its single canonical spelling.
///
/// The grammar is deliberately narrow. Floats collapse to `f64` and must be
/// finite; integers are normalized; map keys must be unique strings and are
/// sorted; binary and extension leaves are refused outright (a hash belongs
/// here as hex). Strings must be ENGINE-AUTHORED: control data is refused so
/// [`DiagnosticEvent::untrusted_detail`] stays the ONLY door untrusted text
/// enters through, rather than one of four.
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
        Value::String(_) => canonical_invariant_string(value),
        Value::Array(items) => canonical_invariant_array(items, budget),
        Value::Map(entries) => canonical_invariant_map(entries, budget),
        Value::Binary(_) | Value::Ext(_, _) => Err(invalid_diagnostic("invariant raw byte leaf")),
    }
}

fn canonical_invariant_string(value: &Value) -> Result<Value> {
    let text = decode_str(value, "invariant string must be valid UTF-8")?;
    canonical_invariant_text(text).map(Value::from)
}

fn canonical_invariant_text(text: &str) -> Result<&str> {
    if text.len() > MAX_INVARIANT_STRING_LEN {
        return Err(invalid_diagnostic("invariant string is too long"));
    }
    if text.chars().any(is_forbidden_text_scalar) {
        return Err(invalid_diagnostic("invariant string carries controls"));
    }
    Ok(text)
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

fn canonical_invariant_map(
    entries: &[(Value, Value)],
    budget: &mut InvariantBudget,
) -> Result<Value> {
    if entries.len() > MAX_INVARIANT_WIDTH {
        return Err(invalid_diagnostic("invariant map is too wide"));
    }
    budget.depth += 1;
    // A `BTreeMap` IS the canonicalization: it sorts by key and it refuses a
    // second value for a key that already has one, in one structure.
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    for (key, value) in entries {
        let key = decode_str(key, "invariant map keys must be strings")?;
        if key.is_empty() {
            return Err(invalid_diagnostic("invariant map key is empty"));
        }
        canonical_invariant_text(key)?;
        let value = canonical_invariant_node(value, budget)?;
        if out.insert(key.to_owned(), value).is_some() {
            return Err(invalid_diagnostic("duplicate invariant map key"));
        }
    }
    budget.depth -= 1;
    let mut sorted = Vec::with_capacity(out.len());
    for (key, value) in out {
        sorted.push((Value::from(key), value));
    }
    Ok(Value::Map(sorted))
}
