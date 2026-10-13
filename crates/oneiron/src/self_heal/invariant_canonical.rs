//! Canonicalization of invariant field values for stable comparison.

use rmpv::{Integer, Value};

use super::event::{
    MAX_INVARIANT_DEPTH, MAX_INVARIANT_NODES, MAX_INVARIANT_WIDTH, invalid_diagnostic,
};
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
        Value::String(_) | Value::Map(_) => Err(invalid_diagnostic("invariant value carries text")),
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
