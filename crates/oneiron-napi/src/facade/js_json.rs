//! JSON values from JavaScript, read as the typed decode behind them reads
//! them (FIX 2884, 4804).

/// JavaScript's `Number.MAX_SAFE_INTEGER`, the largest whole number a JS
/// number holds exactly.
const JS_MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// One JSON value from JavaScript, as the typed decode behind it reads it
/// (FIX 2884). napi hands a whole JS number past the 32-bit range over as a
/// float, which an integer field refuses; every whole number within the safe
/// range reads back as the integer it is, at any depth, so a millisecond
/// `u64` reads. A fractional number stays a float, and a whole number past
/// the safe range stays the float it is, which an integer field refuses: its
/// exact value is already lost. Every JSON-valued N-API method (the generated
/// rows, `retry`, `lensFrameEvent`) reads its argument through this, and so
/// does every caller-owned JSON leaf of a typed input (FIX 4804): a witness
/// message's metadata, a claim's value and scope, a structural body, a habit
/// check-in's data, an imported claim's value and a consolidation's input.
/// Returned bodies are never rewritten.
pub(crate) fn js_json(mut value: serde_json::Value) -> serde_json::Value {
    js_integers(&mut value);
    value
}

fn js_integers(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Number(number) => {
            if let Some(whole) = js_safe_integer(number) {
                *number = whole;
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(js_integers),
        serde_json::Value::Object(fields) => fields.values_mut().for_each(js_integers),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => {}
    }
}

/// A float that holds a safe whole number, as that integer; `None` for an
/// integer already, a fraction, a non-finite value or an unsafe whole number.
fn js_safe_integer(number: &serde_json::Number) -> Option<serde_json::Number> {
    if !number.is_f64() {
        return None;
    }
    let float = number.as_f64()?;
    if !float.is_finite() || float.fract() != 0.0 || float.abs() > JS_MAX_SAFE_INTEGER {
        return None;
    }
    // A whole number within ±(2^53 - 1) converts to i64 exactly.
    let whole = float as i64;
    Some(u64::try_from(whole).map_or_else(|_| whole.into(), serde_json::Number::from))
}
