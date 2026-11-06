//! Consuming output conversion for an opaque JSON leaf.

use serde_json::Value;

use super::{Lift, OneironError, WireJson, internal};

enum Step {
    Value(Value),
    Array(std::vec::IntoIter<Value>, bool),
    Object(serde_json::map::IntoIter, bool),
}

impl Lift<Value> for WireJson {
    fn lift(value: Value) -> Result<Self, OneironError> {
        let mut canonical_json = String::new();
        let mut error = None;
        let mut steps = vec![Step::Value(value)];
        while let Some(step) = steps.pop() {
            match step {
                Step::Value(Value::Array(items)) => {
                    canonical_json.push('[');
                    steps.push(Step::Array(items.into_iter(), true));
                }
                Step::Value(Value::Object(entries)) => {
                    canonical_json.push('{');
                    steps.push(Step::Object(entries.into_iter(), true));
                }
                Step::Value(leaf) => scalar(&mut canonical_json, &mut error, &leaf),
                Step::Array(mut items, first) => {
                    if let Some(item) = items.next() {
                        if !first {
                            canonical_json.push(',');
                        }
                        steps.push(Step::Array(items, false));
                        steps.push(Step::Value(item));
                    } else {
                        canonical_json.push(']');
                    }
                }
                Step::Object(mut entries, first) => {
                    if let Some((key, item)) = entries.next() {
                        if !first {
                            canonical_json.push(',');
                        }
                        scalar(&mut canonical_json, &mut error, &key);
                        canonical_json.push(':');
                        steps.push(Step::Object(entries, false));
                        steps.push(Step::Value(item));
                    } else {
                        canonical_json.push('}');
                    }
                }
            }
        }
        match error {
            Some(error) => Err(internal(format!("could not encode a JSON value: {error}"))),
            None => Ok(Self { canonical_json }),
        }
    }
}

fn scalar<T: serde::Serialize>(
    output: &mut String,
    error: &mut Option<serde_json::Error>,
    value: &T,
) {
    // Drain owned container frames even if encoding a scalar fails.
    if error.is_none() {
        match serde_json::to_string(value) {
            Ok(text) => output.push_str(&text),
            Err(failure) => *error = Some(failure),
        }
    }
}
