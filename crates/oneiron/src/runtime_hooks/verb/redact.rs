//! A post-hook's Redact (ARCH-0080 §3): fields removed or masked in this
//! caller's view of the result. The vault keeps the real result. A path is a
//! JSON pointer (`/rows/0/body`) or dotted (`rows.0.body`); `*` takes every
//! child. An object field is removed, an array element masked to null, and
//! the empty path masks the whole view. Nothing restores what one hid.

use serde_json::Value;

/// Paths one Redact may name.
pub(super) const MAX_PATHS: usize = 64;
/// Bytes one path may hold.
pub(super) const MAX_PATH_BYTES: usize = 256;

/// Hides `path` in `view`. A path that names nothing hides nothing.
pub(super) fn hide(view: &mut Value, path: &str) {
    if path.is_empty() {
        *view = Value::Null;
        return;
    }
    let segments: Vec<String> = match path.strip_prefix('/') {
        Some(pointer) => pointer
            .split('/')
            .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
            .collect(),
        None => path.split('.').map(str::to_owned).collect(),
    };
    hide_at(view, &segments);
}

fn hide_at(node: &mut Value, path: &[String]) {
    let [segment, rest @ ..] = path else {
        return;
    };
    let every = segment == "*";
    if rest.is_empty() {
        match node {
            Value::Object(fields) if every => fields.clear(),
            Value::Object(fields) => {
                fields.remove(segment.as_str());
            }
            Value::Array(items) if every => items.iter_mut().for_each(|item| *item = Value::Null),
            Value::Array(items) => {
                if let Some(item) = index(segment).and_then(|at| items.get_mut(at)) {
                    *item = Value::Null;
                }
            }
            _ => {}
        }
        return;
    }
    match node {
        Value::Object(fields) if every => {
            fields.values_mut().for_each(|child| hide_at(child, rest))
        }
        Value::Object(fields) => {
            if let Some(child) = fields.get_mut(segment.as_str()) {
                hide_at(child, rest);
            }
        }
        Value::Array(items) if every => items.iter_mut().for_each(|child| hide_at(child, rest)),
        Value::Array(items) => {
            if let Some(child) = index(segment).and_then(|at| items.get_mut(at)) {
                hide_at(child, rest);
            }
        }
        _ => {}
    }
}

fn index(segment: &str) -> Option<usize> {
    segment.parse().ok()
}
