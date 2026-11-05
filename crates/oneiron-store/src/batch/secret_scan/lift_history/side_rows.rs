//! The side tables the catalog classes as authored. A row that holds a hit
//! is admitted as a write of it is, by the side-row wall, and stored with its
//! handles. At a write the wall checks a masked copy with the table's own
//! codec; here the check is the table's declared typed acceptance when it
//! names one (FIX 2680), else that the copy keeps the row's shape, each value
//! its kind, so the row's own type still reads it. A copy that does not
//! keeps its row and files a proposal.

use std::borrow::Cow;

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use oneiron_base::error::Result;

/// `bytes` as the door reads a body: JSON, a whole MessagePack value, or
/// text.
pub fn read(bytes: &[u8]) -> Option<Value> {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        return Some(value);
    }
    let mut cursor = std::io::Cursor::new(bytes);
    if let Ok(value) = rmpv::decode::read_value(&mut cursor)
        && cursor.position() == bytes.len() as u64
    {
        return Some(value);
    }
    std::str::from_utf8(bytes).ok().map(Value::from)
}

pub fn same_shape(before: &Value, after: &Value) -> bool {
    match (before, after) {
        // Bytes spelled as an array of byte values may change length.
        (Value::Array(before), Value::Array(after)) => {
            (byte_values(before) && byte_values(after))
                || (before.len() == after.len()
                    && before
                        .iter()
                        .zip(after)
                        .all(|(before, after)| same_shape(before, after)))
        }
        (Value::Map(before), Value::Map(after)) => {
            before.len() == after.len()
                && before
                    .iter()
                    .zip(after)
                    .all(|((key, value), (again, masked))| {
                        same_shape(key, again) && same_shape(value, masked)
                    })
        }
        _ => std::mem::discriminant(before) == std::mem::discriminant(after),
    }
}

fn byte_values(items: &[Value]) -> bool {
    items
        .iter()
        .all(|item| item.as_u64().is_some_and(|n| n <= u64::from(u8::MAX)))
}
