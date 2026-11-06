//! Move native key-value payloads through the core SDK result boundary.

use serde_json::Value;

use crate::memory::{KeyValueItem, KeyValuePutReceipt, MemoryResult};

use super::encode;

pub(super) fn get(mut output: Option<KeyValueItem>) -> MemoryResult<Value> {
    let payload = output.as_mut().map(|item| item.value.take());
    let mut encoded = encode(output)?;
    if let Some(payload) = payload {
        encoded["value"] = payload;
    }
    Ok(encoded)
}

pub(super) fn put(mut output: KeyValuePutReceipt) -> MemoryResult<Value> {
    let payload = output.item.value.take();
    let mut encoded = encode(output)?;
    encoded["item"]["value"] = payload;
    Ok(encoded)
}

pub(super) fn search(mut output: Vec<KeyValueItem>) -> MemoryResult<Value> {
    // Drain every payload before the finite codec can return an error.
    let payloads: Vec<_> = output.iter_mut().map(|item| item.value.take()).collect();
    let mut encoded = encode(output)?;
    for (index, payload) in payloads.into_iter().enumerate() {
        encoded[index]["value"] = payload;
    }
    Ok(encoded)
}
