//! Move stored conversation bodies through the core SDK result boundary.

use serde_json::Value;

use crate::core_write::CoreEntityWriteReceipt;
use crate::memory::MemoryResult;

use super::encode;

pub(super) fn entity(mut output: CoreEntityWriteReceipt) -> MemoryResult<Value> {
    let body = output.body.take();
    let mut encoded = encode(output)?;
    encoded["body"] = body;
    Ok(encoded)
}
