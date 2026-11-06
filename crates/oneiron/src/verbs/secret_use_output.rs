//! Move already-cleared native secret-use results through the core SDK boundary.

use serde_json::Value;

use super::encode;
use crate::memory::MemoryResult;
use crate::task_verb::sdk::SecretUseAnswer;

pub(super) fn answer(mut output: SecretUseAnswer) -> MemoryResult<Value> {
    let result = output.result.as_mut().map(Value::take);
    let mut encoded = encode(output)?;
    if let Some(result) = result {
        encoded["result"] = result;
    }
    Ok(encoded)
}
