//! The engine's JSON Schema implementation behind an import-free Wasm ABI.
//! Every request gets a new Wasmtime Store. The host, not this guest, meters fuel,
//! memory, stack and returned bytes. No resolver callbacks or WASI are linked.

use serde_json::{Value, json};

const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_ERRORS: usize = 8;
const MAX_ERROR_CHARS: usize = 256;

#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: u32) -> u32 {
    if len as usize > MAX_INPUT_BYTES {
        return 0;
    }
    let mut bytes = Vec::<u8>::with_capacity(len as usize);
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr as u32
}

// High 32 bits: output byte length; low 32 bits: pointer in the guest memory.
#[unsafe(no_mangle)]
pub extern "C" fn run(ptr: u32, len: u32) -> u64 {
    if len as usize > MAX_INPUT_BYTES {
        return respond(json!({"status":"limit"}));
    }
    // The host writes only into the region returned by `alloc` in this Store.
    let bytes = unsafe { std::slice::from_raw_parts(ptr as usize as *const u8, len as usize) };
    let request: Value = match serde_json::from_slice(bytes) {
        Ok(request) => request,
        Err(_) => return respond(json!({"status":"bad_request"})),
    };
    let Some(schema) = request.get("schema") else {
        return respond(json!({"status":"bad_request"}));
    };
    let validator = match jsonschema::validator_for(schema) {
        Ok(validator) => validator,
        Err(error) => {
            return respond(json!({"status":"invalid_schema","errors":[short(&error.to_string())]}));
        }
    };
    if request.get("op").and_then(Value::as_str) == Some("check") {
        return respond(json!({"status":"valid"}));
    }
    if request.get("op").and_then(Value::as_str) != Some("validate") || request.get("value").is_none() {
        return respond(json!({"status":"bad_request"}));
    }
    let errors: Vec<String> = validator
        .iter_errors(&request["value"])
        .take(MAX_ERRORS)
        .map(|error| short(&error.to_string()))
        .collect();
    if errors.is_empty() {
        respond(json!({"status":"valid"}))
    } else {
        respond(json!({"status":"invalid_value","errors":errors}))
    }
}

fn short(text: &str) -> String {
    text.chars().take(MAX_ERROR_CHARS).collect()
}

fn respond(result: Value) -> u64 {
    let bytes = result.to_string().into_bytes().into_boxed_slice();
    let len = bytes.len() as u64;
    let ptr = bytes.as_ptr() as u32 as u64;
    std::mem::forget(bytes);
    (len << 32) | ptr
}

// No ambient entropy import: aHash asks for a seed at schema compilation.
// This deterministic seed is not an authority/security source. Its only use is
// an internal hash table in a fuel-limited, per-call Store. The budget, not a
// secret hash key, is what limits hostile collision work.
/// # Safety
/// `dest` points to at least `len` writable bytes supplied by getrandom.
#[unsafe(no_mangle)]
pub unsafe fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
    for index in 0..len {
        let byte = ((index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 56) as u8;
        unsafe { dest.add(index).write(byte) };
    }
    Ok(())
}
