//! Import-free, hash-pinned schema validator compartment (base mode).
//!
//! The same guest compiles and evaluates schemas for the one-shot step shim
//! and the code-mode import. Native schema code never runs in the host.

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

const ARTIFACT: &[u8] =
    include_bytes!("../../../../../components/schema-validator/artifacts/validator.wasm");
const SHA256: &str = "bd82dc89962e5dd043404ffb19206462ed91348caf2d45103e51929d3e0154a1";
const MAX_REQUEST_BYTES: usize = 256 * 1024;
const DEFAULT_BUDGET: SchemaValidationBudget = SchemaValidationBudget {
    fuel: 500_000_000,
    memory_bytes: 64 * 1024 * 1024,
    output_bytes: 4096,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct SchemaValidationBudget {
    pub fuel: u64,
    pub memory_bytes: usize,
    pub output_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum SchemaValidationRequest<'a> {
    CheckSchema(&'a Value),
    Validate { schema: &'a Value, value: &'a Value },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum SchemaValidationOutcome {
    Valid,
    InvalidSchema(Vec<String>),
    InvalidValue(Vec<String>),
    LimitExceeded,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestResponse {
    status: String,
    #[serde(default)]
    errors: Vec<String>,
}

thread_local! {
    // Only compiled immutable code is reused. Every call owns a new limited Store.
    static COMPILED: RefCell<Option<(Engine, Module)>> = const { RefCell::new(None) };
}

struct GuestState {
    limits: StoreLimits,
}

pub(super) fn validate(
    request: SchemaValidationRequest<'_>,
) -> Result<SchemaValidationOutcome, &'static str> {
    validate_with_budget(request, DEFAULT_BUDGET)
}

pub(super) fn validate_with_budget(
    request: SchemaValidationRequest<'_>,
    budget: SchemaValidationBudget,
) -> Result<SchemaValidationOutcome, &'static str> {
    let (schema, value) = match request {
        SchemaValidationRequest::CheckSchema(schema) => (schema, None),
        SchemaValidationRequest::Validate { schema, value } => (schema, Some(value)),
    };
    if super::schema_guard::check(schema, value.unwrap_or(&Value::Null)).is_err() {
        return Ok(SchemaValidationOutcome::LimitExceeded);
    }
    let input = match value {
        Some(value) => json!({"op":"validate","schema":schema,"value":value}),
        None => json!({"op":"check","schema":schema}),
    };
    let input = serde_json::to_vec(&input).map_err(|_| "schema request encoding failed")?;
    if input.len() > MAX_REQUEST_BYTES {
        return Ok(SchemaValidationOutcome::LimitExceeded);
    }
    let (engine, module) = COMPILED.with(|cell| {
        if let Some(compiled) = cell.borrow().as_ref() {
            return Ok(compiled.clone());
        }
        if format!("{:x}", Sha256::digest(ARTIFACT)) != SHA256 {
            return Err("schema validator artifact pin mismatch");
        }
        let mut config = Config::new();
        config.consume_fuel(true).max_wasm_stack(512 * 1024);
        let engine = Engine::new(&config).map_err(|_| "schema validator engine failed")?;
        let module =
            Module::new(&engine, ARTIFACT).map_err(|_| "schema validator module failed")?;
        if module.imports().next().is_some() {
            return Err("schema validator artifact has imports");
        }
        *cell.borrow_mut() = Some((engine.clone(), module.clone()));
        Ok((engine, module))
    })?;
    let mut store = Store::new(
        &engine,
        GuestState {
            limits: StoreLimitsBuilder::new()
                .memory_size(budget.memory_bytes)
                .memories(1)
                .tables(1)
                .table_elements(2048)
                .instances(1)
                .trap_on_grow_failure(true)
                .build(),
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(budget.fuel)
        .map_err(|_| "schema validator fuel setup failed")?;
    let instance = Instance::new(&mut store, &module, &[])
        .map_err(|_| "schema validator instantiation failed")?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or("schema validator memory export missing")?;
    let alloc = instance
        .get_typed_func::<u32, u32>(&mut store, "alloc")
        .map_err(|_| "schema validator alloc export missing")?;
    let run = instance
        .get_typed_func::<(u32, u32), u64>(&mut store, "run")
        .map_err(|_| "schema validator run export missing")?;
    let ptr = match alloc.call(&mut store, input.len() as u32) {
        Ok(ptr) if ptr != 0 => ptr,
        Ok(_) => return Ok(SchemaValidationOutcome::LimitExceeded),
        Err(error) => return guest_trap(error),
    };
    memory
        .write(&mut store, ptr as usize, &input)
        .map_err(|_| "schema validator memory write failed")?;
    let result = match run.call(&mut store, (ptr, input.len() as u32)) {
        Ok(result) => result,
        Err(error) => return guest_trap(error),
    };
    let output_len = (result >> 32) as usize;
    let output_ptr = (result as u32) as usize;
    if output_len > budget.output_bytes {
        return Ok(SchemaValidationOutcome::LimitExceeded);
    }
    let mut output = vec![0; output_len];
    memory
        .read(&store, output_ptr, &mut output)
        .map_err(|_| "schema validator memory read failed")?;
    let result: GuestResponse =
        serde_json::from_slice(&output).map_err(|_| "schema validator reply malformed")?;
    match result.status.as_str() {
        "valid" => Ok(SchemaValidationOutcome::Valid),
        "invalid_schema" => Ok(SchemaValidationOutcome::InvalidSchema(result.errors)),
        "invalid_value" => Ok(SchemaValidationOutcome::InvalidValue(result.errors)),
        "limit" => Ok(SchemaValidationOutcome::LimitExceeded),
        _ => Err("schema validator reply unknown"),
    }
}

fn guest_trap(error: wasmtime::Error) -> Result<SchemaValidationOutcome, &'static str> {
    if error.downcast_ref::<wasmtime::Trap>().is_some() {
        Ok(SchemaValidationOutcome::LimitExceeded)
    } else {
        Err("schema validator execution failed")
    }
}
