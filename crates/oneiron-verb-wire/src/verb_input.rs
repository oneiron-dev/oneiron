//! The input checks and input schemas of the verb rows whose input type this crate holds (lib split W3-GEN),
//! generated at build time from the verb table (crates/oneiron-sdk-build).
//!
//! `oneiron`'s `validate_input` and `input_schema` answer from here first and hold the other rows themselves: a row
//! whose input check runs admission checks, takes a board shape and a host shape, or is feature-gated, and a row whose
//! input names a type the engine holds, stays there. Each row is in exactly one of the two tables.

// A generated check is named after its verb, whose name keeps its own casing (`vault.skills.restoreDefaults` ->
// `validate_input_vault_skills_restoreDefaults`), as the engine's generated fns are.
#![allow(non_snake_case)]

use oneiron_contracts::memory::{MemoryError, MemoryResult};

/// A verb's input decoded from its JSON value; a value that does not decode is `bad_request`, naming the path of the
/// field that failed.
///
/// # Errors
///
/// `bad_request` when the value is no `T`.
pub fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> MemoryResult<T> {
    serde_path_to_error::deserialize(value)
        .map_err(|error| MemoryError::bad_request(format!("invalid SDK request: {error}")))
}

include!(concat!(env!("OUT_DIR"), "/verb_input_checks.rs"));
