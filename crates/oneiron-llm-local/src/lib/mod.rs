//! Local in-process adapter for Oneiron's [`LlmBackend`] seam.
//!
//! This crate intentionally does not download, select, or quantize models. It
//! adapts an already-loaded llama.cpp/mistral.rs-class runtime into the engine
//! trait and derives runtime capabilities from loaded model metadata.

mod abort;
mod backend;
mod capabilities;
mod metadata;
mod output;
mod stream;

pub use self::abort::LocalAbortHandle;
pub use self::backend::{LocalLlmBackend, LocalLlmRuntime};
pub use self::metadata::LocalModelMetadata;
pub use self::output::{LocalGeneration, LocalOutputPart};

#[cfg(test)]
mod tests;

// The flat lib.rs module used to provide these names to the test module
// through `use super::*`: its own private crate/std import header. The
// lib-internal items the tests name bare resolve through the re-exports
// above. After the directory split the seam re-imports the header so
// `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use futures_core::Stream;
#[cfg(test)]
use oneiron::{
    BudgetLease, ContentPart, FatalLlmError, FinishReason, LlmBackend, LlmCapability, LlmMessage,
    LlmMessageRole, LlmRequest, LlmResult, LlmStream, LlmStreamEvent, LlmUsage, ModelId,
    ModelLocality, ResponseFormat, UnsupportedCapability,
};
#[cfg(test)]
use serde_json::Value as JsonValue;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::task::Poll;
