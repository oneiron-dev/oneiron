//! OpenAI-compatible wire adapter for Oneiron's [`oneiron::LlmBackend`] seam.
//!
//! The crate owns protocol mapping and classification only. HTTP execution,
//! authentication, cancellation wiring, and retry policy stay host-owned.

mod backend;
mod options;
mod stream;
mod transport;
mod wire;

pub use self::backend::{OpenAiCompatBackend, OpenAiCompatConfig};
pub use self::options::{OpenAiProviderOptions, OpenAiReasoningOptions};
pub use self::stream::{OpenAiCompatLlmStream, OpenAiCompatStreamAccumulator};
pub use self::transport::{
    OpenAiCompatFuture, OpenAiCompatHttpRequest, OpenAiCompatHttpResponse,
    OpenAiCompatProviderStream, OpenAiCompatStreamFrame, OpenAiCompatTransport,
    OpenAiCompatTransportError,
};
pub use self::wire::{
    build_openai_chat_request, classify_openai_status, parse_openai_chat_response,
};

#[cfg(test)]
mod tests;

// The flat lib.rs module used to provide these names to the inline test
// module through `use super::*`: its own oneiron/std import header, and the
// `json!` macro. After the directory split the seam re-imports them so
// `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use oneiron::{
    ContentPart, FatalLlmError, FinishReason, LlmCapability, LlmCatalogEntry, LlmError,
    LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmStreamEvent,
    LlmToolSpec, LlmUsage, ModelId, ResponseFormat, RetryableLlmError, UnsupportedCapability,
};
#[cfg(test)]
use serde_json::json;
#[cfg(test)]
use std::collections::BTreeMap;
