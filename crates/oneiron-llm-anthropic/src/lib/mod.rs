//! Anthropic Messages wire adapter for Oneiron's [`oneiron::LlmBackend`] seam.
//!
//! The crate owns protocol mapping and classification only. HTTP execution,
//! authentication, cancellation wiring, and retry policy stay host-owned.

mod backend;
mod options;
mod stream;
mod transport;
mod wire;

pub use self::backend::{AnthropicMessagesBackend, AnthropicMessagesConfig};
pub use self::options::{AnthropicProviderOptions, AnthropicThinkingOptions};
pub use self::stream::{AnthropicMessagesLlmStream, AnthropicMessagesStreamAccumulator};
pub use self::transport::{
    AnthropicMessagesFuture, AnthropicMessagesHttpRequest, AnthropicMessagesHttpResponse,
    AnthropicMessagesProviderStream, AnthropicMessagesStreamFrame, AnthropicMessagesTransport,
    AnthropicMessagesTransportError,
};
pub use self::wire::{
    build_anthropic_messages_request, classify_anthropic_status, parse_anthropic_messages_response,
};

#[cfg(test)]
mod tests;

// The flat lib.rs module used to provide these names to the test module
// through `use super::*`: its own private crate/std import header, and every
// crate-internal item the tests name bare. After the directory split the seam
// re-imports both so `tests.rs` resolves exactly as it did before.
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
