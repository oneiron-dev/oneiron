//! OpenAI-compatible wire adapter for Oneiron's [`oneiron::LlmBackend`] seam.
//!
//! The crate owns protocol mapping and classification only. HTTP execution,
//! authentication, cancellation wiring, and retry policy stay host-owned.

mod backend;
mod image;
pub use self::image::{
    DirectOpenAiImageBackend, OpenAiImageBody, OpenAiImageHttpRequest, OpenAiImageHttpResponse,
    OpenAiImagePart, OpenAiImageTransport, OpenAiImageTransportFuture,
};
mod media;
pub use self::media::{
    OpenAiMediaBackend, OpenAiMediaBody, OpenAiMediaHttpRequest, OpenAiMediaHttpResponse,
    OpenAiMediaMethod, OpenAiMediaTransport, OpenAiMediaTransportFuture,
};
mod options;
mod responses;
mod stream;
mod transport;
mod wire;

pub use self::backend::{OpenAiCompatBackend, OpenAiCompatConfig};
pub use self::options::{OpenAiProviderOptions, OpenAiReasoningOptions};
pub use self::responses::{
    OpenAiResponsesChain, OpenAiResponsesLlmStream, OpenAiResponsesStreamAccumulator,
    OpenAiResponsesTurn, RESPONSES_PREVIOUS_NOT_FOUND, RESPONSES_SOCKET_LIMIT,
    build_openai_responses_turn, openai_responses_items, parse_openai_responses_output,
    responses_can_carry, responses_error_code, responses_event_is_terminal, responses_event_type,
    responses_item_digests,
};
pub use self::stream::{OpenAiCompatLlmStream, OpenAiCompatStreamAccumulator};
pub use self::transport::{
    OpenAiCompatFuture, OpenAiCompatHttpRequest, OpenAiCompatHttpResponse,
    OpenAiCompatProviderStream, OpenAiCompatStreamFrame, OpenAiCompatTransport,
    OpenAiCompatTransportError,
};
pub use self::wire::{
    build_openai_chat_request, classify_openai_status, parse_openai_chat_response,
};

// The flat lib.rs module used to provide these names to the inline test
// module through `use super::*`: its own oneiron/std import header, and the
// `json!` macro. After the directory split the seam re-imports them so
// `tests.rs` resolves exactly as it did before.

#[cfg(test)]
mod tests;
