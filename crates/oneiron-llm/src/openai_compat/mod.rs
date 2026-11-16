//! OpenAI-compatible wire adapter for Oneiron's [`oneiron::LlmBackend`] seam.
//!
//! This module owns protocol mapping and classification only. HTTP execution,
//! authentication, cancellation wiring, and retry policy stay host-owned.

mod backend;
// The media wire's shared seam and its embeddings; images and video are
// `oneiron_gen::openai_compat`'s, speech `oneiron_speech::{tts, asr}::openai_compat`'s.
mod media;
pub use self::media::{
    EmbedShape, OpenAiEmbedBackend, OpenAiImagePart, OpenAiMediaBody, OpenAiMediaClient,
    OpenAiMediaHttpRequest, OpenAiMediaHttpResponse, OpenAiMediaMethod, OpenAiMediaTransport,
    OpenAiMediaTransportFuture, audio_extension, form_fields, only_text, with_params,
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
    parse_openai_usage,
};

// The flat lib.rs module used to provide these names to the inline test
// module through `use super::*`: its own oneiron/std import header, and the
// `json!` macro. After the directory split the seam re-imports them so
// `tests.rs` resolves exactly as it did before.

#[cfg(test)]
mod tests;
