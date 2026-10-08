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

// The flat lib.rs module used to provide these names to the inline test
// module through `use super::*`: its own oneiron/std import header, and the
// `json!` macro. After the directory split the seam re-imports them so
// `tests.rs` resolves exactly as it did before.
