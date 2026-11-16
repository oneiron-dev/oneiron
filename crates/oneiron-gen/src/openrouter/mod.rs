//! OpenRouter Image API adapter. Authentication, HTTP execution, and retries are host-owned.
//! Prompt wording is supplied per model by the host; only the slot substitution lives here.
mod backend;
mod wire;

pub use backend::{
    OpenRouterImageBackend, OpenRouterImageConfig, OpenRouterImageFuture,
    OpenRouterImageHttpRequest, OpenRouterImageHttpResponse, OpenRouterImageModel,
    OpenRouterImageTransport, PromptShim,
};
pub use wire::{build_image_request, classify_image_status, parse_image_response};
