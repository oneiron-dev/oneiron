//! Image, video and music job wire adapters for Oneiron's media and image
//! seams, one module per wire protocol (ARCH-0036 `#adapters`, MED-1 = A).
//!
//! Each module owns its protocol's request mapping and reply classification.
//! HTTP execution, authentication and retry policy stay with the host, except
//! for `comfyui` (feature `comfyui`), which brings its own client.
//!
//! `gemini` serves the media seam (`oneiron::llm::media::MediaBackend`);
//! `comfyui` and `openrouter` serve the image seam
//! (`oneiron::llm::image::ImageBackend`), which a host mounts on the media
//! seam through `ImageMedia`.

#[cfg(feature = "comfyui")]
pub mod comfyui;
pub mod gemini;
pub mod openrouter;
