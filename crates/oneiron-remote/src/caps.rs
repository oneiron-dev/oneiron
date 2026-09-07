//! Shared boundary caps live with the engine DTOs so HTTP ingress and SDK
//! dispatch use the same validators. The SDK's public exports stay unchanged.

pub use oneiron::memory::caps::*;
