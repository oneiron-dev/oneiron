//! Text model wire adapters for Oneiron's [`oneiron::LlmBackend`] seam, one
//! module per wire protocol (ARCH-0036 `#adapters`, MED-1 = A).
//!
//! Each module owns its protocol's request mapping and reply classification.
//! HTTP execution, authentication, cancellation wiring and retry policy stay
//! with the host, except for the two modules behind a feature, which bring
//! their own client: `systemone` (feature `systemone`) and `oneiron_rpc`
//! (feature `oneiron-rpc`).

pub mod anthropic;
pub mod gemini;
pub mod local;
#[cfg(feature = "oneiron-rpc")]
pub mod oneiron_rpc;
pub mod openai_compat;
#[cfg(feature = "systemone")]
pub mod systemone;
