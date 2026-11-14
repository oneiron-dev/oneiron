//! Moved from `crates/oneiron/src/runtime_hooks/regen.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::runtime_hooks::regen::history::HookRegenActor;
pub use crate::runtime_hooks::regen::history::HookRegenDecision;
use serde::Deserialize;
use serde::Serialize;

/// Where a regen stopped. Every phase keeps the last good body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookRegenFailurePhase {
    /// The hook kept no intent to run again.
    Intent,
    /// The regenerator could not write a body.
    Generate,
    /// The body it wrote is blank or not text.
    Validate,
    /// The golden set could not replay.
    GoldenReplay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookRegenFailure {
    pub phase: HookRegenFailurePhase,
    pub message: String,
}

impl HookRegenFailure {
    #[must_use]
    pub fn new(phase: HookRegenFailurePhase, message: impl Into<String>) -> Self {
        Self {
            phase,
            message: message.into(),
        }
    }
}

/// A hook body's hash as its binding records it: BLAKE3, lowercase hex.
pub fn body_hash(body: &str) -> String {
    blake3::hash(body.as_bytes()).to_hex().to_string()
}
pub mod history;
