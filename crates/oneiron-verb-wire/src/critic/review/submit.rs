//! Moved from `crates/oneiron/src/critic/review/submit.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

/// One lens's stored skill and the actor executing it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticBinding {
    /// The lens's id in the catalog.
    pub lens_id: String,
    /// The lens's stored SKILL, 32-hex.
    pub lens_ref: String,
    /// The actor executing the lens, 32-hex: the review's authenticated
    /// caller, as its credential names it.
    pub actor_ref: String,
    /// That actor's class: 0 human, 1 agent, 2 system; the caller's own.
    pub actor_class: u8,
}

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
