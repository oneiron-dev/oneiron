//! Moved from `crates/oneiron/src/agent_dispatch/caller_origin.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::settings::destination::CallerLocality;
use serde::Deserialize;
use serde::Serialize;

/// Root-admission provenance, inherited unchanged by children. The host
/// supplies connection locality from the actual transport, not guest input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CallerOrigin {
    Connection {
        locality: CallerLocality,
    },
    NativeHost,
    /// A new root for which no producer supplied an origin fact.
    Unknown,
}
