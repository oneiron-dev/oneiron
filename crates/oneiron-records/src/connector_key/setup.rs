//! Moved from `crates/oneiron/src/connector_key/setup.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::connector_key::setup::allow_ask::PackSetupOwnerAsk;
use oneiron_base::error::Error;

/// Why a Google path refuses a stored Microsoft grant.
pub const MICROSOFT_GRANT_REFUSED: &str =
    "the stored grant is a Microsoft grant; it is never sent to Google";

/// A stored field's value, trimmed, when it holds one.
pub fn present(field: &Option<String>) -> Option<&str> {
    field
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub fn frame(hasher: &mut blake3::Hasher, part: &[u8]) {
    hasher.update(&(part.len() as u64).to_be_bytes());
    hasher.update(part);
}

pub fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("pack setup: {reason}"))
}
pub mod allow_ask;
