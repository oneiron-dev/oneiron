//! Moved from `crates/oneiron/src/surface_event/connector_bridge.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

/// Predicate every surface-born connector event carries; a subscription
/// filter names it to take only inbound channel traffic.
pub const SURFACE_CONNECTOR_EVENT_PREDICATE: &str = "surface_event.v1";

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
