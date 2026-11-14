//! Moved from `crates/oneiron/src/connector_key/slate_revision.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The owner's answer that holds a scope revision's offer back (ED-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorRevisionDeferral {
    /// Ask again after the next backoff step.
    NotNow,
    /// Stop offering until he unpins it.
    ManualPinned,
    /// Offer again once earned.
    Unpin,
}
