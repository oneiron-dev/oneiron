//! Moved from `crates/oneiron/src/store/checkout_lease.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::checkout_task::CheckoutTaskClass;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

pub type CheckoutHolder = String;

/// Closed materialization ladder. There is deliberately no copy-on-write, lazy
/// mount, overlay, filesystem-clone, or `Other(String)` rung: a rung that the
/// executor cannot honour must not be representable.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationSpec {
    FullClone = 1,
    #[default]
    Blobless = 2,
}
