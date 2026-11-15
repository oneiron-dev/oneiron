//! Moved from `crates/oneiron/src/recovery/checkpoint/watermark.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_crypto::backup::inspect_backup;
pub use oneiron_crypto::backup::verify_with_pins;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

/// Which rows a backup snapshot was asked to select.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSelection {
    /// The existing whole-vault canonical snapshot, including private worlds.
    WholeVault,
    /// An automatic copy selected by the worlds' sealed-copy settings.
    Automatic,
}
