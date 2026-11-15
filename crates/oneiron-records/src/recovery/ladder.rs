//! Moved from `crates/oneiron/src/recovery/ladder.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use loro::LoroDoc;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
#[cfg(feature = "sync")]
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

pub const RECOVERY_MANIFEST_ARTIFACT_TYPE: u16 = 2;
