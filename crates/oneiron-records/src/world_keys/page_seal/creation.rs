//! Moved from `crates/oneiron/src/world_keys/page_seal/creation.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::sync::PoisonError;

pub const RECORD_VERSION: u32 = 1;
